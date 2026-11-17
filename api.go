package bydev

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 명세 3 · 4절 — 요청 만들기 · 응답 읽기 · 발견 문서.

// single은 한 번에 하나만 도는 작업이다 — 기다리는 쪽은 Scheduler.Wait로 기다린다(명세 2절).
type single[T any] struct {
	mu  sync.Mutex
	cur *flight[T]
}

type flight[T any] struct {
	done chan struct{}
	val  T
	err  error
}

func (s *single[T]) do(ctx context.Context, sched Scheduler, fn func() (T, error)) (T, error) {
	s.mu.Lock()
	if f := s.cur; f != nil {
		s.mu.Unlock()
		if err := sched.Wait(ctx, f.done); err != nil {
			var zero T
			return zero, err
		}
		return f.val, f.err
	}
	f := &flight[T]{done: make(chan struct{})}
	s.cur = f
	s.mu.Unlock()
	f.val, f.err = fn()
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	close(f.done)
	return f.val, f.err
}

type apiResponse struct {
	Status int
	Header map[string]string
	JSON   any
}

type requestOptions struct {
	Method         string
	URL            string
	Body           any
	Bearer         string
	IdempotencyKey string
}

type api struct {
	baseURL     string
	ports       Ports
	mu          sync.Mutex
	doc         *discovery
	discovering single[*discovery]
}

func newAPI(baseURL string, ports Ports) *api {
	return &api{baseURL: strings.TrimRight(baseURL, "/"), ports: ports}
}

func (a *api) url(path string, params map[string]string, query url.Values) string {
	var b strings.Builder
	b.WriteString(a.baseURL)
	rest := path
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			b.WriteString(rest)
			break
		}
		j := strings.IndexByte(rest[i:], '}')
		b.WriteString(rest[:i])
		b.WriteString(url.PathEscape(params[rest[i+1:i+j]]))
		rest = rest[i+j+1:]
	}
	if len(query) > 0 {
		b.WriteByte('?')
		b.WriteString(query.Encode())
	}
	return b.String()
}

// discovery는 처음 한 번 받아 클라이언트 수명 동안 둔다. 실패하면 두지 않는다(명세 4절).
func (a *api) discovery(ctx context.Context) (*discovery, error) {
	a.mu.Lock()
	if a.doc != nil {
		d := a.doc
		a.mu.Unlock()
		return d, nil
	}
	a.mu.Unlock()
	return a.discovering.do(ctx, a.ports.Scheduler, func() (*discovery, error) {
		res, err := a.send(ctx, requestOptions{Method: "GET", URL: a.baseURL + "/.well-known/openid-configuration"})
		if err != nil {
			return nil, err
		}
		doc, err := readDiscovery(res.JSON)
		if err != nil {
			return nil, err
		}
		if strings.TrimRight(doc.Issuer, "/") != a.baseURL {
			return nil, sdkError(CodeConfiguration, "발견 문서의 issuer("+doc.Issuer+")가 baseUrl("+a.baseURL+")과 다르다", nil)
		}
		a.mu.Lock()
		a.doc = doc
		a.mu.Unlock()
		return doc, nil
	})
}

func (a *api) send(ctx context.Context, o requestOptions) (*apiResponse, error) {
	header := map[string]string{"accept": "application/json", "user-agent": UserAgent}
	var body []byte
	if o.Body != nil {
		header["content-type"] = "application/json"
		b, err := json.Marshal(o.Body)
		if err != nil {
			return nil, sdkError(CodeConfiguration, "본문을 만들지 못했다", err)
		}
		body = b
	}
	if o.Bearer != "" {
		header["authorization"] = "Bearer " + o.Bearer
	}
	if o.IdempotencyKey != "" {
		header["idempotency-key"] = o.IdempotencyKey
	}
	res, err := a.ports.Transport.Send(ctx, HTTPRequest{Method: o.Method, URL: o.URL, Header: header, Body: body})
	if err != nil {
		if e, ok := AsError(err); ok {
			return nil, e
		}
		return nil, sdkError(CodeNetworkError, "API에 연결하지 못했다", err)
	}
	correlation := res.Header["x-correlation-id"]
	var parsed any
	ok := len(res.Body) > 0 && json.Unmarshal(res.Body, &parsed) == nil
	if res.Status >= 200 && res.Status < 300 {
		if !ok {
			return nil, &Error{Code: CodeProtocolError, Message: "응답 본문이 JSON이 아니다", HTTPStatus: res.Status, CorrelationID: correlation}
		}
		return &apiResponse{Status: res.Status, Header: res.Header, JSON: parsed}, nil
	}
	return nil, errorFrom(res, parsed, ok, correlation)
}

// errorFrom — 3.2절. 실패 응답 → *Error
func errorFrom(res HTTPResponse, parsed any, ok bool, correlation string) *Error {
	retry := 0
	if n, err := strconv.Atoi(res.Header["retry-after"]); err == nil && n > 0 {
		retry = n
	}
	if m, isMap := parsed.(map[string]any); ok && isMap {
		code, c := m["code"].(string)
		message, mm := m["message"].(string)
		if c && mm {
			if f, isNum := m["retryAfterSec"].(float64); isNum {
				retry = int(f)
			}
			details, _ := m["details"].(map[string]any)
			return &Error{Code: code, Message: message, HTTPStatus: res.Status, CorrelationID: correlation, RetryAfterSec: retry, Details: details}
		}
	}
	code := CodeProtocolError
	switch {
	case res.Status >= 500:
		code = CodeInternalError
	case res.Status == 429:
		code = CodeRateLimited
	}
	return &Error{Code: code, Message: "HTTP " + strconv.Itoa(res.Status), HTTPStatus: res.Status, CorrelationID: correlation, RetryAfterSec: retry}
}

// iso는 SDK가 만드는 시각 — 밀리초가 0이면 떼는 UTC ISO 8601.
func iso(t time.Time) string {
	s := t.UTC().Format("2006-01-02T15:04:05.000Z")
	return strings.Replace(s, ".000Z", "Z", 1)
}

// jittered — round(base × (min + (max − min) × r)), .5는 올림(명세 2절)
func jittered(p Ports, base time.Duration, min, max float64) time.Duration {
	ms := float64(base.Milliseconds()) * (min + (max-min)*p.Random.Float64())
	return time.Duration(int64(ms+0.5)) * time.Millisecond
}
