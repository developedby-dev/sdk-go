package bydev

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 명세 2절 — 기본 구현. 운영체제별 저장소 · 지문 출처는 앱이 준다(platform.go).

type systemClock struct{}

// SystemClock은 시스템 시계다 — SDK에서 시계를 직접 읽는 유일한 곳.
var SystemClock Clock = systemClock{}

func (systemClock) Now() time.Time { return time.Now() }

type timerScheduler struct{}

// TimerScheduler는 time.AfterFunc 기반 스케줄러다.
var TimerScheduler Scheduler = timerScheduler{}

func (timerScheduler) AfterFunc(d time.Duration, task func()) func() {
	t := time.AfterFunc(d, task)
	return func() { t.Stop() }
}

func (timerScheduler) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (timerScheduler) Wait(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type cryptoRandom struct{}

// CryptoRandom은 crypto/rand 기반 난수다.
var CryptoRandom Random = cryptoRandom{}

func (cryptoRandom) Float64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}

func (cryptoRandom) UUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type httpTransport struct{ client *http.Client }

// HTTPTransport는 net/http 기반 전송이다. 리다이렉트를 따라가지 않는다.
func HTTPTransport(timeout time.Duration) Transport {
	if timeout <= 0 {
		timeout = time.Duration(RuleHttpTimeoutSec) * time.Second
	}
	return httpTransport{client: &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t httpTransport) Send(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return HTTPResponse{}, sdkError(CodeConfiguration, "요청을 만들지 못했다", err)
	}
	for k, v := range req.Header {
		r.Header.Set(k, v)
	}
	res, err := t.client.Do(r)
	if err != nil {
		return HTTPResponse{}, sdkError(CodeNetworkError, "API에 연결하지 못했다", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return HTTPResponse{}, sdkError(CodeNetworkError, "응답을 끝까지 받지 못했다", err)
	}
	header := make(map[string]string, len(res.Header))
	for k, v := range res.Header {
		header[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return HTTPResponse{Status: res.StatusCode, Header: header, Body: data}, nil
}

type memoryStore struct {
	mu     sync.Mutex
	record *CredentialRecord
}

// MemoryStore는 메모리 저장소다 — 앱을 끄면 로그인이 사라진다. 시험 · 짧은 CLI용.
func MemoryStore(initial *CredentialRecord) CredentialStore {
	return &memoryStore{record: initial}
}

func (m *memoryStore) Load(context.Context) (*CredentialRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		return nil, nil
	}
	r := *m.record
	return &r, nil
}

func (m *memoryStore) Save(_ context.Context, record CredentialRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record = &record
	return nil
}

func (m *memoryStore) Clear(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record = nil
	return nil
}

type noFingerprint struct{}

func (noFingerprint) Read(context.Context) (string, error) { return "", nil }

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}

func (p Ports) withDefaults() Ports {
	if p.Transport == nil {
		p.Transport = HTTPTransport(0)
	}
	if p.Store == nil {
		p.Store = MemoryStore(nil)
	}
	if p.Clock == nil {
		p.Clock = SystemClock
	}
	if p.Scheduler == nil {
		p.Scheduler = TimerScheduler
	}
	if p.Random == nil {
		p.Random = CryptoRandom
	}
	if p.Fingerprint == nil {
		p.Fingerprint = noFingerprint{}
	}
	if p.Logger == nil {
		p.Logger = nopLogger{}
	}
	return p
}
