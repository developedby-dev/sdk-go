// conformance-harness는 Go SDK의 적합성 하네스다(sdks/spec/harness-protocol.md). 표준 입출력 JSON 줄로 실행기와 이야기하며 SDK를 가상 시계 ·
// 가상 스케줄러 · 대리 전송으로 몬다.
//
// 블로킹 언어의 정착 판정: SDK 일을 하는 고루틴 수(running)를 세고, 전송 · Sleep · Wait에서 기다리는 고루틴은 그 기다림의 done 채널을 등록한다.
// running이 0이고, 답을 기다리는 요청이 없고, 등록된 done이 하나도 닫히지 않았으면(깨어날 고루틴이 없으면) 할 일이 없다.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	bydev "developedby.dev/sdk/go"
)

var (
	mu       sync.Mutex
	now      int64 // Unix 밀리초
	timers   []*timer
	seq      int
	running  int
	waiters  = map[int]<-chan struct{}{}
	waiterID int
	pending  = map[string]*exchange{}
	randoms  []float64
	uuids    int
	httpSeq  int
	record   *bydev.CredentialRecord
	failLoad bool
	failSave bool
	failClr  bool
	client   *bydev.Client
	login    *bydev.LoginAttempt
	outMu    sync.Mutex
)

type timer struct {
	due       int64
	seq       int
	task      func()
	cancelled bool
}

type exchange struct {
	done     chan struct{}
	response *bydev.HTTPResponse
	failed   bool
}

func emit(message map[string]any) {
	b, _ := json.Marshal(message)
	outMu.Lock()
	os.Stdout.Write(append(b, '\n'))
	outMu.Unlock()
}

func fatal(format string, args ...any) {
	emit(map[string]any{"type": "fatal", "message": fmt.Sprintf(format, args...)})
	os.Exit(1)
}

func nowMs() int64 {
	mu.Lock()
	defer mu.Unlock()
	return now
}

func incRunning() { mu.Lock(); running++; mu.Unlock() }
func decRunning() { mu.Lock(); running--; mu.Unlock() }

// block는 SDK 고루틴이 포트에서 기다리는 동안 running에서 빠지고 done을 등록한다.
func block(done <-chan struct{}) {
	mu.Lock()
	running--
	waiterID++
	id := waiterID
	waiters[id] = done
	mu.Unlock()
	<-done
	mu.Lock()
	delete(waiters, id)
	running++
	mu.Unlock()
}

// ── 포트 ──────────────────────────────────────────────────────

type clock struct{}

func (clock) Now() time.Time { return time.UnixMilli(nowMs()) }

type scheduler struct{}

func (scheduler) AfterFunc(d time.Duration, task func()) func() {
	mu.Lock()
	t := &timer{due: now + max(d.Milliseconds(), 0), seq: seq, task: task}
	seq++
	timers = append(timers, t)
	mu.Unlock()
	return func() { mu.Lock(); t.cancelled = true; mu.Unlock() }
}

func (s scheduler) Sleep(_ context.Context, d time.Duration) error {
	done := make(chan struct{})
	s.AfterFunc(d, func() { close(done) })
	block(done)
	return nil
}

func (scheduler) Wait(_ context.Context, done <-chan struct{}) error {
	block(done)
	return nil
}

type random struct{}

func (random) Float64() float64 {
	mu.Lock()
	defer mu.Unlock()
	if len(randoms) == 0 {
		fatal("시나리오의 random 값을 다 썼다 — random에 더 적는다")
	}
	v := randoms[0]
	randoms = randoms[1:]
	return v
}

func (random) UUID() string {
	mu.Lock()
	defer mu.Unlock()
	uuids++
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", uuids)
}

type transport struct{}

func (transport) Send(_ context.Context, req bydev.HTTPRequest) (bydev.HTTPResponse, error) {
	mu.Lock()
	httpSeq++
	id := fmt.Sprintf("h%d", httpSeq)
	x := &exchange{done: make(chan struct{})}
	pending[id] = x
	at := now
	mu.Unlock()
	header := map[string]string{}
	for k, v := range req.Header {
		header[strings.ToLower(k)] = v
	}
	var body any
	if req.Body != nil {
		body = string(req.Body)
	}
	emit(map[string]any{"type": "http.request", "id": id, "now": at, "request": map[string]any{
		"method": req.Method, "url": req.URL, "headers": header, "body": body,
	}})
	block(x.done)
	if x.failed {
		return bydev.HTTPResponse{}, fmt.Errorf("대리 전송 실패")
	}
	return *x.response, nil
}

type store struct{}

func (store) Load(context.Context) (*bydev.CredentialRecord, error) {
	mu.Lock()
	defer mu.Unlock()
	if failLoad {
		return nil, fmt.Errorf("저장소 읽기 실패(시험)")
	}
	if record == nil {
		return nil, nil
	}
	r := *record
	return &r, nil
}

func (store) Save(_ context.Context, r bydev.CredentialRecord) error {
	mu.Lock()
	if failSave {
		mu.Unlock()
		return fmt.Errorf("저장소 쓰기 실패(시험)")
	}
	record = &r
	at := now
	mu.Unlock()
	emit(map[string]any{"type": "event", "now": at, "event": map[string]any{"kind": "storage", "op": "save", "record": r}})
	return nil
}

func (store) Clear(context.Context) error {
	mu.Lock()
	if failClr {
		mu.Unlock()
		return fmt.Errorf("저장소 지우기 실패(시험)")
	}
	record = nil
	at := now
	mu.Unlock()
	emit(map[string]any{"type": "event", "now": at, "event": map[string]any{"kind": "storage", "op": "clear"}})
	return nil
}

type fingerprint struct{ value *string }

func (f fingerprint) Read(context.Context) (string, error) {
	if f.value == nil {
		return "", nil
	}
	return *f.value, nil
}

type logger struct{}

func (logger) Debug(string, ...any)      {}
func (logger) Info(string, ...any)       {}
func (logger) Warn(msg string, _ ...any) { fmt.Fprintln(os.Stderr, "warn:", msg) }

// ── 정착 ──────────────────────────────────────────────────────

func quiet() bool {
	if running > 0 {
		return false
	}
	if len(pending) > 0 {
		return false
	}
	for _, done := range waiters {
		select {
		case <-done:
			return false // 깨어날 고루틴이 있다
		default:
		}
	}
	return true
}

func waitQuiet() {
	for {
		mu.Lock()
		q := quiet()
		mu.Unlock()
		if q {
			return
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func nextTimer(limit int64) *timer {
	alive := timers[:0]
	for _, t := range timers {
		if !t.cancelled {
			alive = append(alive, t)
		}
	}
	timers = alive
	sort.SliceStable(timers, func(i, j int) bool {
		if timers[i].due != timers[j].due {
			return timers[i].due < timers[j].due
		}
		return timers[i].seq < timers[j].seq
	})
	if len(timers) > 0 && timers[0].due <= limit {
		return timers[0]
	}
	return nil
}

// settle은 지금 시각까지 온 예약 작업을 하나씩 — 앞 작업이 끝나거나 기다릴 때까지 — 돌린다.
func settle() {
	for {
		waitQuiet()
		mu.Lock()
		t := nextTimer(now)
		if t != nil {
			t.cancelled = true
			running++
		}
		mu.Unlock()
		if t == nil {
			return
		}
		go func() {
			defer decRunning()
			t.task()
		}()
	}
}

func advance(ms int64) {
	mu.Lock()
	target := now + ms
	mu.Unlock()
	for {
		settle()
		mu.Lock()
		t := nextTimer(target)
		if t == nil {
			mu.Unlock()
			break
		}
		now = t.due
		mu.Unlock()
	}
	mu.Lock()
	now = target
	mu.Unlock()
	settle()
}

// ── 호출 ──────────────────────────────────────────────────────

func errorJSON(err error) map[string]any {
	e, ok := bydev.AsError(err)
	if !ok {
		return map[string]any{"code": "HARNESS_ERROR", "message": err.Error()}
	}
	out := map[string]any{"code": e.Code, "message": e.Message, "httpStatus": nil, "correlationId": nil, "retryAfterSec": nil, "details": e.Details}
	if e.HTTPStatus != 0 {
		out["httpStatus"] = e.HTTPStatus
	}
	if e.CorrelationID != "" {
		out["correlationId"] = e.CorrelationID
	}
	if e.RetryAfterSec != 0 {
		out["retryAfterSec"] = e.RetryAfterSec
	}
	return out
}

func str(args map[string]any, key string) string {
	v, ok := args[key].(string)
	if !ok {
		fatal("인자 %s가 문자열이 아니다", key)
	}
	return v
}

func session() *bydev.Session {
	s, err := client.Session()
	if err != nil {
		fatal("세션: %v", err)
	}
	return s
}

func invoke(method string, args map[string]any) (any, error) {
	ctx := context.Background()
	switch method {
	case "login.start":
		attempt, err := client.StartLogin(ctx)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		login = attempt
		mu.Unlock()
		return map[string]any{"userCode": attempt.UserCode, "verificationUri": attempt.VerificationURI, "verificationUriComplete": attempt.VerificationURIComplete, "expiresAt": attempt.ExpiresAt}, nil
	case "login.wait":
		mu.Lock()
		attempt := login
		mu.Unlock()
		if attempt == nil {
			fatal("login.start 전에 login.wait")
		}
		return attempt.Wait(ctx)
	case "login.cancel":
		mu.Lock()
		attempt := login
		mu.Unlock()
		if attempt != nil {
			attempt.Cancel()
		}
		return nil, nil
	case "hasCredentials":
		return client.HasCredentials(ctx)
	case "entitlement":
		return client.Entitlement(ctx)
	case "devices":
		cursor, _ := args["cursor"].(string)
		limit, _ := args["limit"].(float64)
		return client.Devices(ctx, cursor, int(limit))
	case "releaseDevice":
		return client.ReleaseDevice(ctx, str(args, "deviceId"))
	case "profile":
		return client.Profile(ctx)
	case "checkForUpdate":
		return client.CheckForUpdate(ctx, str(args, "target"), str(args, "currentVersion"))
	case "verifyDownload":
		data, err := base64.StdEncoding.DecodeString(str(args, "dataBase64"))
		if err != nil {
			fatal("dataBase64: %v", err)
		}
		return nil, client.VerifyDownload(data, str(args, "sha256"))
	case "verifyToken":
		return client.VerifyToken(ctx, str(args, "token"))
	case "logout":
		revoked, err := client.Logout(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"serverRevoked": revoked}, nil
	case "session.start":
		session().Start()
		return nil, nil
	case "session.takeOver":
		session().TakeOver()
		return nil, nil
	case "session.retry":
		session().Retry()
		return nil, nil
	case "session.stop":
		session().Stop(ctx)
		return nil, nil
	case "session.state":
		return bydev.StateJSON(session().State()), nil
	}
	fatal("모르는 호출 %s", method)
	return nil, nil
}

func startCall(id, method string, args map[string]any) {
	incRunning()
	go func() {
		defer decRunning()
		value, err := invoke(method, args)
		if err != nil {
			emit(map[string]any{"type": "result", "id": id, "now": nowMs(), "ok": false, "error": errorJSON(err)})
			return
		}
		raw, _ := json.Marshal(value)
		var plain any
		_ = json.Unmarshal(raw, &plain)
		emit(map[string]any{"type": "result", "id": id, "now": nowMs(), "ok": true, "value": plain})
	}()
}

// ── 명령 ──────────────────────────────────────────────────────

type initMessage struct {
	Config struct {
		BaseURL   string   `json:"baseUrl"`
		ClientID  string   `json:"clientId"`
		ProductID string   `json:"productId"`
		Scopes    []string `json:"scopes"`
		Device    struct {
			Name              string  `json:"name"`
			Platform          string  `json:"platform"`
			FingerprintSource *string `json:"fingerprintSource"`
		} `json:"device"`
		App *struct {
			Target  string `json:"target"`
			Version string `json:"version"`
		} `json:"app"`
	} `json:"config"`
	Now     string                  `json:"now"`
	Random  []float64               `json:"random"`
	Storage *bydev.CredentialRecord `json:"storage"`
}

func initClient(raw json.RawMessage) {
	var m initMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		fatal("init: %v", err)
	}
	t, err := time.Parse(time.RFC3339, m.Now)
	if err != nil {
		fatal("init.now: %v", err)
	}
	mu.Lock()
	now = t.UnixMilli()
	randoms = m.Random
	record = m.Storage
	mu.Unlock()
	var app *bydev.AppInfo
	if m.Config.App != nil {
		app = &bydev.AppInfo{Target: m.Config.App.Target, Version: m.Config.App.Version}
	}
	c, err := bydev.New(bydev.Config{
		BaseURL: m.Config.BaseURL, ClientID: m.Config.ClientID, ProductID: m.Config.ProductID, Scopes: m.Config.Scopes,
		Device: &bydev.DeviceInfo{Name: m.Config.Device.Name, Platform: m.Config.Device.Platform},
		App:    app,
		Ports: bydev.Ports{
			Transport: transport{}, Store: store{}, Clock: clock{}, Scheduler: scheduler{}, Random: random{},
			Fingerprint: fingerprint{value: m.Config.Device.FingerprintSource}, Logger: logger{},
		},
	})
	if err != nil {
		fatal("New: %v", err)
	}
	client = c
	session().Subscribe(func(state bydev.SessionState) {
		emit(map[string]any{"type": "event", "now": nowMs(), "event": map[string]any{"kind": "session.state", "state": bydev.StateJSON(state)}})
	})
}

func main() {
	emit(map[string]any{"type": "ready", "sdk": "go", "version": bydev.SDKVersion, "specVersion": bydev.SpecVersion})
	commands := make(chan map[string]json.RawMessage, 64)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1<<20), 1<<24)
		for scanner.Scan() {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
				fatal("JSON이 아닌 입력: %s", scanner.Text())
			}
			var kind string
			_ = json.Unmarshal(m["type"], &kind)
			if kind != "http.response" {
				commands <- m
				continue
			}
			var r struct {
				ID       string `json:"id"`
				Error    string `json:"error"`
				Response *struct {
					Status  int               `json:"status"`
					Headers map[string]string `json:"headers"`
					Body    string            `json:"body"`
				} `json:"response"`
			}
			_ = json.Unmarshal(scanner.Bytes(), &r)
			// 지우기와 닫기를 한 잠금 안에서 — 둘 사이에 "할 일 없음"으로 보이는 틈이 없게
			mu.Lock()
			x, ok := pending[r.ID]
			if !ok {
				mu.Unlock()
				fatal("모르는 http.response id %s", r.ID)
			}
			if r.Response != nil {
				x.response = &bydev.HTTPResponse{Status: r.Response.Status, Header: r.Response.Headers, Body: []byte(r.Response.Body)}
			} else {
				x.failed = true
			}
			close(x.done)
			delete(pending, r.ID)
			mu.Unlock()
		}
		close(commands)
	}()
	for m := range commands {
		var kind string
		_ = json.Unmarshal(m["type"], &kind)
		switch kind {
		case "init":
			raw, _ := json.Marshal(m)
			initClient(raw)
			settle()
		case "call":
			var calls []struct {
				ID     string         `json:"id"`
				Method string         `json:"method"`
				Args   map[string]any `json:"args"`
			}
			_ = json.Unmarshal(m["calls"], &calls)
			for _, c := range calls {
				startCall(c.ID, c.Method, c.Args)
			}
			settle()
		case "advance":
			var ms int64
			_ = json.Unmarshal(m["ms"], &ms)
			advance(ms)
		case "set":
			var key string
			var value bool
			_ = json.Unmarshal(m["key"], &key)
			_ = json.Unmarshal(m["value"], &value)
			mu.Lock()
			switch key {
			case "storage.failLoad":
				failLoad = value
			case "storage.failSave":
				failSave = value
			case "storage.failClear":
				failClr = value
			}
			mu.Unlock()
			settle()
		case "end":
			os.Exit(0)
		default:
			fatal("모르는 명령 %s", kind)
		}
		emit(map[string]any{"type": "idle", "now": nowMs()})
	}
}
