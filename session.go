package bydev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
)

// 명세 8.1절 — 세션 상태(판별 유니온). 참/거짓 하나로 이용 가능을 알리지 않는다.

// SessionState는 세션 상태다. Type()으로 분기한다 — Starting · Active · Degraded · NeedsDecision · Locked · Stopped.
type SessionState interface{ Type() string }

// ErrorView는 상태에 싣는 에러다.
type ErrorView struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	HTTPStatus    *int           `json:"httpStatus"`
	CorrelationID *string        `json:"correlationId"`
	RetryAfterSec *int           `json:"retryAfterSec"`
	Details       map[string]any `json:"details"`
}

func viewOf(e *Error) *ErrorView {
	v := &ErrorView{Code: e.Code, Message: e.Message, Details: e.Details}
	if e.HTTPStatus != 0 {
		v.HTTPStatus = &e.HTTPStatus
	}
	if e.CorrelationID != "" {
		v.CorrelationID = &e.CorrelationID
	}
	if e.RetryAfterSec != 0 {
		v.RetryAfterSec = &e.RetryAfterSec
	}
	return v
}

// Starting은 획득 중이다.
type Starting struct {
	Attempt   int        `json:"attempt"`
	LastError *ErrorView `json:"lastError"`
}

// Active는 세션을 들고 있다. 앱은 Claims로 기능을 연다.
type Active struct {
	Session      SessionInfo      `json:"session"`
	LicenseToken LicenseTokenInfo `json:"licenseToken"`
	Claims       LicenseClaims    `json:"claims"`
}

// Degraded는 하트비트가 일시적으로 실패 중이다. OfflineUntil까지는 계속 써도 된다.
type Degraded struct {
	Active
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	OfflineUntil        string     `json:"offlineUntil"`
	LastError           *ErrorView `json:"lastError"`
}

// ActiveSession은 다른 곳에서 쓰는 세션이다.
type ActiveSession struct {
	DeviceID   string `json:"deviceId"`
	DeviceName string `json:"deviceName"`
	LastSeenAt string `json:"lastSeenAt"`
}

// NeedsDecision은 사용자가 골라야 한다 — DEVICE_IN_USE · INSTANCE_ALREADY_RUNNING이면 TakeOver, DEVICE_LIMIT_EXCEEDED면 기기 해제 뒤 Retry.
type NeedsDecision struct {
	Reason        NeedsDecisionReason `json:"reason"`
	ActiveSession *ActiveSession      `json:"activeSession"`
	MaxDevices    *int                `json:"maxDevices"`
	CorrelationID *string             `json:"correlationId"`
}

// Locked는 쓰면 안 된다. Retrying이 참(OFFLINE_EXPIRED)이면 연결이 돌아올 때 스스로 풀린다.
type Locked struct {
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	CorrelationID *string        `json:"correlationId"`
	Details       map[string]any `json:"details"`
	Retrying      bool           `json:"retrying"`
}

// Stopped는 멈춤이다.
type Stopped struct{}

func (Starting) Type() string      { return "Starting" }
func (Active) Type() string        { return "Active" }
func (Degraded) Type() string      { return "Degraded" }
func (NeedsDecision) Type() string { return "NeedsDecision" }
func (Locked) Type() string        { return "Locked" }
func (Stopped) Type() string       { return "Stopped" }

// StateJSON은 상태를 {"type": …, 필드…} 모양으로 쓴다.
func StateJSON(s SessionState) map[string]any {
	b, _ := json.Marshal(s)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	out["type"] = s.Type()
	return out
}

// DeviceInfo는 세션 획득 때 보내는 기기 정보다.
type DeviceInfo struct {
	Name     string
	Platform string
}

// AppInfo는 실행 중인 앱이다(명세 1절 · ADR-0049) — 배포 대상(CheckForUpdate의 target과 같은 값)과 콘솔에 업로드한 버전 문자열.
// 세션 획득에 싣는다. 업데이트 제공 기한이 있는 영구 이용권은 이 값이 없으면 획득이 ENTITLEMENT_VERSION_NOT_COVERED로 거절된다.
type AppInfo struct {
	Target  string
	Version string
}

// Session은 라이선스 세션(실행 리스)이다. Start · TakeOver · Retry · Stop과 상태 구독.
type Session struct {
	api      *api
	ports    Ports
	tokens   *tokenManager
	verifier *verifier
	device   DeviceInfo
	app      *AppInfo

	mu        sync.Mutex
	current   SessionState
	listeners []func(SessionState)
	run       int
	instance  string
	held      *Active
	failures  int
	heartbeat func()
	offline   func()
	fallback  string
	// fingerprint는 처음 계산한 지문 해시 — 한 실행 동안 다시 쓴다(명세 10절). 획득마다 출처를 다시 읽으면 일시적인 읽기 실패 하나로 다른 기기가 된다
	fingerprint string
}

func newSession(c *Client, device DeviceInfo, app *AppInfo) *Session {
	s := &Session{api: c.api, ports: c.ports, tokens: c.tokens, verifier: c.verifier, device: device, current: Stopped{}}
	if app != nil {
		copied := *app // 설정을 만든 뒤 앱이 바꿔도 세션이 보내는 값은 그대로
		s.app = &copied
	}
	return s
}

// State는 지금 상태다.
func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Subscribe는 상태가 바뀔 때마다 부른다. 돌려준 함수로 끊는다.
func (s *Session) Subscribe(listener func(SessionState)) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, listener)
	index := len(s.listeners) - 1
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.listeners[index] = nil
	}
}

func (s *Session) setState(next SessionState) {
	s.mu.Lock()
	a, _ := json.Marshal(StateJSON(next))
	b, _ := json.Marshal(StateJSON(s.current))
	if string(a) == string(b) {
		s.mu.Unlock()
		return
	}
	s.current = next
	listeners := slices.Clone(s.listeners)
	s.mu.Unlock()
	for _, l := range listeners {
		if l != nil {
			l(next)
		}
	}
}

// Start는 Stopped에서만 의미가 있다(8.2절).
func (s *Session) Start() {
	s.mu.Lock()
	if s.current.Type() != "Stopped" {
		s.mu.Unlock()
		return
	}
	s.run++
	s.instance = s.ports.Random.UUID()
	s.mu.Unlock()
	s.beginAcquire(false, nil)
}

// TakeOver는 NeedsDecision(다른 기기 · 같은 기기 실행 중) 또는 Locked(SESSION_SUPERSEDED)에서 인수한다 — 새 Idempotency-Key.
func (s *Session) TakeOver() {
	switch st := s.State().(type) {
	case NeedsDecision:
		if st.Reason == NeedsDecisionReasonDeviceLimitExceeded {
			return
		}
	case Locked:
		if st.Code != CodeSessionSuperseded {
			return
		}
	default:
		return
	}
	s.bump()
	s.beginAcquire(true, nil)
}

// Retry는 NeedsDecision(기기 수) 또는 스스로 풀리지 않는 Locked에서 다시 얻는다.
func (s *Session) Retry() {
	switch st := s.State().(type) {
	case NeedsDecision:
		if st.Reason != NeedsDecisionReasonDeviceLimitExceeded {
			return
		}
	case Locked:
		if st.Retrying {
			return
		}
	default:
		return
	}
	s.bump()
	s.beginAcquire(false, nil)
}

func (s *Session) bump() {
	s.mu.Lock()
	s.run++
	s.mu.Unlock()
}

// Stop은 예약을 모두 취소하고 반납을 한 번 보낸다(8.7절).
func (s *Session) Stop(ctx context.Context) {
	s.mu.Lock()
	if s.current.Type() == "Stopped" {
		s.mu.Unlock()
		return
	}
	s.run++
	s.cancelTimersLocked()
	var sid string
	if s.held != nil {
		sid = s.held.Session.ID
	}
	s.held = nil
	s.instance = ""
	s.mu.Unlock()
	if sid != "" {
		_, err := s.tokens.authed(ctx, func(bearer string) (*apiResponse, error) {
			return s.api.send(ctx, requestOptions{Method: "DELETE", URL: s.api.url(RouteReleaseSession.Path, map[string]string{"sid": sid}, nil), Bearer: bearer})
		})
		if err != nil {
			s.ports.Logger.Debug("세션 반납을 보내지 못했다 — 리스가 저절로 빈다")
		}
	}
	s.setState(Stopped{})
}

// noteLease — 8.5절. 다른 인증 응답의 X-Lease-Expires-At.
func (s *Session) noteLease(value string) {
	if value == "" {
		return
	}
	s.mu.Lock()
	if s.held == nil {
		s.mu.Unlock()
		return
	}
	var next SessionState
	switch st := s.current.(type) {
	case Active:
		if st.Session.LeaseExpiresAt == value {
			s.mu.Unlock()
			return
		}
		st.Session.LeaseExpiresAt = value
		next = st
	case Degraded:
		if st.Session.LeaseExpiresAt == value {
			s.mu.Unlock()
			return
		}
		st.Session.LeaseExpiresAt = value
		next = st
	default:
		s.mu.Unlock()
		return
	}
	s.held.Session.LeaseExpiresAt = value
	s.mu.Unlock()
	s.setState(next)
}

func (s *Session) cancelTimersLocked() {
	if s.heartbeat != nil {
		s.heartbeat()
		s.heartbeat = nil
	}
	if s.offline != nil {
		s.offline()
		s.offline = nil
	}
}

func (s *Session) beginAcquire(force bool, lastError *Error) {
	s.mu.Lock()
	s.cancelTimersLocked()
	s.held = nil
	s.failures = 0
	run := s.run
	s.mu.Unlock()
	var view *ErrorView
	if lastError != nil {
		view = viewOf(lastError)
	}
	s.setState(Starting{Attempt: 0, LastError: view})
	key := s.ports.Random.UUID()
	cancel := s.ports.Scheduler.AfterFunc(0, func() { s.acquire(run, force, key, 0) })
	s.mu.Lock()
	s.heartbeat = cancel
	s.mu.Unlock()
}

func (s *Session) live(run int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.run == run
}

func (s *Session) fingerprintHash(ctx context.Context) string {
	s.mu.Lock()
	cached := s.fingerprint
	s.mu.Unlock()
	if cached != "" {
		return cached
	}
	source, err := s.ports.Fingerprint.Read(ctx)
	value := strings.TrimSpace(source)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fingerprint != "" { // 다른 고루틴이 먼저 정했다
		return s.fingerprint
	}
	if err != nil || value == "" {
		if s.fallback == "" {
			s.fallback = s.ports.Random.UUID()
			s.ports.Logger.Warn("기기 지문 출처를 읽지 못해 이번 실행 동안만 쓰는 ID를 쓴다 — 출처 포트를 준다(명세 10절)")
		}
		value = s.fallback
	}
	sum := sha256.Sum256([]byte(value + RuleFingerprintSalt))
	s.fingerprint = hex.EncodeToString(sum[:])
	return s.fingerprint
}

// acquire — 8.2절. 일시적 실패의 재시도는 같은 키.
func (s *Session) acquire(run int, force bool, key string, attempt int) {
	if !s.live(run) {
		return
	}
	ctx := context.Background()
	s.mu.Lock()
	instance := s.instance
	s.mu.Unlock()
	body := map[string]any{
		"device":     map[string]string{"fingerprintHash": s.fingerprintHash(ctx), "name": s.device.Name, "platform": s.device.Platform},
		"instanceId": instance,
		"force":      force,
	}
	if s.app != nil {
		body["app"] = map[string]string{"target": s.app.Target, "version": s.app.Version}
	}
	res, err := s.tokens.authed(ctx, func(bearer string) (*apiResponse, error) {
		return s.api.send(ctx, requestOptions{Method: "POST", URL: s.api.url(RouteAcquireSession.Path, nil, nil), Body: body, Bearer: bearer, IdempotencyKey: key})
	})
	if !s.live(run) {
		return
	}
	if err == nil {
		err = s.adopt(ctx, run, res.JSON)
		if err == nil || !s.live(run) {
			return
		}
	}
	e := toError(err)
	switch {
	case e.Transient():
		delays := RuleSessionStartRetryDelaysSec
		base := delays[min(attempt, len(delays)-1)]
		s.setState(Starting{Attempt: attempt + 1, LastError: viewOf(e)})
		delay := jittered(s.ports, time.Duration(base*1000+0.5)*time.Millisecond, RuleSessionHeartbeatJitterMin, RuleSessionHeartbeatJitterMax)
		cancel := s.ports.Scheduler.AfterFunc(delay, func() { s.acquire(run, force, key, attempt+1) })
		s.mu.Lock()
		s.heartbeat = cancel
		s.mu.Unlock()
	case slices.Contains(RuleNeedsDecisionReasons, e.Code):
		state := NeedsDecision{Reason: NeedsDecisionReason(e.Code)}
		if active, ok := e.Details["activeSession"].(map[string]any); ok {
			name, _ := active["deviceName"].(string)
			id, _ := active["deviceId"].(string)
			seen, _ := active["lastSeenAt"].(string)
			state.ActiveSession = &ActiveSession{DeviceID: id, DeviceName: name, LastSeenAt: seen}
		}
		if m, ok := e.Details["maxDevices"].(float64); ok {
			n := int(m)
			state.MaxDevices = &n
		}
		if e.CorrelationID != "" {
			state.CorrelationID = &e.CorrelationID
		}
		s.setState(state)
	default:
		s.lock(e, false)
	}
}

// adopt — 200 응답 → 검증(9절) → Active → 다음 하트비트.
func (s *Session) adopt(ctx context.Context, run int, raw any) error {
	session, token, err := readSessionResponse(raw)
	if err != nil {
		return err
	}
	claims, err := s.verifier.verifyLicense(ctx, token.Token, &sessionExpectation{sid: session.ID, deviceID: session.DeviceID, generation: session.Generation}, 0)
	if err != nil {
		return err
	}
	if !s.live(run) {
		return nil
	}
	active := Active{Session: *session, LicenseToken: *token, Claims: *claims}
	s.mu.Lock()
	s.held = &active
	s.failures = 0
	if s.offline != nil {
		s.offline()
		s.offline = nil
	}
	s.mu.Unlock()
	s.setState(active)
	s.scheduleHeartbeat(run, session.HeartbeatSec, 0)
	return nil
}

func (s *Session) scheduleHeartbeat(run, heartbeatSec, retryAfterSec int) {
	delay := jittered(s.ports, time.Duration(heartbeatSec)*time.Second, RuleSessionHeartbeatJitterMin, RuleSessionHeartbeatJitterMax)
	if retry := time.Duration(retryAfterSec) * time.Second; retry > delay {
		delay = retry
	}
	cancel := s.ports.Scheduler.AfterFunc(delay, func() { s.beat(run) })
	s.mu.Lock()
	s.heartbeat = cancel
	s.mu.Unlock()
}

// beat — 8.3절 하트비트.
func (s *Session) beat(run int) {
	s.mu.Lock()
	if s.run != run || s.held == nil {
		s.mu.Unlock()
		return
	}
	held := *s.held
	s.mu.Unlock()
	ctx := context.Background()
	res, err := s.tokens.authed(ctx, func(bearer string) (*apiResponse, error) {
		return s.api.send(ctx, requestOptions{
			Method: "POST",
			URL:    s.api.url(RouteHeartbeatSession.Path, map[string]string{"sid": held.Session.ID}, nil),
			Body:   map[string]int{"generation": held.Session.Generation},
			Bearer: bearer,
		})
	})
	if !s.live(run) {
		return
	}
	if err == nil {
		err = s.adopt(ctx, run, res.JSON)
		if err == nil || !s.live(run) {
			return
		}
	}
	e := toError(err)
	switch {
	case e.Transient():
		s.mu.Lock()
		s.failures++
		failures := s.failures
		current := s.current
		s.mu.Unlock()
		switch current.(type) {
		case Active, Degraded:
			s.setState(Degraded{Active: held, ConsecutiveFailures: failures, OfflineUntil: held.LicenseToken.ExpiresAt, LastError: viewOf(e)})
			s.armOfflineExpiry(run, held.LicenseToken.ExpiresAt)
		}
		retry := 0
		if e.Code == CodeRateLimited || e.HTTPStatus == 429 {
			retry = e.RetryAfterSec
		}
		s.scheduleHeartbeat(run, held.Session.HeartbeatSec, retry)
	case e.Code == CodeSessionRevoked:
		// 리스가 끝났을 때도 이 코드다 — 한 번 다시 얻는다(같은 instanceId, 새 키)
		s.beginAcquire(false, e)
	default:
		s.lock(e, false)
	}
}

// armOfflineExpiry — 8.4절. offlineUntil이 지나도록 성공하지 못하면 잠근다. 재시도는 그대로.
func (s *Session) armOfflineExpiry(run int, offlineUntil string) {
	s.mu.Lock()
	if s.offline != nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	until, err := time.Parse(time.RFC3339, offlineUntil)
	delay := time.Duration(0)
	if err == nil {
		delay = max(until.Sub(s.ports.Clock.Now()), 0)
	}
	cancel := s.ports.Scheduler.AfterFunc(delay, func() {
		s.mu.Lock()
		s.offline = nil
		ok := s.run == run && s.current.Type() == "Degraded"
		s.mu.Unlock()
		if ok {
			s.setState(Locked{Code: CodeOfflineExpired, Message: "하트비트에 성공하지 못한 채 licenseToken이 만료됐다", Retrying: true})
		}
	})
	s.mu.Lock()
	s.offline = cancel
	s.mu.Unlock()
}

func (s *Session) lock(e *Error, retrying bool) {
	s.mu.Lock()
	s.cancelTimersLocked()
	s.mu.Unlock()
	state := Locked{Code: e.Code, Message: e.Message, Details: e.Details, Retrying: retrying}
	if e.CorrelationID != "" {
		state.CorrelationID = &e.CorrelationID
	}
	s.setState(state)
}
