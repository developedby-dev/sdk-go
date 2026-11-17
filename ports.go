package bydev

import (
	"context"
	"time"
)

// 명세 2절 — 바꿔 끼울 수 있는 포트. SDK 안에서 시계 · 타이머 · 난수를 직접 읽지 않는다.

// HTTPRequest는 전송 포트가 보낼 요청이다. Body가 nil이면 본문이 없다.
type HTTPRequest struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

// HTTPResponse는 받은 응답이다. Header 이름은 소문자다.
type HTTPResponse struct {
	Status int
	Header map[string]string
	Body   []byte
}

// Transport는 요청을 보낸다. 연결 실패 · 시간 초과는 NETWORK_ERROR *Error로 돌려준다. 3xx를 따라가지 않는다.
type Transport interface {
	Send(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
}

// CredentialRecord는 보안 저장소에 두는 기록이다(명세 3.6). access_token은 두지 않는다.
type CredentialRecord struct {
	Version      int    `json:"version"`
	RefreshToken string `json:"refreshToken"`
	Scope        string `json:"scope"`
	SavedAt      string `json:"savedAt"`
}

// CredentialStore는 로그인 기록을 둔다. 없으면 Load가 nil을 돌려준다.
type CredentialStore interface {
	Load(ctx context.Context) (*CredentialRecord, error)
	Save(ctx context.Context, record CredentialRecord) error
	Clear(ctx context.Context) error
}

// Clock은 지금 시각이다.
type Clock interface {
	Now() time.Time
}

// Scheduler는 나중 작업 · 기다림이다. SDK가 시간이나 다른 작업을 기다리는 곳은 모두 Sleep · Wait를 거친다(명세 2절 — 블로킹 언어).
type Scheduler interface {
	AfterFunc(d time.Duration, task func()) (cancel func())
	Sleep(ctx context.Context, d time.Duration) error
	Wait(ctx context.Context, done <-chan struct{}) error
}

// Random은 [0, 1) 실수와 UUID v4다.
type Random interface {
	Float64() float64
	UUID() string
}

// FingerprintSource는 운영체제의 기기 식별자다. 없으면 ""를 돌려준다 — 원본은 SDK 밖으로 나가지 않는다(해시만, 명세 10절).
type FingerprintSource interface {
	Read(ctx context.Context) (string, error)
}

// Logger에는 토큰 · 지문 출처 값을 넘기지 않는다.
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
}

// Ports는 클라이언트가 쓰는 포트 묶음이다. 비운 칸은 기본 구현이다.
type Ports struct {
	Transport   Transport
	Store       CredentialStore
	Clock       Clock
	Scheduler   Scheduler
	Random      Random
	Fingerprint FingerprintSource
	Logger      Logger
}
