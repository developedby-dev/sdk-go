package bydev

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// 명세 12절 — 판매자 서버의 도우미. 앱 쪽 클라이언트와 상태를 나누지 않는다.

// WebhookVerification은 검증된 웹훅의 id와 시각이다. 중복 수신은 ID로 거른다.
type WebhookVerification struct {
	ID        string
	Timestamp int64
}

// VerifyWebhook은 웹훅 서명을 검증한다(안내서 11장 · Standard Webhooks v1). rawBody는 받은 그대로의 본문이다 — 파싱했다가 다시 만든 바이트는
// 서명이 맞지 않는다. 시크릿을 교체하는 중이면 둘 다 넘긴다. clock이 nil이면 시스템 시계.
func VerifyWebhook(secrets []string, header http.Header, rawBody []byte, clock Clock) (*WebhookVerification, error) {
	id := header.Get("webhook-id")
	timestamp := header.Get("webhook-timestamp")
	signatures := header.Get("webhook-signature")
	if id == "" || timestamp == "" || signatures == "" {
		return nil, sdkError(CodeWebhookInvalid, "웹훅 헤더(webhook-id · webhook-timestamp · webhook-signature)가 없다", nil)
	}
	sent, err := strconv.ParseInt(timestamp, 10, 64)
	if clock == nil {
		clock = SystemClock
	}
	now := float64(clock.Now().UnixMilli()) / 1000
	if err != nil || math.Abs(now-float64(sent)) > float64(RuleWebhookToleranceSec) {
		return nil, sdkError(CodeWebhookInvalid, "웹훅 시각이 허용 범위 밖이다 — 재전송 공격일 수 있다", nil)
	}
	var candidates [][]byte
	for _, entry := range strings.Fields(signatures) {
		version, value, ok := strings.Cut(entry, ",")
		if !ok || version != RuleWebhookSignatureVersion {
			continue
		}
		if sig, err := base64.StdEncoding.DecodeString(value); err == nil {
			candidates = append(candidates, sig)
		}
	}
	signed := []byte(id + "." + timestamp + "." + string(rawBody))
	for _, secret := range secrets {
		raw, found := strings.CutPrefix(secret, RuleWebhookSecretPrefix)
		if !found {
			return nil, sdkError(CodeConfiguration, "웹훅 시크릿은 "+RuleWebhookSecretPrefix+"로 시작한다", nil)
		}
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, sdkError(CodeConfiguration, "웹훅 시크릿을 읽지 못했다", err)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(signed)
		expected := mac.Sum(nil)
		for _, candidate := range candidates {
			if hmac.Equal(candidate, expected) {
				return &WebhookVerification{ID: id, Timestamp: sent}, nil
			}
		}
	}
	return nil, sdkError(CodeWebhookInvalid, "웹훅 서명이 맞지 않는다", nil)
}

// ServerVerifier는 판매자 서버의 토큰 검증이다(안내서 09장) — JWKS를 받아 캐시한다.
type ServerVerifier struct{ v *verifier }

// NewServerVerifier는 서버 검증기를 만든다. transport · clock이 nil이면 기본 구현.
func NewServerVerifier(baseURL, clientID string, transport Transport, clock Clock) *ServerVerifier {
	ports := Ports{Transport: transport, Clock: clock}.withDefaults()
	return &ServerVerifier{v: newVerifier(newAPI(baseURL, ports), ports, clientID, false)}
}

// VerifyAccessToken은 access_token(at+jwt)을 검증한다.
func (s *ServerVerifier) VerifyAccessToken(ctx context.Context, token string) (*AccessClaims, error) {
	return s.v.verifyAccess(ctx, token)
}

// VerifyLicenseToken은 licenseToken을 검증한다. minGeneration — 같은 sub · device_id에서 이미 본 가장 큰 세대번호(0이면 보지 않는다).
func (s *ServerVerifier) VerifyLicenseToken(ctx context.Context, token string, minGeneration int) (*LicenseClaims, error) {
	return s.v.verifyLicense(ctx, token, nil, minGeneration)
}
