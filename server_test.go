package bydev

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 안내서 11장의 서명 예시 — 문서와 SDK가 같은 값으로 맞는다(TS 시험과 같은 값).
var webhookExample = struct{ secret, id, timestamp, body, signature string }{
	secret:    "whsec_/MU12AiKByBoT7xt+p81N/uKdp/WxQRb",
	id:        "evt_01J9MC4D6E8F0G2H4J6K8M0N2P",
	timestamp: "1791295205",
	body:      `{"id":"evt_01J9MC4D6E8F0G2H4J6K8M0N2P","type":"build.review_completed","occurredAt":"2026-10-06T14:00:00Z","mode":"LIVE","simulated":false,"data":{"build":{"id":"build_01J9M4D6F8H0J2K4M6N8P0R2S4","productId":"prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD","version":"1.4.2","reviewedAt":"2026-10-06T13:58:00Z","result":"APPROVED"}}}`,
	signature: "v1,vmsiq2HY4gik/WNJjXJzuESzXAjJgr8Vi13SKwwhgEo=",
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func atSec(sec int64) Clock { return fixedClock{time.Unix(sec, 0)} }

func webhookHeader(signature string) http.Header {
	h := http.Header{}
	h.Set("Webhook-Id", webhookExample.id)
	h.Set("Webhook-Timestamp", webhookExample.timestamp)
	h.Set("Webhook-Signature", signature)
	return h
}

const exampleSent int64 = 1791295205

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := AsError(err)
	if !ok || e.Code != code {
		t.Fatalf("에러 %v, want %s", err, code)
	}
}

func TestVerifyWebhookExample(t *testing.T) {
	got, err := VerifyWebhook([]string{webhookExample.secret}, webhookHeader(webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent+10))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != webhookExample.id || got.Timestamp != exampleSent {
		t.Fatalf("%+v", got)
	}
}

func TestVerifyWebhookRotation(t *testing.T) {
	// 서명 여러 개 · 시크릿 여러 개 중 하나라도 맞으면
	if _, err := VerifyWebhook([]string{webhookExample.secret}, webhookHeader("v1,AAAA "+webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWebhook([]string{"whsec_AAAAAAAAAAAAAAAAAAAAAAAA", webhookExample.secret}, webhookHeader(webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWebhookRejects(t *testing.T) {
	secrets := []string{webhookExample.secret}
	_, err := VerifyWebhook(secrets, webhookHeader(webhookExample.signature), []byte(webhookExample.body+" "), atSec(exampleSent))
	wantCode(t, err, CodeWebhookInvalid)
	_, err = VerifyWebhook(secrets, webhookHeader(webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent+301))
	wantCode(t, err, CodeWebhookInvalid)
	_, err = VerifyWebhook(secrets, webhookHeader(webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent-301))
	wantCode(t, err, CodeWebhookInvalid)
	missing := http.Header{}
	missing.Set("webhook-id", webhookExample.id)
	_, err = VerifyWebhook(secrets, missing, []byte(webhookExample.body), atSec(exampleSent))
	wantCode(t, err, CodeWebhookInvalid)
	_, err = VerifyWebhook(secrets, webhookHeader("v2,"+webhookExample.signature[3:]), []byte(webhookExample.body), atSec(exampleSent))
	wantCode(t, err, CodeWebhookInvalid)
	// 접두사 없는 시크릿은 설정 실수
	_, err = VerifyWebhook([]string{"/MU12AiKByBoT7xt+p81N/uKdp/WxQRb"}, webhookHeader(webhookExample.signature), []byte(webhookExample.body), atSec(exampleSent))
	wantCode(t, err, CodeConfiguration)
}

// 판매자 서버의 토큰 검증 — 발견 문서 · JWKS를 받아 at+jwt를 검증한다.
func TestServerVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var base string
	jwksHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": base, "jwks_uri": base + "/.well-known/jwks.json",
				"device_authorization_endpoint": base + "/v1/oauth/device/code", "token_endpoint": base + "/v1/oauth/token",
				"revocation_endpoint": base + "/v1/oauth/revoke",
			})
		case "/.well-known/jwks.json":
			jwksHits++
			w.Header().Set("cache-control", "public, max-age=300")
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "OKP", "crv": "Ed25519", "kid": "srv-k1", "use": "sig", "alg": "EdDSA",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			}}})
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"PRODUCT_NOT_FOUND","message":"없음"}`))
		}
	}))
	defer server.Close()
	base = server.URL
	now := time.Unix(1791295205, 0)
	mint := func(kid string, claims map[string]any) string {
		head, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": kid})
		body, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
		return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
	}
	claims := func(aud string) map[string]any {
		return map[string]any{
			"iss": base, "sub": "usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", "aud": aud, "client_id": aud,
			"scope": "entitlement.read", "iat": now.Unix(), "exp": now.Unix() + 3600, "jti": "at_srv0001",
		}
	}
	v := NewServerVerifier(base, "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", nil, fixedClock{now})
	ctx := context.Background()
	got, err := v.VerifyAccessToken(ctx, mint("srv-k1", claims("cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW" || got.Scope != "entitlement.read" {
		t.Fatalf("%+v", got)
	}
	_, err = v.VerifyAccessToken(ctx, mint("srv-k1", claims("cli_other_client_00000000")))
	wantCode(t, err, CodeTokenInvalid)
	// 모르는 kid — 1분 안에는 다시 받지 않는다
	_, err = v.VerifyAccessToken(ctx, mint("srv-k9", claims("cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW")))
	wantCode(t, err, CodeTokenInvalid)
	if jwksHits != 1 {
		t.Fatalf("JWKS를 %d번 받았다, want 1", jwksHits)
	}
}
