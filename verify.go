package bydev

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 명세 9절 — 토큰 검증 · JWKS 캐시 · 세대번호 단조 확인.

type keySet struct {
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
	expiresAt time.Time
}

type sessionExpectation struct {
	sid        string
	deviceID   string
	generation int
}

type verifier struct {
	api              *api
	ports            Ports
	clientID         string
	trackGenerations bool
	mu               sync.Mutex
	set              *keySet
	fetching         single[*keySet]
	generations      map[string]int
}

func newVerifier(a *api, p Ports, clientID string, track bool) *verifier {
	return &verifier{api: a, ports: p, clientID: clientID, trackGenerations: track, generations: map[string]int{}}
}

func invalid(message string) *Error { return sdkError(CodeTokenInvalid, message, nil) }

var maxAgePattern = regexp.MustCompile(`max-age=(\d+)`)

// verifySigned — 9절 1 ~ 4. 페이로드를 돌려준다.
func (v *verifier) verifySigned(ctx context.Context, token, typ string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid("JWT 형식이 아니다")
	}
	var header map[string]any
	var payload map[string]any
	head, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	body, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(head, &header) != nil || json.Unmarshal(body, &payload) != nil {
		return nil, invalid("JWT를 읽지 못했다")
	}
	if header["alg"] != "EdDSA" {
		return nil, invalid(fmt.Sprintf("alg %v", header["alg"]))
	}
	if header["typ"] != typ {
		return nil, invalid(fmt.Sprintf("typ %v", header["typ"]))
	}
	kid, ok := header["kid"].(string)
	if !ok {
		return nil, invalid("kid가 없다")
	}
	key, err := v.keyFor(ctx, kid)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, invalid("서명이 맞지 않는다")
	}
	doc, err := v.api.discovery(ctx)
	if err != nil {
		return nil, err
	}
	if payload["iss"] != doc.Issuer {
		return nil, invalid("iss가 다르다")
	}
	if payload["aud"] != v.clientID {
		return nil, invalid("aud가 이 client_id가 아니다")
	}
	exp, ok := payload["exp"].(float64)
	nowSec := float64(v.ports.Clock.Now().UnixMilli()) / 1000
	if !ok || exp <= nowSec-float64(RuleTokenClockLeewaySec) {
		return nil, invalid("만료된 토큰")
	}
	return payload, nil
}

func (v *verifier) verifyLicense(ctx context.Context, token string, expect *sessionExpectation, minGeneration int) (*LicenseClaims, error) {
	payload, err := v.verifySigned(ctx, token, "license+jwt")
	if err != nil {
		return nil, err
	}
	claims, err := readLicenseClaims(payload)
	if err != nil {
		return nil, invalid("클레임 모양이 다르다")
	}
	if expect != nil {
		if claims.Sid != expect.sid {
			return nil, invalid("sid가 세션과 다르다")
		}
		if claims.DeviceID != expect.deviceID {
			return nil, invalid("device_id가 세션과 다르다")
		}
		if claims.Generation != expect.generation {
			return nil, invalid("generation이 세션과 다르다")
		}
	}
	if minGeneration > 0 && claims.Generation < minGeneration {
		return nil, sdkError(CodeGenerationRegressed, fmt.Sprintf("세대번호 %d < 이미 본 %d", claims.Generation, minGeneration), nil)
	}
	if v.trackGenerations {
		slot := claims.Sub + "|" + claims.DeviceID
		v.mu.Lock()
		seen, ok := v.generations[slot]
		if ok && claims.Generation < seen {
			v.mu.Unlock()
			return nil, sdkError(CodeGenerationRegressed, fmt.Sprintf("세대번호 %d < 이미 본 %d", claims.Generation, seen), nil)
		}
		if claims.Generation > seen {
			v.generations[slot] = claims.Generation
		}
		v.mu.Unlock()
	}
	return claims, nil
}

func (v *verifier) verifyAccess(ctx context.Context, token string) (*AccessClaims, error) {
	payload, err := v.verifySigned(ctx, token, "at+jwt")
	if err != nil {
		return nil, err
	}
	claims, err := readAccessClaims(payload)
	if err != nil {
		return nil, invalid("클레임 모양이 다르다")
	}
	return claims, nil
}

// keyFor — 9.1절. 지난 캐시는 쓰지 않는다 · 모르는 kid는 1분에 한 번만 다시 받는다.
func (v *verifier) keyFor(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	now := v.ports.Clock.Now()
	v.mu.Lock()
	set := v.set
	v.mu.Unlock()
	var err error
	if set == nil || !now.Before(set.expiresAt) {
		if set, err = v.fetchKeys(ctx); err != nil {
			return nil, err
		}
	}
	if key, ok := set.keys[kid]; ok {
		return key, nil
	}
	if now.Sub(set.fetchedAt) < time.Duration(RuleJwksUnknownKidRefetchMinIntervalSec)*time.Second {
		return nil, invalid("모르는 kid " + kid)
	}
	if set, err = v.fetchKeys(ctx); err != nil {
		return nil, err
	}
	if key, ok := set.keys[kid]; ok {
		return key, nil
	}
	return nil, invalid("모르는 kid " + kid)
}

func (v *verifier) fetchKeys(ctx context.Context) (*keySet, error) {
	return v.fetching.do(ctx, v.ports.Scheduler, func() (*keySet, error) {
		doc, err := v.api.discovery(ctx)
		if err != nil {
			return nil, err
		}
		res, err := v.api.send(ctx, requestOptions{Method: "GET", URL: doc.JWKSURI})
		if err != nil {
			return nil, err
		}
		r := &reader{}
		keys := map[string]ed25519.PublicKey{}
		for _, item := range r.array(r.object(res.JSON, "$")["keys"], "keys") {
			jwk, ok := item.(map[string]any)
			if !ok || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
				continue
			}
			kid, _ := jwk["kid"].(string)
			x, _ := jwk["x"].(string)
			raw, err := base64.RawURLEncoding.DecodeString(x)
			if kid == "" || err != nil || len(raw) != ed25519.PublicKeySize {
				v.ports.Logger.Warn("JWKS 키를 읽지 못했다", "kid", kid)
				continue
			}
			keys[kid] = ed25519.PublicKey(raw)
		}
		if r.err != nil {
			return nil, r.err
		}
		age := RuleJwksDefaultMaxAgeSec
		if m := maxAgePattern.FindStringSubmatch(res.Header["cache-control"]); m != nil {
			age, _ = strconv.Atoi(m[1])
		}
		fetched := v.ports.Clock.Now()
		set := &keySet{keys: keys, fetchedAt: fetched, expiresAt: fetched.Add(time.Duration(age) * time.Second)}
		v.mu.Lock()
		v.set = set
		v.mu.Unlock()
		return set, nil
	})
}
