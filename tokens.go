package bydev

import (
	"context"
	"sync"
	"time"
)

// 명세 3.5 · 3.6 · 6절 — 기록 보관 · 갱신 · 인증 요청 감싸기.

type accessToken struct {
	token     string
	expiresAt time.Time
}

type tokenManager struct {
	api        *api
	ports      Ports
	clientID   string
	mu         sync.Mutex
	access     *accessToken
	refreshing single[string]
}

func (t *tokenManager) load(ctx context.Context) (*CredentialRecord, error) {
	record, err := t.ports.Store.Load(ctx)
	if err != nil {
		return nil, sdkError(CodeStorageFailed, "보안 저장소를 읽지 못했다", err)
	}
	if record == nil || record.Version != RuleStorageRecordVersion {
		return nil, nil
	}
	return record, nil
}

// adopt — 6절 3 · 5절. 저장한 뒤에 쓴다.
func (t *tokenManager) adopt(ctx context.Context, set *tokenSet) error {
	t.setAccess(nil)
	record := CredentialRecord{Version: 1, RefreshToken: set.RefreshToken, Scope: set.Scope, SavedAt: iso(t.ports.Clock.Now())}
	if err := t.ports.Store.Save(ctx, record); err != nil {
		return sdkError(CodeStorageFailed, "새 로그인을 보안 저장소에 두지 못했다 — 새 토큰을 쓰지 않는다", err)
	}
	t.setAccess(&accessToken{token: set.AccessToken, expiresAt: t.ports.Clock.Now().Add(time.Duration(set.ExpiresIn) * time.Second)})
	return nil
}

func (t *tokenManager) setAccess(a *accessToken) {
	t.mu.Lock()
	t.access = a
	t.mu.Unlock()
}

func (t *tokenManager) accessToken(ctx context.Context) (string, error) {
	t.mu.Lock()
	a := t.access
	t.mu.Unlock()
	if a != nil && a.expiresAt.Add(-time.Duration(RuleTokenRefreshSkewSec)*time.Second).After(t.ports.Clock.Now()) {
		return a.token, nil
	}
	return t.refresh(ctx)
}

// refresh — 6절 1. 한 번에 하나.
func (t *tokenManager) refresh(ctx context.Context) (string, error) {
	t.setAccess(nil)
	return t.refreshing.do(ctx, t.ports.Scheduler, func() (string, error) { return t.doRefresh(ctx) })
}

func (t *tokenManager) doRefresh(ctx context.Context) (string, error) {
	record, err := t.load(ctx)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", sdkError(CodeNotSignedIn, "로그인이 없다 — 먼저 로그인한다", nil)
	}
	doc, err := t.api.discovery(ctx)
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		res, err := t.api.send(ctx, requestOptions{Method: "POST", URL: doc.TokenEndpoint, Body: map[string]string{
			"grant_type": "refresh_token", "client_id": t.clientID, "refresh_token": record.RefreshToken,
		}})
		if err == nil {
			set, err := readTokenResponse(res.JSON)
			if err != nil {
				return "", err
			}
			if err := t.adopt(ctx, set); err != nil {
				return "", err
			}
			return set.AccessToken, nil
		}
		e := toError(err)
		if e.Code == CodeInvalidGrant {
			t.forgetStored(ctx)
			return "", e
		}
		if !e.Transient() || attempt >= len(RuleTokenRefreshRetryDelaysSec) {
			return "", e
		}
		delay := time.Duration(RuleTokenRefreshRetryDelaysSec[attempt]*1000+0.5) * time.Millisecond
		if err := t.ports.Scheduler.Sleep(ctx, delay); err != nil {
			return "", err
		}
	}
}

// authed — 3.5절. 만료면 한 번만 갱신하고 다시 보낸다.
func (t *tokenManager) authed(ctx context.Context, send func(token string) (*apiResponse, error)) (*apiResponse, error) {
	token, err := t.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	res, err := send(token)
	if e, ok := AsError(err); !ok || e.Code != CodeExpiredToken {
		return res, err
	}
	token, err = t.refresh(ctx)
	if err != nil {
		return nil, err
	}
	res, err = send(token)
	if e, ok := AsError(err); ok && e.Code == CodeExpiredToken {
		// 갓 받은 토큰도 거절됐다 — 다음 요청이 같은 토큰을 다시 쓰지 않게 버린다
		t.setAccess(nil)
	}
	return res, err
}

func (t *tokenManager) forgetStored(ctx context.Context) {
	t.setAccess(nil)
	if err := t.ports.Store.Clear(ctx); err != nil {
		t.ports.Logger.Warn("끝난 로그인의 기록을 지우지 못했다")
	}
}

// logout — 7절. 폐기 요청은 한 번, 결과와 상관없이 지운다.
func (t *tokenManager) logout(ctx context.Context) (bool, error) {
	record, err := t.load(ctx)
	if err != nil {
		return false, err
	}
	revoked := false
	if record != nil {
		if doc, err := t.api.discovery(ctx); err == nil {
			_, err := t.api.send(ctx, requestOptions{Method: "POST", URL: doc.RevocationEndpoint, Body: map[string]string{
				"client_id": t.clientID, "token": record.RefreshToken, "token_type_hint": "refresh_token",
			}})
			revoked = err == nil
		}
	}
	t.setAccess(nil)
	if err := t.ports.Store.Clear(ctx); err != nil {
		return revoked, sdkError(CodeStorageFailed, "로그인 기록을 지우지 못했다", err)
	}
	return revoked, nil
}
