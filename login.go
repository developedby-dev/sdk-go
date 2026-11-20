package bydev

import (
	"context"
	"sync"
	"time"
)

// LoginResult는 로그인이 끝났을 때 받은 스코프다.
type LoginResult struct {
	Scope string `json:"scope"`
}

// LoginAttempt는 디바이스 플로우 하나다(명세 5절). 코드를 받은 순간부터 폴링하고 Wait는 그 결과를 기다린다.
type LoginAttempt struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               string

	expiresAt time.Time
	code      *deviceCode
	api       *api
	ports     Ports
	tokens    *tokenManager
	clientID  string

	mu       sync.Mutex
	interval int
	settled  bool
	cancel   func()
	done     chan struct{}
	result   *LoginResult
	err      error
}

func newLoginAttempt(code *deviceCode, c *Client) *LoginAttempt {
	now := c.ports.Clock.Now()
	l := &LoginAttempt{
		UserCode:                code.UserCode,
		VerificationURI:         code.VerificationURI,
		VerificationURIComplete: code.VerificationURIComplete,
		expiresAt:               now.Add(time.Duration(code.ExpiresIn) * time.Second),
		code:                    code,
		api:                     c.api,
		ports:                   c.ports,
		tokens:                  c.tokens,
		clientID:                c.config.ClientID,
		interval:                code.Interval,
		done:                    make(chan struct{}),
	}
	l.ExpiresAt = iso(l.expiresAt)
	l.schedulePoll(0)
	return l
}

// Wait는 로그인이 끝나기를 기다린다.
func (l *LoginAttempt) Wait(ctx context.Context) (*LoginResult, error) {
	if err := l.ports.Scheduler.Wait(ctx, l.done); err != nil {
		return nil, err
	}
	return l.result, l.err
}

// Cancel은 로그인을 취소한다 — Wait는 LOGIN_CANCELLED로 끝난다.
func (l *LoginAttempt) Cancel() {
	l.finish(nil, sdkError(CodeLoginCancelled, "로그인을 취소했다", nil))
}

func (l *LoginAttempt) finish(result *LoginResult, err error) {
	l.mu.Lock()
	if l.settled {
		l.mu.Unlock()
		return
	}
	l.settled = true
	cancel := l.cancel
	l.cancel = nil
	l.result, l.err = result, err
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	close(l.done)
}

func (l *LoginAttempt) isSettled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.settled
}

// schedulePoll — 폴링 지터는 위로만(interval보다 이르면 SLOW_DOWN이다). 429면 retryAfterSec(0이면 없음)보다 이르게 묻지 않는다(명세 5절).
func (l *LoginAttempt) schedulePoll(retryAfterSec int) {
	l.mu.Lock()
	interval := l.interval
	l.mu.Unlock()
	delay := jittered(l.ports, time.Duration(interval)*time.Second, RuleLoginPollJitterMin, RuleLoginPollJitterMax)
	if floor := time.Duration(retryAfterSec) * time.Second; floor > delay {
		delay = floor
	}
	if l.ports.Clock.Now().Add(delay).After(l.expiresAt) {
		l.finish(nil, &Error{Code: CodeExpiredToken, Message: "로그인 코드가 만료됐다 — 처음부터 다시"})
		return
	}
	cancel := l.ports.Scheduler.AfterFunc(delay, l.poll)
	l.mu.Lock()
	if l.settled {
		l.mu.Unlock()
		cancel()
		return
	}
	l.cancel = cancel
	l.mu.Unlock()
}

func (l *LoginAttempt) poll() {
	if l.isSettled() {
		return
	}
	ctx := context.Background()
	doc, err := l.api.discovery(ctx)
	if err == nil {
		var res *apiResponse
		res, err = l.api.send(ctx, requestOptions{Method: "POST", URL: doc.TokenEndpoint, Body: map[string]string{
			"grant_type": DeviceCodeGrantType, "client_id": l.clientID, "device_code": l.code.DeviceCode,
		}})
		if err == nil {
			if l.isSettled() {
				return
			}
			set, err := readTokenResponse(res.JSON)
			if err == nil {
				err = l.tokens.adopt(ctx, set)
			}
			if err != nil {
				l.finish(nil, err)
			} else {
				l.finish(&LoginResult{Scope: set.Scope}, nil)
			}
			return
		}
	}
	if l.isSettled() {
		return
	}
	e := toError(err)
	switch {
	case e.Code == CodeAuthorizationPending:
		l.schedulePoll(0)
	case e.Transient():
		retry := 0
		if e.Code == CodeRateLimited || e.HTTPStatus == 429 {
			retry = e.RetryAfterSec
		}
		l.schedulePoll(retry)
	case e.Code == CodeSlowDown:
		l.mu.Lock()
		if e.RetryAfterSec > 0 {
			l.interval = e.RetryAfterSec
		} else {
			l.interval += RuleLoginSlowDownIncrementSec
		}
		l.mu.Unlock()
		l.schedulePoll(0)
	default:
		l.finish(nil, e)
	}
}
