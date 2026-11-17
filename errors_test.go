package bydev

import "testing"

// 명세 3.4 — 일시적 실패 분류.
func TestTransient(t *testing.T) {
	cases := []struct {
		code   string
		status int
		want   bool
	}{
		{CodeRateLimited, 429, true},
		{CodeInternalError, 503, true},
		{CodeNetworkError, 0, true},
		// 429인 한도 초과 코드는 끝난 실패다
		{CodeTakeoverLimitExceeded, 429, false},
		{CodeDeviceReleaseLimitExceeded, 429, false},
		// 모르는 코드만 HTTP 상태로
		{"FUTURE_THROTTLE", 429, true},
		{"FUTURE_OUTAGE", 502, true},
		{"FUTURE_FORBIDDEN", 403, false},
		{"FUTURE_NOTHING", 0, false},
		{CodeStorageFailed, 0, false},
	}
	for _, c := range cases {
		e := &Error{Code: c.code, HTTPStatus: c.status}
		if got := e.Transient(); got != c.want {
			t.Errorf("%s %d: Transient() = %v, want %v", c.code, c.status, got, c.want)
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := sdkError(CodeNetworkError, "아래", nil)
	wrapped := sdkError(CodeStorageFailed, "위", cause)
	if e, ok := AsError(wrapped); !ok || e.Code != CodeStorageFailed {
		t.Fatalf("AsError = %v %v", e, ok)
	}
	if wrapped.Unwrap() != cause {
		t.Fatal("Unwrap이 원인을 돌려주지 않는다")
	}
}
