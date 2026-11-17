package bydev

import (
	"errors"
	"slices"
)

// Error는 SDK의 에러 하나다(명세 3.3). Code로 분기하고 Message는 보여 주기만 한다. 앱의 오류 화면에 CorrelationID를 보이면 문의를 바로 찾는다.
type Error struct {
	Code          string
	Message       string
	HTTPStatus    int // 0이면 없음
	CorrelationID string
	RetryAfterSec int // 0이면 없음
	Details       map[string]any
	cause         error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func (e *Error) Unwrap() error { return e.cause }

// Transient는 일시적 실패인지다(명세 3.4). 아는 코드는 그 뜻대로 — 429인 한도 초과 코드는 끝난 실패 — 모르는 코드만 HTTP 상태로 나눈다.
func (e *Error) Transient() bool {
	if slices.Contains(RuleTransientCodes, e.Code) {
		return true
	}
	if _, known := APIErrorHTTPStatus[e.Code]; known || slices.Contains(SDKErrorCodes, e.Code) {
		return false
	}
	if e.HTTPStatus == 0 {
		return false
	}
	if slices.Contains(RuleTransientUnknownCodeStatuses, e.HTTPStatus) {
		return true
	}
	for _, r := range RuleTransientUnknownCodeStatusRanges {
		if e.HTTPStatus >= r[0] && e.HTTPStatus <= r[1] {
			return true
		}
	}
	return false
}

func sdkError(code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, cause: cause}
}

// AsError는 err가 *Error면 그것을 돌려준다.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func toError(err error) *Error {
	if e, ok := AsError(err); ok {
		return e
	}
	return sdkError(CodeProtocolError, err.Error(), err)
}
