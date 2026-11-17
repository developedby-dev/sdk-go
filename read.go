package bydev

import (
	"encoding/json"
	"fmt"
	"math"
)

// 관대한 읽기(명세 0절 5) — 필요한 필드는 확인하고, 모르는 필드는 버리고, 모르는 열거 값은 문자열 그대로. 어긋나면 PROTOCOL_ERROR.

type reader struct{ err error }

func (r *reader) fail(path, want string, got any) {
	if r.err == nil {
		b, _ := json.Marshal(got)
		r.err = sdkError(CodeProtocolError, fmt.Sprintf("응답의 %s가 %s가 아니다 (%s)", path, want, b), nil)
	}
}

func (r *reader) object(v any, path string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		r.fail(path, "객체", v)
		return map[string]any{}
	}
	return m
}

func (r *reader) str(v any, path string) string {
	s, ok := v.(string)
	if !ok {
		r.fail(path, "문자열", v)
	}
	return s
}

func (r *reader) integer(v any, path string) int {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) {
		r.fail(path, "정수", v)
		return 0
	}
	return int(f)
}

func (r *reader) boolean(v any, path string) bool {
	b, ok := v.(bool)
	if !ok {
		r.fail(path, "참/거짓", v)
	}
	return b
}

func (r *reader) array(v any, path string) []any {
	a, ok := v.([]any)
	if !ok {
		r.fail(path, "배열", v)
	}
	return a
}

func (r *reader) optStr(v any, path string) *string {
	if v == nil {
		return nil
	}
	s := r.str(v, path)
	return &s
}

func (r *reader) optInt(v any, path string) *int {
	if v == nil {
		return nil
	}
	i := r.integer(v, path)
	return &i
}
