// Package bydev는 데브 라이선스 API의 공식 Go SDK다.
//
// 디바이스 로그인 · refresh_token 회전 · 세션 리스(하트비트) · licenseToken 검증 · 업데이트 확인을 sdks/spec 동작 명세대로 한다.
// 의존성은 표준 라이브러리뿐이다(cgo 없음). 이용 가능 여부를 참/거짓 하나로 알리지 않는다 — 세션 상태와 검증된 토큰의 클레임을 쓴다.
package bydev

// SDKVersion은 User-Agent(bydev-go/<판>)에 실린다.
const SDKVersion = "1.0.0"

// UserAgent는 모든 요청에 싣는 값이다(명세 3.1).
const UserAgent = "bydev-go/" + SDKVersion
