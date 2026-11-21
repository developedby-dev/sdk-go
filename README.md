# 데브 SDK: Go

데브 라이선스 API의 공식 Go SDK입니다. 표준 라이브러리(`net/http`, `crypto/ed25519`)만 쓰며 다른 의존성은 없습니다.

[공통 동작 명세](https://github.com/developedby-dev/sdk-spec/blob/main/spec/README.md)를
따르며, [적합성 시험 시나리오](https://github.com/developedby-dev/sdk-spec/tree/main/conformance/scenarios)를 모두 통과합니다.

| 지원 | 버전 |
|---|---|
| 동작 명세 | 1.2.0 |
| API | v1 |
| Go | 1.23 이상, Windows, macOS, Linux (cgo 없이 동작) |

모듈 경로는 `developedby.dev/sdk/go`이고, 패키지 이름은 `bydev`입니다. `go get developedby.dev/sdk/go@latest`로 받습니다(소스는 공개 저장소
`developedby-dev/sdk-go`).

## 빠른 시작

```go
import bydev "developedby.dev/sdk/go"

device := bydev.SystemDeviceInfo()
client, err := bydev.New(bydev.Config{
	BaseURL:   "https://api.developedby.dev",
	ClientID:  "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", // 판매자 콘솔에서 제품마다 발급받습니다
	ProductID: "prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD",
	Scopes:    []string{"entitlement.read", "session.write", "version.read"},
	Device:    &device,
	App:       &bydev.AppInfo{Target: "WINDOWS_X64", Version: "1.4.0"}, // 콘솔에 업로드한 빌드의 버전과 같게
	Ports: bydev.Ports{
		Store:       bydev.DefaultCredentialStore("MyApp", "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", logger),
		Fingerprint: bydev.OSFingerprintSource(filepath.Join(bydev.AppDataDir("MyApp"), "install-id")),
	},
})

if ok, _ := client.HasCredentials(ctx); !ok {
	login, err := client.StartLogin(ctx)
	showCode(login.UserCode, login.VerificationURIComplete) // 화면에 코드와 QR 코드를 보여 줍니다
	_, err = login.Wait(ctx)                                 // 사용자가 브라우저에서 승인할 때까지 기다립니다
}

session, err := client.Session()
session.Subscribe(func(state bydev.SessionState) {
	switch s := state.(type) {
	case bydev.Active:
		enableFeatures(s.Claims) // exp와 sid는 기능 코드에서 쓰고, 참/거짓 하나로만 판단하지 마세요
	case bydev.Degraded:
		enableFeatures(s.Claims) // OfflineUntil까지는 계속 쓸 수 있습니다
	case bydev.NeedsDecision:
		askUser(s) // DEVICE_IN_USE: "여기서 사용할까요?"에 동의하면 session.TakeOver()를 부릅니다
	case bydev.Locked:
		lockApp(s.Code, s.CorrelationID) // 오류 화면에 CorrelationID를 보여 주세요
	}
})
session.Start()
// 앱을 끌 때
session.Stop(ctx)
```

구독 함수는 SDK의 고루틴에서 불립니다. Fyne이나 Wails처럼 UI 스레드가 따로 있는 프레임워크를 사용한다면, 받은 상태를 그 스레드로 넘겨 처리해 주세요.

## 포트

| 포트 | 기본 구현 | 직접 구현하거나 설정할 항목 |
|---|---|---|
| `Transport` | `HTTPTransport(0)`. `net/http` 기반이며 시간 초과는 30초이고, 리다이렉트를 따라가지 않습니다. | 프록시나 인증서 고정이 필요할 때 |
| `Store` | **메모리**. 앱을 끄면 로그인이 사라집니다. | `DefaultCredentialStore`, `DPAPICredentialStore`, `SecretToolCredentialStore`, `FileCredentialStore` |
| `Fingerprint` | 없음. 실행할 때마다 새 기기로 보일 수 있습니다(경고 로그를 남깁니다) | `OSFingerprintSource(설치 ID 파일)`. MachineGuid, IOPlatformUUID, machine-id를 읽고, 못 읽으면 설치 ID를 씁니다. |
| `Clock`, `Scheduler`, `Random` | 시스템 시계, `time.AfterFunc`, `crypto/rand` | 시험할 때 교체합니다. SDK는 시간이 지나기를 기다리거나 다른 작업을 기다릴 때 `Scheduler.Sleep`과 `Wait`만 씁니다. |
| `Logger` | 로그 기록 없음 | 토큰과 기기 지문 원본은 로그로 넘어오지 않습니다. |

`DefaultCredentialStore`는 Windows에서는 DPAPI로 보호한 파일을, Linux에서는 Secret Service를 씁니다. Linux에 `secret-tool`이 없으면 0600 파일에 저장하고
경고를 남깁니다.

macOS에서는 cgo 없이 키체인을 안전하게 쓸 방법이 없어 0600 파일에 저장하고 경고를 남깁니다. `security` 명령은 비밀 값을 명령줄 인자로
받고, 그 명령으로 만든 항목은 다른 프로세스도 `security`로 읽을 수 있기 때문입니다. 키체인이 꼭 필요한 앱은 Security.framework로 `CredentialStore`를 직접
구현해 주세요.

SDK는 비밀 값(refresh_token)을 명령줄 인자로 넘기지 않고, `secret-tool`이나 PowerShell에 표준 입력으로만 전달합니다.

**Linux용 배포 패키지에는 `secret-tool`을 의존성으로 걸어 주세요.** 기본 저장소는 이 명령으로 Secret Service에 접근하는데, Debian과 Ubuntu 데스크톱의
기본 설치에는 이 명령이 없습니다.

Ubuntu 26.04.1에서 확인했으며, Secret Service 자체는 실행되고 있었습니다. .deb 패키지는 `libsecret-tools`를 `Depends`나
`Recommends`에 넣고, RPM(Fedora 등)과 Arch 패키지는 `libsecret`을 넣어 주세요.

의존성을 지정할 수 없는 AppImage나 tar.gz 배포본에는 `secret-tool` 설치 방법을 안내해 주세요.
이 명령이 없으면 0600 파일에 대신 저장하고 경고 로그를 남깁니다.

## 판매자 서버

```go
// 웹훅은 받은 본문을 그대로 넣어 검증합니다. 파싱했다가 다시 만든 바이트로는 서명이 맞지 않습니다.
// 시크릿을 교체하는 중이면 두 시크릿을 모두 넘기세요
event, err := bydev.VerifyWebhook([]string{secret}, r.Header, rawBody, nil)

// 앱이 보낸 access_token이나 licenseToken을 검증합니다. JWKS는 받아서 캐시해 둡니다
verifier := bydev.NewServerVerifier("https://api.developedby.dev", clientID, nil, nil)
claims, err := verifier.VerifyAccessToken(ctx, token)
```

## 사용 조건

- **업데이트**: `CheckForUpdate(ctx, target, currentVersion)`가 반환한 `Update.Status`가 `REQUIRED`이면, 업데이트하기 전까지 앱 실행을 막아 주세요. 받은
  파일은 설치하기 전에 `VerifyDownload(data, install.SHA256)`로 확인해 주세요.
  업데이트 제공 기한이 있는 구매자는 결과에 `Entitled`가 들어 있습니다. 그때는 최상위 대신 `Entitled.Release`를 따라 주세요.
  최상위 최신 버전은 그 구매자가 실행할 수 없는 버전일 수 있고, `Entitled.Release`가 비어 있으면 그 대상에 제공 범위 안의 버전이 없습니다.
- **오류**: `bydev.AsError(err)`로 꺼낸 뒤 `Code`로 분기해 주세요. 코드 값은 생성된 `Code…` 상수에 있습니다. `Message`는 화면에 보여 주는 용도로만 사용해 주세요.
  `Transient()`가 참이면 다시 시도해 볼 만한 오류입니다.
- **모르는 값**: `EntitlementStatus` 같은 열거형은 문자열 타입입니다. 그래서 이 버전의 SDK가 모르는 새 값도 그대로 담깁니다. `switch`에는 `default`를 넣어
  두어 주세요.
- 라이선스: MIT 또는 Apache-2.0.

## 출처 확인

이 꾸러미는 공개 저장소 `developedby-dev/sdk-go`의 GitHub Actions가 판 태그에서 짓고 올립니다. 판 태그마다 올린 소스 묶음에는 GitHub 출처 증명이 있습니다. 받은 파일을 `gh attestation verify <파일> --repo developedby-dev/sdk-go`로 확인할 수 있습니다.

## 개발

| 명령 | 하는 일 |
|---|---|
| `go test ./...` | 단위 시험입니다. 실제 전송은 적합성 시험용 가짜 서버(HTTP 모드)를 node로 띄워 확인합니다. 쓸 node는 `BYDEV_NODE`로 바꿀 수 있습니다. |
| `pnpm sdk:check go` | gofmt, vet(지금 운영체제와 Windows, Linux 대상), 단위 시험, 적합성 시나리오 48개를 확인합니다. |
| `go run ./cmd/conformance-harness` | 적합성 하네스입니다(적합성 실행기가 띄웁니다) |

`generated.go`는 생성된 파일이며 `pnpm --filter @bydev/sdk-codegen generate`로 다시 만듭니다.
