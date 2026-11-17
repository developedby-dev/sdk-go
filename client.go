package bydev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// Config는 명세 1절의 설정이다.
type Config struct {
	BaseURL   string
	ClientID  string
	ProductID string
	Scopes    []string
	// Device는 세션을 쓰면 필요하다.
	Device *DeviceInfo
	// App은 실행 중인 앱의 배포 대상 · 버전이다 — 세션을 쓰면 넣는다(명세 1절 · ADR-0049).
	App   *AppInfo
	Ports Ports
}

// Client는 bydev 라이선스 API 클라이언트다. 서버 응답 하나의 참/거짓으로 기능을 열지 않는다 — Session().State()와 검증된 토큰의 클레임을 쓴다.
type Client struct {
	config   Config
	ports    Ports
	api      *api
	tokens   *tokenManager
	verifier *verifier

	mu      sync.Mutex
	login   *LoginAttempt
	session *Session
}

// New는 클라이언트를 만든다.
func New(config Config) (*Client, error) {
	if len(config.Scopes) == 0 {
		return nil, sdkError(CodeConfiguration, "scopes가 비었다", nil)
	}
	ports := config.Ports.withDefaults()
	a := newAPI(config.BaseURL, ports)
	return &Client{
		config:   config,
		ports:    ports,
		api:      a,
		tokens:   &tokenManager{api: a, ports: ports, clientID: config.ClientID},
		verifier: newVerifier(a, ports, config.ClientID, true),
	}, nil
}

// StartLogin은 디바이스 로그인을 시작한다(명세 5절). 진행 중인 로그인은 취소한다.
func (c *Client) StartLogin(ctx context.Context) (*LoginAttempt, error) {
	c.mu.Lock()
	if c.login != nil {
		c.login.Cancel()
		c.login = nil
	}
	c.mu.Unlock()
	doc, err := c.api.discovery(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.api.send(ctx, requestOptions{Method: "POST", URL: doc.DeviceAuthorizationEndpoint, Body: map[string]string{
		"client_id": c.config.ClientID, "scope": strings.Join(c.config.Scopes, " "),
	}})
	if err != nil {
		return nil, err
	}
	code, err := readDeviceCode(res.JSON)
	if err != nil {
		return nil, err
	}
	attempt := newLoginAttempt(code, c)
	c.mu.Lock()
	c.login = attempt
	c.mu.Unlock()
	return attempt, nil
}

// HasCredentials는 저장된 로그인이 있는지다 — 이용 가능 여부가 아니다.
func (c *Client) HasCredentials(ctx context.Context) (bool, error) {
	record, err := c.tokens.load(ctx)
	return record != nil, err
}

func (c *Client) get(ctx context.Context, path string, params map[string]string, query url.Values) (any, error) {
	u := c.api.url(path, params, query)
	res, err := c.tokens.authed(ctx, func(bearer string) (*apiResponse, error) {
		return c.api.send(ctx, requestOptions{Method: "GET", URL: u, Bearer: bearer})
	})
	if err != nil {
		return nil, err
	}
	c.noteLease(res)
	return res.JSON, nil
}

func (c *Client) noteLease(res *apiResponse) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session != nil {
		session.noteLease(res.Header["x-lease-expires-at"])
	}
}

// Entitlement는 이 제품의 이용권이다.
func (c *Client) Entitlement(ctx context.Context) (*Entitlement, error) {
	raw, err := c.get(ctx, RouteGetMyEntitlement.Path, nil, nil)
	if err != nil {
		return nil, err
	}
	return readEntitlementResponse(raw)
}

// Devices는 등록된 기기 한 쪽이다. 다음 쪽을 저절로 따라가지 않는다.
func (c *Client) Devices(ctx context.Context, cursor string, limit int) (*DevicePage, error) {
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	raw, err := c.get(ctx, RouteListDevices.Path, nil, q)
	if err != nil {
		return nil, err
	}
	return readDevicePage(raw)
}

// ReleaseDevice는 기기를 해제한다(월 횟수 제한).
func (c *Client) ReleaseDevice(ctx context.Context, deviceID string) (*DeviceRelease, error) {
	key := c.ports.Random.UUID()
	res, err := c.tokens.authed(ctx, func(bearer string) (*apiResponse, error) {
		return c.api.send(ctx, requestOptions{Method: "DELETE", URL: c.api.url(RouteReleaseDevice.Path, map[string]string{"deviceId": deviceID}, nil), Bearer: bearer, IdempotencyKey: key})
	})
	if err != nil {
		return nil, err
	}
	c.noteLease(res)
	return readDeviceRelease(res.JSON)
}

// Profile은 닉네임과 가명 식별자다.
func (c *Client) Profile(ctx context.Context) (*Profile, error) {
	raw, err := c.get(ctx, RouteGetProfile.Path, nil, nil)
	if err != nil {
		return nil, err
	}
	return readProfileResponse(raw)
}

// CheckForUpdate는 업데이트 확인이다. Update.Status가 REQUIRED면 업데이트 전까지 실행을 막는다. 받은 파일은 설치 전에 VerifyDownload.
// Entitled가 있으면 Latest · Update · Install 대신 Entitled.Release를 따른다 — 범위 밖 버전을 설치하면 세션 획득이 거절된다.
func (c *Client) CheckForUpdate(ctx context.Context, target, currentVersion string) (*UpdateCheck, error) {
	q := url.Values{}
	q.Set("target", target)
	q.Set("currentVersion", currentVersion)
	raw, err := c.get(ctx, RouteGetProductUpdates.Path, map[string]string{"id": c.config.ProductID}, q)
	if err != nil {
		return nil, err
	}
	return readUpdateCheck(raw)
}

// VerifyDownload는 내려받은 파일의 SHA-256을 확인한다 — 다르면 DOWNLOAD_INTEGRITY.
func (c *Client) VerifyDownload(data []byte, sha string) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(sha) {
		return sdkError(CodeDownloadIntegrity, "내려받은 파일의 SHA-256이 다르다 — 설치하지 않는다", nil)
	}
	return nil
}

// VerifyToken은 licenseToken을 검증한다(명세 9절) — 앱이 기능 코드 여러 곳에서 다시 검증할 때.
func (c *Client) VerifyToken(ctx context.Context, token string) (*LicenseClaims, error) {
	return c.verifier.verifyLicense(ctx, token, nil, 0)
}

// Logout은 세션을 멈추고 폐기 요청을 한 번 보낸 뒤 기록을 지운다. 서버 폐기에 성공했는지를 돌려준다.
func (c *Client) Logout(ctx context.Context) (bool, error) {
	c.mu.Lock()
	if c.login != nil {
		c.login.Cancel()
		c.login = nil
	}
	session := c.session
	c.mu.Unlock()
	if session != nil {
		session.Stop(ctx)
	}
	return c.tokens.logout(ctx)
}

// Session은 이 클라이언트의 세션이다(하나뿐).
func (c *Client) Session() (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		if c.config.Device == nil {
			return nil, sdkError(CodeConfiguration, "세션을 쓰려면 Device { Name, Platform }을 준다", nil)
		}
		c.session = newSession(c, *c.config.Device, c.config.App)
	}
	return c.session, nil
}
