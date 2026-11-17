package bydev

import "encoding/json"

// 공개 API 응답의 SDK 모델 — 필드 이름은 contracts 그대로(JSON 태그), 없을 수 있는 값은 포인터.

// EntitlementTerm은 기간이다. Type을 먼저 분기한다 — 영구(PERPETUAL)는 잔여 필드가 nil이다.
type EntitlementTerm struct {
	Type             string  `json:"type"`
	ExpiresAt        *string `json:"expiresAt"`
	RemainingDays    *int    `json:"remainingDays"`
	RemainingSeconds *int    `json:"remainingSeconds"`
}

// EntitlementSubscription은 구독형일 때만 있다.
type EntitlementSubscription struct {
	ID            string             `json:"id"`
	Status        SubscriptionStatus `json:"status"`
	WillRenew     bool               `json:"willRenew"`
	NextBillingAt *string            `json:"nextBillingAt"`
	GraceEndsAt   *string            `json:"graceEndsAt"`
}

// LicensePolicy는 판매자가 정한 정책 수치다 — 앱에 하드코딩하지 않는다.
type LicensePolicy struct {
	MaxDevices        int `json:"maxDevices"`
	MaxConcurrent     int `json:"maxConcurrent"`
	HeartbeatSec      int `json:"heartbeatSec"`
	OfflineGraceHours int `json:"offlineGraceHours"`
}

// UpdateCoverage는 업데이트 제공 범위다(ADR-0049). Type을 먼저 분기한다 — UNTIL이면 Until 전에 출시된 버전을 실행할 수 있다.
// 모르는 Type이면 Type만 있다(명세 0절 5).
type UpdateCoverage struct {
	Type  UpdateCoverageType `json:"type"`
	Until string             `json:"until,omitempty"`
}

// Entitlement는 이 제품의 이용권이다.
type Entitlement struct {
	ID             string                   `json:"id"`
	ProductID      string                   `json:"productId"`
	Status         EntitlementStatus        `json:"status"`
	Term           EntitlementTerm          `json:"term"`
	UpdateCoverage UpdateCoverage           `json:"updateCoverage"`
	Subscription   *EntitlementSubscription `json:"subscription"`
	Policy         LicensePolicy            `json:"policy"`
	EvaluatedAt    string                   `json:"evaluatedAt"`
}

func readEntitlementResponse(json any) (*Entitlement, error) {
	r := &reader{}
	e := r.object(r.object(json, "$")["entitlement"], "entitlement")
	t := r.object(e["term"], "entitlement.term")
	term := EntitlementTerm{Type: r.str(t["type"], "entitlement.term.type")}
	if term.Type != "PERPETUAL" {
		term.ExpiresAt = r.optStr(t["expiresAt"], "entitlement.term.expiresAt")
		term.RemainingDays = r.optInt(t["remainingDays"], "entitlement.term.remainingDays")
		term.RemainingSeconds = r.optInt(t["remainingSeconds"], "entitlement.term.remainingSeconds")
	}
	c := r.object(e["updateCoverage"], "entitlement.updateCoverage")
	coverage := UpdateCoverage{Type: UpdateCoverageType(r.str(c["type"], "entitlement.updateCoverage.type"))}
	if coverage.Type == UpdateCoverageTypeUntil {
		coverage.Until = r.str(c["until"], "entitlement.updateCoverage.until")
	}
	p := r.object(e["policy"], "entitlement.policy")
	out := &Entitlement{
		ID:             r.str(e["id"], "entitlement.id"),
		ProductID:      r.str(e["productId"], "entitlement.productId"),
		Status:         EntitlementStatus(r.str(e["status"], "entitlement.status")),
		Term:           term,
		UpdateCoverage: coverage,
		Policy: LicensePolicy{
			MaxDevices:        r.integer(p["maxDevices"], "entitlement.policy.maxDevices"),
			MaxConcurrent:     r.integer(p["maxConcurrent"], "entitlement.policy.maxConcurrent"),
			HeartbeatSec:      r.integer(p["heartbeatSec"], "entitlement.policy.heartbeatSec"),
			OfflineGraceHours: r.integer(p["offlineGraceHours"], "entitlement.policy.offlineGraceHours"),
		},
		EvaluatedAt: r.str(e["evaluatedAt"], "entitlement.evaluatedAt"),
	}
	if sub := e["subscription"]; sub != nil {
		s := r.object(sub, "entitlement.subscription")
		out.Subscription = &EntitlementSubscription{
			ID:            r.str(s["id"], "entitlement.subscription.id"),
			Status:        SubscriptionStatus(r.str(s["status"], "entitlement.subscription.status")),
			WillRenew:     r.boolean(s["willRenew"], "entitlement.subscription.willRenew"),
			NextBillingAt: r.optStr(s["nextBillingAt"], "entitlement.subscription.nextBillingAt"),
			GraceEndsAt:   r.optStr(s["graceEndsAt"], "entitlement.subscription.graceEndsAt"),
		}
	}
	return out, r.err
}

// Device는 등록된 기기다.
type Device struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Platform     DevicePlatform `json:"platform"`
	RegisteredAt string         `json:"registeredAt"`
	LastSeenAt   string         `json:"lastSeenAt"`
}

// DevicePage는 기기 목록 한 쪽이다. NextCursor가 nil이면 마지막 쪽이다.
type DevicePage struct {
	Items      []Device `json:"items"`
	NextCursor *string  `json:"nextCursor"`
}

func readDevicePage(json any) (*DevicePage, error) {
	r := &reader{}
	page := r.object(json, "$")
	out := &DevicePage{Items: []Device{}}
	for i, v := range r.array(page["items"], "items") {
		d := r.object(v, "items[]")
		out.Items = append(out.Items, Device{
			ID:           r.str(d["id"], "items[].id"),
			Name:         r.str(d["name"], "items[].name"),
			Platform:     DevicePlatform(r.str(d["platform"], "items[].platform")),
			RegisteredAt: r.str(d["registeredAt"], "items[].registeredAt"),
			LastSeenAt:   r.str(d["lastSeenAt"], "items[].lastSeenAt"),
		})
		_ = i
	}
	out.NextCursor = r.optStr(page["nextCursor"], "nextCursor")
	return out, r.err
}

// DeviceRelease는 기기 해제 결과다.
type DeviceRelease struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	ReleasedAt string `json:"releasedAt"`
}

func readDeviceRelease(json any) (*DeviceRelease, error) {
	r := &reader{}
	d := r.object(r.object(json, "$")["device"], "device")
	return &DeviceRelease{
		ID:         r.str(d["id"], "device.id"),
		Status:     r.str(d["status"], "device.status"),
		ReleasedAt: r.str(d["releasedAt"], "device.releasedAt"),
	}, r.err
}

// Profile은 닉네임과 가명 식별자다. PseudonymousID를 판매자 쪽 고객 키로 쓴다.
type Profile struct {
	PseudonymousID string  `json:"pseudonymousId"`
	Nickname       string  `json:"nickname"`
	Email          *string `json:"email"`
}

func readProfileResponse(json any) (*Profile, error) {
	r := &reader{}
	p := r.object(r.object(json, "$")["profile"], "profile")
	return &Profile{
		PseudonymousID: r.str(p["pseudonymousId"], "profile.pseudonymousId"),
		Nickname:       r.str(p["nickname"], "profile.nickname"),
		Email:          r.optStr(p["email"], "profile.email"),
	}, r.err
}

// ExternalChannel은 외부 채널의 설치 위치다.
type ExternalChannel struct {
	Channel string `json:"channel"`
	Locator string `json:"locator"`
}

// ProductInstall은 설치 방법이다. Mode가 HOSTED면 내려받기 필드, EXTERNAL이면 Channels가 있다. 모르는 방식이면 Mode만 있다.
type ProductInstall struct {
	Mode                 InstallMode       `json:"mode"`
	BuildID              string            `json:"buildId,omitempty"`
	DownloadURL          string            `json:"downloadUrl,omitempty"`
	DownloadURLExpiresAt string            `json:"downloadUrlExpiresAt,omitempty"`
	SHA256               string            `json:"sha256,omitempty"`
	SizeBytes            int               `json:"sizeBytes,omitempty"`
	Channels             []ExternalChannel `json:"channels,omitempty"`
}

// LatestVersion은 최신 버전이다.
type LatestVersion struct {
	Version    string  `json:"version"`
	ReleasedAt string  `json:"releasedAt"`
	Notes      *string `json:"notes"`
}

// UpdateDecision은 업데이트 판정이다. Status가 REQUIRED면 업데이트 전까지 실행을 막는다.
type UpdateDecision struct {
	Status UpdateStatus `json:"status"`
}

// UpdateRelease는 최신 버전 · 업데이트 판정 · 설치 방법이다 — UpdateCheck의 최상위와 EntitledUpdate.Release가 같은 모양이다.
type UpdateRelease struct {
	Latest  LatestVersion  `json:"latest"`
	Update  UpdateDecision `json:"update"`
	Install ProductInstall `json:"install"`
}

// EntitledUpdate는 업데이트 제공 기한이 있는 구매자에게만 오는 값이다(ADR-0049 4절). 있으면 앱은 최상위 대신 Release를 따른다 — 최상위
// 최신은 그 구매자가 실행할 수 없는 버전일 수 있다. 이 대상에 범위 안 버전이 없으면 Release는 nil이다.
type EntitledUpdate struct {
	CoveredUntil string         `json:"coveredUntil"`
	Release      *UpdateRelease `json:"release"`
}

// UpdateCheck는 업데이트 확인 결과다. Update.Status가 REQUIRED면 업데이트 전까지 실행을 막는다. Entitled가 있으면 Latest · Update ·
// Install 대신 Entitled.Release를 따른다.
type UpdateCheck struct {
	Product struct {
		ID string `json:"id"`
	} `json:"product"`
	Target  DistributionTarget `json:"target"`
	Latest  LatestVersion      `json:"latest"`
	Update  UpdateDecision     `json:"update"`
	Install ProductInstall     `json:"install"`
	// Entitled는 업데이트 제공 기한이 있는 구매자에게만 있다. 없으면 nil.
	Entitled *EntitledUpdate `json:"entitled,omitempty"`
}

func readInstall(r *reader, v any, path string) ProductInstall {
	install := r.object(v, path)
	out := ProductInstall{Mode: InstallMode(r.str(install["mode"], path+".mode"))}
	switch out.Mode {
	case InstallModeHosted:
		out.BuildID = r.str(install["buildId"], path+".buildId")
		out.DownloadURL = r.str(install["downloadUrl"], path+".downloadUrl")
		out.DownloadURLExpiresAt = r.str(install["downloadUrlExpiresAt"], path+".downloadUrlExpiresAt")
		out.SHA256 = r.str(install["sha256"], path+".sha256")
		out.SizeBytes = r.integer(install["sizeBytes"], path+".sizeBytes")
	case InstallModeExternal:
		out.Channels = []ExternalChannel{}
		for _, item := range r.array(install["channels"], path+".channels") {
			c := r.object(item, path+".channels[]")
			out.Channels = append(out.Channels, ExternalChannel{
				Channel: r.str(c["channel"], path+".channels[].channel"),
				Locator: r.str(c["locator"], path+".channels[].locator"),
			})
		}
	}
	return out
}

// readRelease는 latest · update · install을 읽는다. prefix는 경로 앞부분이다("" 또는 "entitled.release.").
func readRelease(r *reader, o map[string]any, prefix string) UpdateRelease {
	latest := r.object(o["latest"], prefix+"latest")
	return UpdateRelease{
		Latest: LatestVersion{
			Version:    r.str(latest["version"], prefix+"latest.version"),
			ReleasedAt: r.str(latest["releasedAt"], prefix+"latest.releasedAt"),
			Notes:      r.optStr(latest["notes"], prefix+"latest.notes"),
		},
		Update:  UpdateDecision{Status: UpdateStatus(r.str(r.object(o["update"], prefix+"update")["status"], prefix+"update.status"))},
		Install: readInstall(r, o["install"], prefix+"install"),
	}
}

func readUpdateCheck(json any) (*UpdateCheck, error) {
	r := &reader{}
	o := r.object(json, "$")
	out := &UpdateCheck{}
	out.Product.ID = r.str(r.object(o["product"], "product")["id"], "product.id")
	out.Target = DistributionTarget(r.str(o["target"], "target"))
	release := readRelease(r, o, "")
	out.Latest, out.Update, out.Install = release.Latest, release.Update, release.Install
	if v := o["entitled"]; v != nil {
		e := r.object(v, "entitled")
		out.Entitled = &EntitledUpdate{CoveredUntil: r.str(e["coveredUntil"], "entitled.coveredUntil")}
		if rel := e["release"]; rel != nil {
			entitledRelease := readRelease(r, r.object(rel, "entitled.release"), "entitled.release.")
			out.Entitled.Release = &entitledRelease
		}
	}
	return out, r.err
}

type tokenSet struct {
	AccessToken  string
	ExpiresIn    int
	RefreshToken string
	Scope        string
}

func readTokenResponse(json any) (*tokenSet, error) {
	r := &reader{}
	t := r.object(json, "$")
	return &tokenSet{
		AccessToken:  r.str(t["access_token"], "access_token"),
		ExpiresIn:    r.integer(t["expires_in"], "expires_in"),
		RefreshToken: r.str(t["refresh_token"], "refresh_token"),
		Scope:        r.str(t["scope"], "scope"),
	}, r.err
}

type deviceCode struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
}

func readDeviceCode(json any) (*deviceCode, error) {
	r := &reader{}
	d := r.object(json, "$")
	return &deviceCode{
		DeviceCode:              r.str(d["device_code"], "device_code"),
		UserCode:                r.str(d["user_code"], "user_code"),
		VerificationURI:         r.str(d["verification_uri"], "verification_uri"),
		VerificationURIComplete: r.str(d["verification_uri_complete"], "verification_uri_complete"),
		ExpiresIn:               r.integer(d["expires_in"], "expires_in"),
		Interval:                r.integer(d["interval"], "interval"),
	}, r.err
}

// SessionInfo는 세션(실행 리스)이다.
type SessionInfo struct {
	ID             string `json:"id"`
	ProductID      string `json:"productId"`
	DeviceID       string `json:"deviceId"`
	Generation     int    `json:"generation"`
	LeaseExpiresAt string `json:"leaseExpiresAt"`
	HeartbeatSec   int    `json:"heartbeatSec"`
}

// LicenseTokenInfo는 세션 보유 증명 JWT와 그 만료(오프라인 유예의 끝)다.
type LicenseTokenInfo struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

func readSessionResponse(json any) (*SessionInfo, *LicenseTokenInfo, error) {
	r := &reader{}
	o := r.object(json, "$")
	s := r.object(o["session"], "session")
	t := r.object(o["licenseToken"], "licenseToken")
	return &SessionInfo{
		ID:             r.str(s["id"], "session.id"),
		ProductID:      r.str(s["productId"], "session.productId"),
		DeviceID:       r.str(s["deviceId"], "session.deviceId"),
		Generation:     r.integer(s["generation"], "session.generation"),
		LeaseExpiresAt: r.str(s["leaseExpiresAt"], "session.leaseExpiresAt"),
		HeartbeatSec:   r.integer(s["heartbeatSec"], "session.heartbeatSec"),
	}, &LicenseTokenInfo{
		Token:     r.str(t["token"], "licenseToken.token"),
		ExpiresAt: r.str(t["expiresAt"], "licenseToken.expiresAt"),
	}, r.err
}

type discovery struct {
	Issuer                      string
	JWKSURI                     string
	DeviceAuthorizationEndpoint string
	TokenEndpoint               string
	RevocationEndpoint          string
}

func readDiscovery(json any) (*discovery, error) {
	r := &reader{}
	d := r.object(json, "$")
	return &discovery{
		Issuer:                      r.str(d["issuer"], "issuer"),
		JWKSURI:                     r.str(d["jwks_uri"], "jwks_uri"),
		DeviceAuthorizationEndpoint: r.str(d["device_authorization_endpoint"], "device_authorization_endpoint"),
		TokenEndpoint:               r.str(d["token_endpoint"], "token_endpoint"),
		RevocationEndpoint:          r.str(d["revocation_endpoint"], "revocation_endpoint"),
	}, r.err
}

// LicenseClaims는 검증된 licenseToken 클레임이다(명세 9절).
type LicenseClaims struct {
	Iss        string `json:"iss"`
	Sub        string `json:"sub"`
	Aud        string `json:"aud"`
	ProductID  string `json:"product_id"`
	DeviceID   string `json:"device_id"`
	Sid        string `json:"sid"`
	Generation int    `json:"generation"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
	// BuildID는 세션을 얻을 때 앱이 보낸 대상 · 버전(Config.App)으로 서버가 확정한 빌드다(ADR-0049). 확정하지 못했으면 nil.
	BuildID *string `json:"build_id,omitempty"`
}

func readLicenseClaims(json any) (*LicenseClaims, error) {
	r := &reader{}
	c := r.object(json, "claims")
	return &LicenseClaims{
		Iss:        r.str(c["iss"], "claims.iss"),
		Sub:        r.str(c["sub"], "claims.sub"),
		Aud:        r.str(c["aud"], "claims.aud"),
		ProductID:  r.str(c["product_id"], "claims.product_id"),
		DeviceID:   r.str(c["device_id"], "claims.device_id"),
		Sid:        r.str(c["sid"], "claims.sid"),
		Generation: r.integer(c["generation"], "claims.generation"),
		Iat:        int64(r.integer(c["iat"], "claims.iat")),
		Exp:        int64(r.integer(c["exp"], "claims.exp")),
		BuildID:    r.optStr(c["build_id"], "claims.build_id"),
	}, r.err
}

// AccessClaims는 검증된 access_token 클레임이다(명세 12절).
type AccessClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Jti      string `json:"jti"`
}

func readAccessClaims(json any) (*AccessClaims, error) {
	r := &reader{}
	c := r.object(json, "claims")
	return &AccessClaims{
		Iss:      r.str(c["iss"], "claims.iss"),
		Sub:      r.str(c["sub"], "claims.sub"),
		Aud:      r.str(c["aud"], "claims.aud"),
		ClientID: r.str(c["client_id"], "claims.client_id"),
		Scope:    r.str(c["scope"], "claims.scope"),
		Iat:      int64(r.integer(c["iat"], "claims.iat")),
		Exp:      int64(r.integer(c["exp"], "claims.exp")),
		Jti:      r.str(c["jti"], "claims.jti"),
	}, r.err
}

// MarshalJSON은 방식마다 그 방식의 필드만 쓴다(계약의 판별 유니온 모양).
func (p ProductInstall) MarshalJSON() ([]byte, error) {
	switch p.Mode {
	case InstallModeHosted:
		return json.Marshal(map[string]any{
			"mode": p.Mode, "buildId": p.BuildID, "downloadUrl": p.DownloadURL,
			"downloadUrlExpiresAt": p.DownloadURLExpiresAt, "sha256": p.SHA256, "sizeBytes": p.SizeBytes,
		})
	case InstallModeExternal:
		channels := p.Channels
		if channels == nil {
			channels = []ExternalChannel{}
		}
		return json.Marshal(map[string]any{"mode": p.Mode, "channels": channels})
	default:
		return json.Marshal(map[string]any{"mode": p.Mode})
	}
}
