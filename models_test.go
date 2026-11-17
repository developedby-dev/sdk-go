package bydev

import (
	"encoding/json"
	"testing"
)

func decode(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func entitlementWith(coverage string) string {
	field := ""
	if coverage != "" {
		field = `"updateCoverage": ` + coverage + `,`
	}
	return `{"entitlement": {"id": "ent_1", "productId": "prod_1", "status": "ACTIVE",
		"term": {"type": "PERPETUAL", "expiresAt": null, "remainingDays": null, "remainingSeconds": null}, ` + field + `
		"subscription": null, "policy": {"maxDevices": 3, "maxConcurrent": 1, "heartbeatSec": 150, "offlineGraceHours": 0},
		"evaluatedAt": "2026-10-06T14:00:00Z"}}`
}

func wantProtocolError(t *testing.T, name string, err error) {
	t.Helper()
	if e, ok := AsError(err); !ok || e.Code != CodeProtocolError {
		t.Errorf("%s: err = %v, want PROTOCOL_ERROR", name, err)
	}
}

// ADR-0049 — updateCoverage는 필수, UNTIL이면 until도 필수, 모르는 type은 문자열 그대로(명세 0절 5).
func TestReadUpdateCoverage(t *testing.T) {
	_, err := readEntitlementResponse(decode(t, entitlementWith("")))
	wantProtocolError(t, "updateCoverage 없음", err)
	_, err = readEntitlementResponse(decode(t, entitlementWith(`{"type": "UNTIL"}`)))
	wantProtocolError(t, "UNTIL인데 until 없음", err)

	e, err := readEntitlementResponse(decode(t, entitlementWith(`{"type": "UNTIL", "until": "2027-11-12T03:00:00Z"}`)))
	if err != nil || e.UpdateCoverage != (UpdateCoverage{Type: UpdateCoverageTypeUntil, Until: "2027-11-12T03:00:00Z"}) {
		t.Errorf("UNTIL: %+v %v", e, err)
	}
	e, err = readEntitlementResponse(decode(t, entitlementWith(`{"type": "BY_RELEASE_LINE", "until": "x", "line": "2.x"}`)))
	if err != nil || e.UpdateCoverage != (UpdateCoverage{Type: "BY_RELEASE_LINE"}) {
		t.Errorf("모르는 type: %+v %v", e, err)
	}
	b, _ := json.Marshal(UpdateCoverage{Type: UpdateCoverageTypeAll})
	if string(b) != `{"type":"ALL"}` {
		t.Errorf("ALL 직렬화 = %s", b)
	}
}

// 명세 7절 — entitled는 있을 때만, release 안은 최상위와 같은 읽기 규칙.
func TestReadUpdateCheckEntitled(t *testing.T) {
	top := `"product": {"id": "prod_1"}, "target": "WINDOWS_X64",
		"latest": {"version": "2.0.0", "releasedAt": "2027-12-01T06:00:00Z", "notes": null},
		"update": {"status": "AVAILABLE"}, "install": {"mode": "STORE_LINK", "url": "x"}`
	check, err := readUpdateCheck(decode(t, `{`+top+`}`))
	if err != nil || check.Entitled != nil || check.Install.Mode != "STORE_LINK" {
		t.Fatalf("entitled 없음: %+v %v", check, err)
	}
	check, err = readUpdateCheck(decode(t, `{`+top+`, "entitled": {"coveredUntil": "2027-11-12T03:00:00Z", "release": {
		"latest": {"version": "1.4.2", "releasedAt": "2027-10-02T06:00:00Z", "notes": "보안 수정"},
		"update": {"status": "UP_TO_DATE"}, "install": {"mode": "EXTERNAL", "channels": [{"channel": "MICROSOFT_STORE", "locator": "9N"}]}}}}`))
	if err != nil || check.Entitled == nil || check.Entitled.Release == nil {
		t.Fatalf("entitled: %+v %v", check, err)
	}
	if r := check.Entitled.Release; r.Latest.Version != "1.4.2" || r.Update.Status != UpdateStatusUpToDate || len(r.Install.Channels) != 1 {
		t.Errorf("entitled.release: %+v", r)
	}
	_, err = readUpdateCheck(decode(t, `{`+top+`, "entitled": {"coveredUntil": "2027-11-12T03:00:00Z", "release": {
		"latest": {"version": "1.4.2", "releasedAt": "2027-10-02T06:00:00Z", "notes": null},
		"update": {"status": "UP_TO_DATE"}, "install": {"mode": "HOSTED"}}}}`))
	wantProtocolError(t, "entitled.release.install 필드 없음", err)
	_, err = readUpdateCheck(decode(t, `{`+top+`, "entitled": {"release": null}}`))
	wantProtocolError(t, "coveredUntil 없음", err)
}

// licenseToken build_id — 없거나 null이면 nil, 문자열이 아니면 모양 오류.
func TestReadLicenseClaimsBuildID(t *testing.T) {
	base := `"iss": "i", "sub": "s", "aud": "a", "product_id": "p", "device_id": "d", "sid": "x", "generation": 1, "iat": 1, "exp": 2`
	c, err := readLicenseClaims(decode(t, `{`+base+`}`))
	if err != nil || c.BuildID != nil {
		t.Errorf("없음: %+v %v", c, err)
	}
	c, err = readLicenseClaims(decode(t, `{`+base+`, "build_id": "build_1"}`))
	if err != nil || c.BuildID == nil || *c.BuildID != "build_1" {
		t.Errorf("있음: %+v %v", c, err)
	}
	_, err = readLicenseClaims(decode(t, `{`+base+`, "build_id": 7}`))
	wantProtocolError(t, "build_id 숫자", err)
}
