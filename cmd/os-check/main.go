// os-check는 운영체제 포트의 실제 확인이다 — Windows · Linux 기기에서 돌린다(launch-checklist A31 · ADR-0040 ⚠ 20). 사용자 보안 저장소를
// 건드리므로 BYDEV_KEYCHAIN_CHECK=1일 때만 — `BYDEV_KEYCHAIN_CHECK=1 go run ./cmd/os-check`.
//
// 기본 저장소(DefaultCredentialStore — Windows DPAPI 파일 · Linux Secret Service)에 항목 하나(계정 bydev-keychain-check)를 넣고 · 고치고 · 읽고 ·
// 지운다. 보안 저장소 대신 0600 파일로 떨어지면(경고 로그) 실패다. 지문 출처(OSFingerprintSource — MachineGuid · machine-id)가 설치 ID 파일 없이
// 운영체제 값을 읽고 두 번 읽어도 같은지 본다.
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	bydev "developedby.dev/sdk/go"
)

const (
	appName = "bydev-os-check"
	account = "bydev-keychain-check"
)

type warnings struct{ seen []string }

func (w *warnings) Debug(string, ...any)      {}
func (w *warnings) Info(string, ...any)       {}
func (w *warnings) Warn(msg string, _ ...any) { w.seen = append(w.seen, msg) }

func main() { os.Exit(run()) }

func run() int {
	if os.Getenv("BYDEV_KEYCHAIN_CHECK") != "1" {
		fmt.Println("BYDEV_KEYCHAIN_CHECK=1이 아니라 건너뛴다 — 사용자 보안 저장소를 건드린다")
		return 0
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		fmt.Printf("%s는 대상이 아니다 — Windows · Linux에서 돌린다\n", runtime.GOOS)
		return 0
	}
	ctx := context.Background()
	var failures []string
	device := bydev.SystemDeviceInfo()
	fmt.Printf("기기 %s · %s\n", device.Name, device.Platform)

	fingerprint := bydev.OSFingerprintSource("")
	first, err1 := fingerprint.Read(ctx)
	again, err2 := fingerprint.Read(ctx)
	switch {
	case err1 != nil || err2 != nil:
		failures = append(failures, fmt.Sprintf("지문 — 읽지 못했다: %v %v", err1, err2))
	case first == "":
		failures = append(failures, "지문 — 운영체제 값을 읽지 못했다(설치 ID 없이)")
	case first != again:
		failures = append(failures, "지문 — 두 번 읽은 값이 다르다")
	default:
		fmt.Printf("✓ 지문 출처 — 운영체제 값(길이 %d)을 읽었고 두 번 같다\n", len(first))
	}

	logger := &warnings{}
	store := bydev.DefaultCredentialStore(appName, account, logger)
	defer func() {
		_ = store.Clear(ctx)
		_ = os.RemoveAll(bydev.AppDataDir(appName))
	}()
	record := bydev.CredentialRecord{Version: 1, RefreshToken: "rt_node_test_00000000001", Scope: "entitlement.read", SavedAt: "2026-10-06T13:00:00Z"}
	rotated := record
	rotated.RefreshToken = "rt_keychain_rotated_000001"
	check := func() error {
		if err := store.Clear(ctx); err != nil {
			return err
		}
		if got, err := store.Load(ctx); err != nil || got != nil {
			return fmt.Errorf("지운 뒤 읽기: %v %v", got, err)
		}
		for _, want := range []bydev.CredentialRecord{record, rotated} {
			if err := store.Save(ctx, want); err != nil {
				return err
			}
			if got, err := store.Load(ctx); err != nil || got == nil || *got != want {
				return fmt.Errorf("넣은 것을 읽지 못했다: %v", err)
			}
		}
		if err := store.Clear(ctx); err != nil {
			return err
		}
		if got, err := store.Load(ctx); err != nil || got != nil {
			return fmt.Errorf("지운 항목이 남았다: %v", err)
		}
		return nil
	}
	if err := check(); err != nil {
		failures = append(failures, "저장소 — "+err.Error())
	} else if len(logger.seen) > 0 {
		failures = append(failures, fmt.Sprintf("저장소 — 보안 저장소가 아니라 파일로 떨어졌다: %v", logger.seen))
	} else {
		kind := "Secret Service"
		if runtime.GOOS == "windows" {
			kind = "DPAPI 파일"
		}
		fmt.Printf("✓ 기본 저장소(%s) — 넣기 · 고치기 · 읽기 · 지우기\n", kind)
	}
	for _, f := range failures {
		fmt.Println("✗ " + f)
	}
	if len(failures) > 0 {
		return 1
	}
	return 0
}
