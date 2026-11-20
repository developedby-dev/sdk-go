//go:build windows

package bydev

import (
	"context"
	"strings"
	"testing"
)

// 실제 Windows — 레지스트리 API가 reg 명령과 같은 MachineGuid를 읽는다(같은 PC가 같은 기기로 보이게).
func TestRegistryMachineGUIDMatchesRegCommand(t *testing.T) {
	api, err := registryMachineGUID()
	if err != nil || strings.TrimSpace(api) == "" {
		t.Fatalf("레지스트리 API: %q, %v", api, err)
	}
	cmd := readMachineID(context.Background(), osDeps{goos: "windows", exec: systemDeps.exec})
	if cmd != api {
		t.Fatalf("API %q ≠ reg 명령 %q", api, cmd)
	}
}
