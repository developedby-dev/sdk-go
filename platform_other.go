//go:build !windows

package bydev

import "os/exec"

// hideConsole은 Windows에만 할 일이 있다(콘솔 창 없이 띄우기).
func hideConsole(*exec.Cmd) {}

// registryMachineGUID는 Windows에만 있다 — 다른 운영체제는 명령 · 파일로 읽는다(readMachineID).
var registryMachineGUID func() (string, error)
