//go:build !windows

package bydev

// registryMachineGUID는 Windows에만 있다 — 다른 운영체제는 명령 · 파일로 읽는다(readMachineID).
var registryMachineGUID func() (string, error)
