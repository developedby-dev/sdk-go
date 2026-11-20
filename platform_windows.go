//go:build windows

package bydev

import (
	"errors"
	"syscall"
	"unsafe"
)

// registryMachineGUID는 HKLM\SOFTWARE\Microsoft\Cryptography의 MachineGuid를 레지스트리 API로 읽는다 — reg 명령을 띄우지 않는다(명세 10절).
// 32비트 프로세스도 64비트 보기를 읽는다(KEY_WOW64_64KEY) — 같은 PC에서 같은 값이 나오게.
var registryMachineGUID = func() (string, error) {
	const keyWow6464Key = 0x0100
	path, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ|keyWow6464Key, &key); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)
	name, err := syscall.UTF16PtrFromString("MachineGuid")
	if err != nil {
		return "", err
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, nil, &size); err != nil {
		return "", err
	}
	if typ != syscall.REG_SZ || size < 2 {
		return "", errors.New("MachineGuid가 문자열이 아니다")
	}
	buf := make([]uint16, size/2+1)
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}
