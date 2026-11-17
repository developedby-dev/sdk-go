package bydev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// 명세 2절 표 — 운영체제별 기본 구현. 원본 지문 · 토큰을 명령 줄 인자로 넘기지 않는다 — 비밀은 표준 입력으로만(다른 프로세스의 ps에 보이지 않게).
// 클라이언트의 기본 저장소는 메모리다 — 앱이 이 중에서 고른다(DefaultCredentialStore).

// osDeps는 명령 실행 · 파일이다. 단위 시험이 바꿔 끼운다.
type osDeps struct {
	goos      string
	exec      func(ctx context.Context, name string, args []string, stdin string) (string, error)
	lookPath  func(name string) error
	readFile  func(path string) (string, bool, error)
	writeFile func(path, content string) error
	remove    func(path string) error
	newID     func() string
}

var systemDeps = osDeps{
	goos: runtime.GOOS,
	exec: func(ctx context.Context, name string, args []string, stdin string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return out.String(), &commandError{err: err, stderr: stderr.String()}
		}
		return out.String(), nil
	},
	lookPath: func(name string) error {
		_, err := exec.LookPath(name)
		return err
	},
	readFile: func(path string) (string, bool, error) {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return string(data), true, nil
	},
	// 사용자만 읽는 권한(0600) · 임시 파일 뒤 이름 바꾸기(반쯤 쓴 파일이 남지 않게)
	writeFile: func(path, content string) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
		if err != nil {
			return err
		}
		name := temp.Name()
		if err := temp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
			temp.Close()
			os.Remove(name)
			return err
		}
		if _, err := temp.WriteString(content); err != nil {
			temp.Close()
			os.Remove(name)
			return err
		}
		if err := temp.Close(); err != nil {
			os.Remove(name)
			return err
		}
		return os.Rename(name, path)
	},
	remove: func(path string) error {
		err := os.Remove(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	},
	newID: func() string { return CryptoRandom.UUID() },
}

// AppDataDir는 운영체제 · 앱 이름별 데이터 폴더다.
func AppDataDir(appName string) string { return appDataDir(appName, systemDeps) }

func appDataDir(appName string, deps osDeps) string {
	home, _ := os.UserHomeDir()
	switch deps.goos {
	case "windows":
		if dir := os.Getenv("APPDATA"); dir != "" {
			return filepath.Join(dir, appName)
		}
		return filepath.Join(home, "AppData", "Roaming", appName)
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", appName)
	default:
		if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
			return filepath.Join(dir, appName)
		}
		return filepath.Join(home, ".config", appName)
	}
}

// SystemDeviceInfo는 Config.Device의 기본값이다 — 호스트 이름(64자까지)과 운영체제.
func SystemDeviceInfo() DeviceInfo { return deviceInfo(systemDeps) }

func deviceInfo(deps osDeps) DeviceInfo {
	platform := DevicePlatformOther
	switch deps.goos {
	case "windows":
		platform = DevicePlatformWindows
	case "darwin":
		platform = DevicePlatformMacos
	case "linux":
		platform = DevicePlatformLinux
	}
	name, _ := os.Hostname()
	if r := []rune(name); len(r) > 64 {
		name = string(r[:64])
	}
	if name == "" {
		name = "PC"
	}
	return DeviceInfo{Name: name, Platform: string(platform)}
}

// OSFingerprintSource는 명세 10절 · 2절 표의 지문 출처다 — Windows MachineGuid · macOS IOPlatformUUID · Linux /etc/machine-id. 읽지 못하면
// installIDFile의 설치 ID(없으면 만든다). installIDFile이 ""면 ""를 돌려준다(SDK가 클라이언트 수명 동안의 난수 ID로 물러난다).
func OSFingerprintSource(installIDFile string) FingerprintSource {
	return fingerprintSource{installIDFile: installIDFile, deps: systemDeps}
}

type fingerprintSource struct {
	installIDFile string
	deps          osDeps
}

var (
	machineGUIDPattern    = regexp.MustCompile(`MachineGuid\s+REG_SZ\s+(\S+)`)
	platformUUIDPattern   = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	linuxMachineIDSources = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
)

func (f fingerprintSource) Read(ctx context.Context) (string, error) {
	if value := strings.TrimSpace(readMachineID(ctx, f.deps)); value != "" {
		return value, nil
	}
	if f.installIDFile == "" {
		return "", nil
	}
	existing, found, err := f.deps.readFile(f.installIDFile)
	if err != nil {
		return "", err
	}
	if id := strings.TrimSpace(existing); found && id != "" {
		return id, nil
	}
	created := f.deps.newID()
	if err := f.deps.writeFile(f.installIDFile, created); err != nil {
		return "", err
	}
	return created, nil
}

func readMachineID(ctx context.Context, deps osDeps) string {
	switch deps.goos {
	case "windows":
		out, err := deps.exec(ctx, "reg", []string{"query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"}, "")
		if m := machineGUIDPattern.FindStringSubmatch(out); err == nil && m != nil {
			return m[1]
		}
	case "darwin":
		out, err := deps.exec(ctx, "ioreg", []string{"-rd1", "-c", "IOPlatformExpertDevice"}, "")
		if m := platformUUIDPattern.FindStringSubmatch(out); err == nil && m != nil {
			return m[1]
		}
	default:
		for _, path := range linuxMachineIDSources {
			if value, found, err := deps.readFile(path); err == nil && found && strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func parseRecord(text string) (*CredentialRecord, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var record CredentialRecord
	if err := json.Unmarshal([]byte(text), &record); err != nil {
		return nil, err
	}
	if record.Version != RuleStorageRecordVersion || record.RefreshToken == "" {
		return nil, nil
	}
	return &record, nil
}

func storageFailed(what string, err error) error {
	if err == nil {
		return nil
	}
	return sdkError(CodeStorageFailed, "보안 저장소 "+what+" 실패", err)
}

// FileCredentialStore는 사용자 전용 권한(0600) 파일이다 — **암호화하지 않는다.** 같은 사용자로 도는 프로그램은 읽을 수 있다. 운영체제 보안 저장소를 쓸 수
// 없을 때만(명세 2절 — warn 로그).
func FileCredentialStore(path string, logger Logger) CredentialStore {
	return newFileStore(path, logger, systemDeps)
}

func newFileStore(path string, logger Logger, deps osDeps) CredentialStore {
	if logger != nil {
		logger.Warn("로그인 기록을 암호화하지 않은 사용자 전용 파일에 둔다 — 운영체제 보안 저장소를 쓸 수 없는 환경")
	}
	return fileStore{path: path, deps: deps}
}

type fileStore struct {
	path string
	deps osDeps
}

func (s fileStore) Load(context.Context) (*CredentialRecord, error) {
	text, _, err := s.deps.readFile(s.path)
	if err != nil {
		return nil, storageFailed("읽기", err)
	}
	record, err := parseRecord(text)
	return record, storageFailed("읽기", err)
}

func (s fileStore) Save(_ context.Context, record CredentialRecord) error {
	data, _ := json.Marshal(record)
	return storageFailed("쓰기", s.deps.writeFile(s.path, string(data)))
}

func (s fileStore) Clear(context.Context) error {
	return storageFailed("지우기", s.deps.remove(s.path))
}

// SecretToolCredentialStore는 Linux Secret Service(libsecret secret-tool)다 — 비밀은 표준 입력으로 넘긴다. account는 clientId.
func SecretToolCredentialStore(account string) CredentialStore {
	return secretToolStore{account: account, deps: systemDeps}
}

type secretToolStore struct {
	account string
	deps    osDeps
}

func (s secretToolStore) attributes() []string {
	return []string{"service", RuleStorageService, "account", s.account}
}

// commandError는 끝난 명령의 오류에 오류 출력을 싣는다 — secret-tool은 "항목 없음"과 오류를 같은 종료 코드(1)로 내고 오류 출력으로만 가른다.
type commandError struct {
	err    error
	stderr string
}

func (e *commandError) Error() string  { return e.err.Error() }
func (e *commandError) Unwrap() error  { return e.err }
func (e *commandError) Stderr() string { return e.stderr }

// secretToolFoundNothing은 secret-tool이 항목을 찾지 못했다는 뜻이다 — 오류 출력 없이 1로 끝난다. 오류(D-Bus 없음 · 잠긴 모음 · 없는 모음)도
// 1이지만 "secret-tool: …"를 쓴다(2026-10-17 Debian 12 libsecret 0.20에서 확인 — ADR-0040 Linux 실제 확인 기록).
func secretToolFoundNothing(err error) bool {
	var withStderr interface{ Stderr() string }
	if errors.As(err, &withStderr) && strings.TrimSpace(withStderr.Stderr()) != "" {
		return false
	}
	return exitCode(err) == 1
}

func exitCode(err error) int {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return -1
}

func (s secretToolStore) Load(ctx context.Context) (*CredentialRecord, error) {
	out, err := s.deps.exec(ctx, "secret-tool", append([]string{"lookup"}, s.attributes()...), "")
	if err != nil {
		if secretToolFoundNothing(err) {
			return nil, nil
		}
		return nil, storageFailed("읽기", err)
	}
	record, err := parseRecord(out)
	return record, storageFailed("읽기", err)
}

func (s secretToolStore) Save(ctx context.Context, record CredentialRecord) error {
	data, _ := json.Marshal(record)
	args := append([]string{"store", "--label=bydev " + s.account}, s.attributes()...)
	_, err := s.deps.exec(ctx, "secret-tool", args, string(data))
	return storageFailed("쓰기", err)
}

// Clear — 없는 항목을 지우는 것은 성공이다(로그아웃은 몇 번 해도 된다).
func (s secretToolStore) Clear(ctx context.Context) error {
	_, err := s.deps.exec(ctx, "secret-tool", append([]string{"clear"}, s.attributes()...), "")
	if err != nil && secretToolFoundNothing(err) {
		return nil
	}
	return storageFailed("지우기", err)
}

const (
	dpapiProtect   = "Add-Type -AssemblyName System.Security; $b=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))"
	dpapiUnprotect = "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))"
)

// DPAPICredentialStore는 Windows DPAPI(사용자 범위)로 암호화한 파일이다 — PowerShell에 표준 입력으로 넘긴다. 다른 Windows 사용자는 풀 수 없다.
func DPAPICredentialStore(path string) CredentialStore {
	return dpapiStore{path: path, deps: systemDeps}
}

type dpapiStore struct {
	path string
	deps osDeps
}

func (s dpapiStore) ps(ctx context.Context, script, input string) (string, error) {
	return s.deps.exec(ctx, "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", script}, input)
}

func (s dpapiStore) Load(ctx context.Context) (*CredentialRecord, error) {
	sealed, found, err := s.deps.readFile(s.path)
	if err != nil {
		return nil, storageFailed("읽기", err)
	}
	if !found || strings.TrimSpace(sealed) == "" {
		return nil, nil
	}
	plain, err := s.ps(ctx, dpapiUnprotect, sealed)
	if err != nil {
		return nil, storageFailed("읽기", err)
	}
	record, err := parseRecord(plain)
	return record, storageFailed("읽기", err)
}

func (s dpapiStore) Save(ctx context.Context, record CredentialRecord) error {
	data, _ := json.Marshal(record)
	sealed, err := s.ps(ctx, dpapiProtect, string(data))
	if err != nil {
		return storageFailed("쓰기", err)
	}
	return storageFailed("쓰기", s.deps.writeFile(s.path, strings.TrimSpace(sealed)))
}

func (s dpapiStore) Clear(context.Context) error {
	return storageFailed("지우기", s.deps.remove(s.path))
}

// DefaultCredentialStore는 운영체제에 맞는 기본 저장소다 — Windows DPAPI 파일 · Linux Secret Service(secret-tool이 없으면 0600 파일 + warn) ·
// macOS는 cgo 없이 키체인을 안전하게 쓸 길이 없어(security 명령은 비밀을 인자로 받고, 그 명령이 만든 항목은 다른 프로세스도 security로 읽는다)
// 0600 파일 + warn. account는 clientId.
func DefaultCredentialStore(appName, account string, logger Logger) CredentialStore {
	return defaultStore(appName, account, logger, systemDeps)
}

func defaultStore(appName, account string, logger Logger, deps osDeps) CredentialStore {
	file := filepath.Join(appDataDir(appName, deps), "bydev-credentials")
	switch deps.goos {
	case "windows":
		return dpapiStore{path: file, deps: deps}
	case "linux":
		if deps.lookPath("secret-tool") == nil {
			return secretToolStore{account: account, deps: deps}
		}
	}
	return newFileStore(file, logger, deps)
}
