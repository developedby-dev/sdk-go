package bydev

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type call struct {
	name  string
	args  []string
	stdin string
}

type exitError struct {
	code   int
	stderr string
}

func (e exitError) Error() string  { return "exit" }
func (e exitError) ExitCode() int  { return e.code }
func (e exitError) Stderr() string { return e.stderr }

// 명령 · 파일을 기록하는 가짜 — 운영체제 명령이 없는 곳에서 명령 모양과 해석을 본다.
type fake struct {
	calls   []call
	files   map[string]string
	answers map[string]any // "명령 첫인자" 또는 "명령" → string | error
	tools   map[string]bool
}

func newFake(answers map[string]any) *fake {
	return &fake{files: map[string]string{}, answers: answers, tools: map[string]bool{}}
}

func (f *fake) deps(goos string) osDeps {
	return osDeps{
		goos: goos,
		exec: func(_ context.Context, name string, args []string, stdin string) (string, error) {
			f.calls = append(f.calls, call{name, args, stdin})
			answer, ok := f.answers[name+" "+args[0]]
			if !ok {
				answer = f.answers[name]
			}
			switch a := answer.(type) {
			case error:
				return "", a
			case string:
				return a, nil
			}
			return "", nil
		},
		lookPath: func(name string) error {
			if f.tools[name] {
				return nil
			}
			return errors.New("없음")
		},
		readFile: func(path string) (string, bool, error) {
			v, ok := f.files[path]
			return v, ok, nil
		},
		writeFile: func(path, content string) error { f.files[path] = content; return nil },
		remove:    func(path string) error { delete(f.files, path); return nil },
		newID:     func() string { return "00000000-0000-4000-8000-00000000abcd" },
	}
}

var testRecord = CredentialRecord{Version: 1, RefreshToken: "rt_node_test_00000000001", Scope: "entitlement.read", SavedAt: "2026-10-06T13:00:00Z"}

type recordingLogger struct{ warns []string }

func (l *recordingLogger) Debug(string, ...any)      {}
func (l *recordingLogger) Info(string, ...any)       {}
func (l *recordingLogger) Warn(msg string, _ ...any) { l.warns = append(l.warns, msg) }

func TestFingerprintPerOS(t *testing.T) {
	ctx := context.Background()
	win := newFake(map[string]any{"reg": "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    3f1e9a2b-1111-2222-3333-444455556666\r\n"})
	if got, _ := (fingerprintSource{deps: win.deps("windows")}).Read(ctx); got != "3f1e9a2b-1111-2222-3333-444455556666" {
		t.Fatalf("windows %q", got)
	}
	mac := newFake(map[string]any{"ioreg": `  "IOPlatformUUID" = "A1B2C3D4-0000-1111-2222-333344445555"`})
	if got, _ := (fingerprintSource{deps: mac.deps("darwin")}).Read(ctx); got != "A1B2C3D4-0000-1111-2222-333344445555" {
		t.Fatalf("darwin %q", got)
	}
	linux := newFake(nil)
	linux.files["/var/lib/dbus/machine-id"] = "0123456789abcdef0123456789abcdef\n"
	if got, _ := (fingerprintSource{deps: linux.deps("linux")}).Read(ctx); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("linux %q", got)
	}
}

func TestFingerprintInstallIDFallback(t *testing.T) {
	ctx := context.Background()
	f := newFake(map[string]any{"ioreg": errors.New("권한 없음")})
	src := fingerprintSource{installIDFile: "/app/install-id", deps: f.deps("darwin")}
	first, _ := src.Read(ctx)
	if first != "00000000-0000-4000-8000-00000000abcd" || f.files["/app/install-id"] != first {
		t.Fatalf("설치 ID %q · 파일 %q", first, f.files["/app/install-id"])
	}
	f.files["/app/install-id"] = "kept-install-id\n"
	if again, _ := src.Read(ctx); again != "kept-install-id" {
		t.Fatalf("다시 읽기 %q", again)
	}
	// 파일 자리도 없으면 ""(SDK가 수명 동안의 난수 ID로 물러난다)
	if none, _ := (fingerprintSource{deps: f.deps("darwin")}).Read(ctx); none != "" {
		t.Fatalf("%q", none)
	}
}

func TestSecretToolStore(t *testing.T) {
	ctx := context.Background()
	f := newFake(map[string]any{"secret-tool lookup": exitError{code: 1}})
	store := secretToolStore{account: "cli_test", deps: f.deps("linux")}
	if got, err := store.Load(ctx); got != nil || err != nil {
		t.Fatalf("항목 없음 → nil, got %v %v", got, err)
	}
	if err := store.Save(ctx, testRecord); err != nil {
		t.Fatal(err)
	}
	save := f.calls[1]
	if strings.Join(save.args, " ") != "store --label=bydev cli_test service "+RuleStorageService+" account cli_test" {
		t.Fatalf("인자 %v", save.args)
	}
	// 비밀은 인자에 없고 표준 입력으로만
	for _, a := range save.args {
		if strings.Contains(a, testRecord.RefreshToken) {
			t.Fatal("refresh_token이 인자에 있다")
		}
	}
	if !strings.Contains(save.stdin, testRecord.RefreshToken) {
		t.Fatal("refresh_token이 표준 입력에 없다")
	}
	f.answers = map[string]any{"secret-tool lookup": `{"version":1,"refreshToken":"rt_node_test_00000000001","scope":"entitlement.read","savedAt":"2026-10-06T13:00:00Z"}`}
	if got, err := store.Load(ctx); err != nil || got == nil || *got != testRecord {
		t.Fatalf("%v %v", got, err)
	}
	f.answers = map[string]any{"secret-tool lookup": exitError{code: 2}}
	_, err := store.Load(ctx)
	wantCode(t, err, CodeStorageFailed)
	// 없는 항목 지우기는 성공 — 오류 출력이 있으면(D-Bus 없음 등) 읽기 · 지우기 모두 STORAGE_FAILED
	f.answers = map[string]any{"secret-tool clear": exitError{code: 1}}
	if err := store.Clear(ctx); err != nil {
		t.Fatalf("없는 항목 지우기 %v", err)
	}
	broken := exitError{code: 1, stderr: "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n"}
	f.answers = map[string]any{"secret-tool clear": broken, "secret-tool lookup": broken}
	wantCode(t, store.Clear(ctx), CodeStorageFailed)
	_, err = store.Load(ctx)
	wantCode(t, err, CodeStorageFailed)
}

func TestDPAPIStore(t *testing.T) {
	ctx := context.Background()
	f := newFake(map[string]any{"powershell.exe": "c2VhbGVk\r\n"})
	store := dpapiStore{path: `C:\app\bydev-credentials`, deps: f.deps("windows")}
	if err := store.Save(ctx, testRecord); err != nil {
		t.Fatal(err)
	}
	if f.files[`C:\app\bydev-credentials`] != "c2VhbGVk" {
		t.Fatalf("파일 %q", f.files[`C:\app\bydev-credentials`])
	}
	protect := f.calls[0]
	if strings.Contains(strings.Join(protect.args, " "), testRecord.RefreshToken) || !strings.Contains(protect.stdin, testRecord.RefreshToken) {
		t.Fatal("비밀이 표준 입력으로만 가야 한다")
	}
	f.answers = map[string]any{"powershell.exe": `{"version":1,"refreshToken":"rt_node_test_00000000001","scope":"entitlement.read","savedAt":"2026-10-06T13:00:00Z"}`}
	if got, err := store.Load(ctx); err != nil || got == nil || *got != testRecord {
		t.Fatalf("%v %v", got, err)
	}
	if f.calls[1].stdin != "c2VhbGVk" {
		t.Fatalf("풀기 입력 %q", f.calls[1].stdin)
	}
	_ = store.Clear(ctx)
	if got, _ := store.Load(ctx); got != nil {
		t.Fatal("지운 뒤에도 기록이 있다")
	}
}

func TestFileStoreRealDisk(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "bydev-credentials")
	logger := &recordingLogger{}
	store := FileCredentialStore(path, logger)
	if len(logger.warns) != 1 {
		t.Fatal("암호화하지 않는다는 warn이 없다")
	}
	if got, err := store.Load(ctx); got != nil || err != nil {
		t.Fatalf("%v %v", got, err)
	}
	if err := store.Save(ctx, testRecord); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("권한 %v", info.Mode().Perm())
		}
	}
	if got, err := store.Load(ctx); err != nil || *got != testRecord {
		t.Fatalf("%v %v", got, err)
	}
	// 판이 다른 기록은 없는 것으로 읽는다
	os.WriteFile(path, []byte(`{"version":99,"refreshToken":"x"}`), 0o600)
	if got, _ := store.Load(ctx); got != nil {
		t.Fatal("모르는 판을 읽었다")
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatal("없는 파일 지우기는 실패가 아니다")
	}
}

func TestDefaultStoreChoice(t *testing.T) {
	f := newFake(nil)
	if _, ok := defaultStore("App", "cli", nil, f.deps("windows")).(dpapiStore); !ok {
		t.Fatal("windows → DPAPI")
	}
	logger := &recordingLogger{}
	if _, ok := defaultStore("App", "cli", logger, f.deps("linux")).(fileStore); !ok || len(logger.warns) != 1 {
		t.Fatal("secret-tool 없는 linux → 0600 파일 + warn")
	}
	f.tools["secret-tool"] = true
	if _, ok := defaultStore("App", "cli", nil, f.deps("linux")).(secretToolStore); !ok {
		t.Fatal("linux → Secret Service")
	}
	if _, ok := defaultStore("App", "cli", nil, f.deps("darwin")).(fileStore); !ok {
		t.Fatal("darwin → 0600 파일")
	}
}

// 이 기기의 실제 지문 출처를 한 번 읽는다(값은 출력하지 않는다)
func TestFingerprintThisMachine(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("지문 출처가 없는 운영체제")
	}
	got, err := OSFingerprintSource("").Read(context.Background())
	if err != nil || got == "" {
		t.Fatalf("이 기기의 지문 출처를 읽지 못했다: %v", err)
	}
}
