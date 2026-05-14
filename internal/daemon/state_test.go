package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAndReadStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.state")
	want := State{Port: 31415, Token: "abc123def_-XYZ", WrittenAt: 1700000000}

	if err := WriteStateFile(path, want); err != nil {
		t.Fatalf("WriteStateFile: %v", err)
	}

	got, found, err := ReadStateFile(path)
	if err != nil {
		t.Fatalf("ReadStateFile: %v", err)
	}
	if !found {
		t.Fatal("ReadStateFile found=false on existing file")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestWriteStateFileSetsMode0600OnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode semantics differ on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.state")
	if err := WriteStateFile(path, State{Port: 1, Token: "x"}); err != nil {
		t.Fatalf("WriteStateFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600 (token is sensitive; group/other read is unsafe)", mode)
	}
}

func TestReadStateFileMissingFileReturnsFoundFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.state")
	got, found, err := ReadStateFile(path)
	if err != nil {
		t.Fatalf("ReadStateFile: %v", err)
	}
	if found {
		t.Fatalf("found=true on missing file: %+v", got)
	}
}

func TestReadStateFileRejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.state")
	if err := os.WriteFile(path, []byte("{this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadStateFile(path); err == nil {
		t.Fatal("expected error on corrupt JSON")
	}
}

func TestReadStateFileRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing port", `{"token":"t"}`},
		{"missing token", `{"port":1}`},
		{"zero port", `{"port":0,"token":"t"}`},
		{"empty token", `{"port":1,"token":""}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "daemon.state")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadStateFile(path); err == nil {
				t.Fatalf("expected error for %q, got nil", tt.body)
			}
		})
	}
}

func TestWriteStateFileIsAtomicAcrossOverwrites(t *testing.T) {
	// Verify the temp+rename pattern: at no point should a reader see a
	// half-written file. We can't easily induce a race in a unit test,
	// but we CAN verify there's no leftover temp file after a clean
	// write — a smoke test that the rename happened.
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.state")
	for i := 0; i < 5; i++ {
		if err := WriteStateFile(path, State{Port: i + 1, Token: "t"}); err != nil {
			t.Fatalf("WriteStateFile #%d: %v", i, err)
		}
	}
	// Directory should only contain the final state file, no .tmp leftovers.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected 1 entry after rename, got %d: %v", len(entries), names)
	}
}

func TestRemoveStateFileIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.state")
	// File doesn't exist yet.
	if err := RemoveStateFile(path); err != nil {
		t.Fatalf("Remove on missing file: %v", err)
	}
	// Create + remove.
	if err := WriteStateFile(path, State{Port: 1, Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStateFile(path); err != nil {
		t.Fatalf("Remove on existing file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still exists after Remove: %v", err)
	}
}

func TestStateJSONFieldNamesAreStable(t *testing.T) {
	// The on-disk format is a public-ish contract — `audr open` reads
	// it, future versions read it. Lock the field names so a rename
	// breaks the test rather than silently breaking deployments.
	s := State{Port: 1, Token: "x", WrittenAt: 2}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{`"port":1`, `"token":"x"`, `"written_at":2`} {
		if !contains(body, want) {
			t.Errorf("JSON missing %q: %s", want, body)
		}
	}
}
