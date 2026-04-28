package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchInSumsFile(t *testing.T) {
	dir := t.TempDir()

	tarball := filepath.Join(dir, "agentguard-v0.2.4-linux-arm64.tar.gz")
	if err := os.WriteFile(tarball, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := sha256File(tarball)
	if err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(dir, "agentguard-v0.2.4-linux-amd64.tar.gz")
	if err := os.WriteFile(other, []byte("different bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	otherSum, _ := sha256File(other)

	cases := []struct {
		name    string
		sums    string
		hash    string
		base    string
		want    bool
		wantErr bool
	}{
		{
			name: "matched line",
			sums: fmt.Sprintf("%s  %s\n%s  %s\n", sum, filepath.Base(tarball), otherSum, filepath.Base(other)),
			hash: sum,
			base: filepath.Base(tarball),
			want: true,
		},
		{
			name: "right hash wrong filename",
			sums: fmt.Sprintf("%s  agentguard-v0.2.4-darwin-arm64.tar.gz\n", sum),
			hash: sum,
			base: filepath.Base(tarball),
			want: false,
		},
		{
			name: "wrong hash right filename",
			sums: fmt.Sprintf("%s  %s\n", otherSum, filepath.Base(tarball)),
			hash: sum,
			base: filepath.Base(tarball),
			want: false,
		},
		{
			name: "ignores comments and blank lines",
			sums: "# header\n\n  \n" + fmt.Sprintf("%s  %s\n", sum, filepath.Base(tarball)),
			hash: sum,
			base: filepath.Base(tarball),
			want: true,
		},
		{
			name: "binary-mode asterisk prefix tolerated",
			sums: fmt.Sprintf("%s *%s\n", sum, filepath.Base(tarball)),
			hash: sum,
			base: filepath.Base(tarball),
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sumsPath := filepath.Join(t.TempDir(), "SHA256SUMS")
			if err := os.WriteFile(sumsPath, []byte(tc.sums), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := matchInSumsFile(sumsPath, tc.hash, tc.base)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestVerify_HashOnlyHappyPath(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "agentguard-vX.Y.Z-linux-arm64.tar.gz")
	body := []byte("agentguard release artifact bytes")
	if err := os.WriteFile(tarball, body, 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	sum := hex.EncodeToString(h[:])
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(sum+"  "+filepath.Base(tarball)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Verify(tarball, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !r.SumsOK {
		t.Errorf("SumsOK = false, want true")
	}
	if r.Sum != sum {
		t.Errorf("Sum = %s, want %s", r.Sum, sum)
	}
	if r.CosignAttempted {
		// Test environment may or may not have cosign; only assert if .sig/.crt missing
		if !fileExists(r.SigPath) {
			t.Errorf("CosignAttempted = true with no .sig present")
		}
	}
	if !r.Pass() {
		t.Errorf("Pass() = false, want true")
	}
}

func TestVerify_TamperedTarballFails(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "agentguard.tar.gz")
	if err := os.WriteFile(tarball, []byte("genuine body"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sums file claims a hash that won't match.
	sums := filepath.Join(dir, "SHA256SUMS")
	bogus := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := os.WriteFile(sums, []byte(bogus+"  "+filepath.Base(tarball)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Verify(tarball, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.SumsOK {
		t.Fatalf("SumsOK = true on tampered tarball")
	}
	if r.Pass() {
		t.Fatalf("Pass() = true on tampered tarball")
	}
}

func TestVerify_MissingSumsFileIsHardError(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "agentguard.tar.gz")
	if err := os.WriteFile(tarball, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tarball, Options{}); err == nil {
		t.Fatalf("expected error when SHA256SUMS is missing, got nil")
	}
}
