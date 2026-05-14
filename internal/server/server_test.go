package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	p := daemon.Paths{
		State: filepath.Join(dir, "state"),
		Logs:  filepath.Join(dir, "logs"),
	}
	if err := p.Ensure(); err != nil {
		t.Fatalf("ensure paths: %v", err)
	}
	s, err := NewServer(Options{Paths: p, ListenHost: "127.0.0.1", Version: "test"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestNewServerRejectsNonLoopbackHost(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "192.168.1.1", "::"} {
		t.Run(host, func(t *testing.T) {
			_, err := NewServer(Options{
				Paths:      daemon.Paths{State: t.TempDir(), Logs: t.TempDir()},
				ListenHost: host,
			})
			if err == nil {
				t.Fatalf("expected error binding to %q", host)
			}
		})
	}
}

func TestBindWritesStateFile(t *testing.T) {
	s := newTestServer(t)
	state, found, err := daemon.ReadStateFile(s.opts.Paths.StateFile())
	if err != nil {
		t.Fatalf("ReadStateFile: %v", err)
	}
	if !found {
		t.Fatal("state file not present after Bind")
	}
	if state.Port != s.Port() {
		t.Errorf("state.Port = %d, want %d", state.Port, s.Port())
	}
	if state.Token != s.Token() {
		t.Errorf("state.Token = %q, want %q", state.Token, s.Token())
	}
	if state.WrittenAt == 0 {
		t.Error("state.WrittenAt is zero — should be set by Bind")
	}
}

func TestCloseRemovesStateFile(t *testing.T) {
	s := newTestServer(t)
	if _, found, _ := daemon.ReadStateFile(s.opts.Paths.StateFile()); !found {
		t.Fatal("state file should exist after Bind")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, found, _ := daemon.ReadStateFile(s.opts.Paths.StateFile()); found {
		t.Error("state file should be removed after Close")
	}
}

func TestHealthzNoAuth(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })
	resp := mustDo(t, s, "GET", "/healthz", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}

func TestFindingsRequiresToken(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	// No token.
	resp := mustDo(t, s, "GET", "/api/findings", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token status = %d, want 401", resp.StatusCode)
	}

	// Wrong token.
	resp = mustDo(t, s, "GET", "/api/findings?t=nope", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-token status = %d, want 401", resp.StatusCode)
	}

	// Correct token.
	resp = mustDo(t, s, "GET", "/api/findings?t="+s.Token(), "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("good-token status = %d, want 200", resp.StatusCode)
	}
}

func TestFindingsReturnsSnapshot(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	resp := mustDo(t, s, "GET", "/api/findings?t="+s.Token(), "")
	defer resp.Body.Close()
	var snap SnapshotResponse
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) == 0 {
		t.Error("expected demo findings to be present")
	}
	// Metric totals match the findings count.
	if snap.Metrics.OpenTotal != len(snap.Findings) {
		t.Errorf("metrics.OpenTotal = %d, want %d", snap.Metrics.OpenTotal, len(snap.Findings))
	}
	if snap.Daemon.Version != "test" {
		t.Errorf("daemon.Version = %q, want test", snap.Daemon.Version)
	}
}

func TestRemediationRoute(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	// Known fingerprint -> 200 + body.
	resp := mustDo(t, s, "GET", "/api/remediation/demo-codex-trust?t="+s.Token(), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var rem RemediationResponse
	_ = json.NewDecoder(resp.Body).Decode(&rem)
	if rem.AIPrompt == "" || rem.HumanSteps == "" {
		t.Errorf("missing remediation fields: %+v", rem)
	}

	// Unknown fingerprint -> 404.
	resp = mustDo(t, s, "GET", "/api/remediation/does-not-exist?t="+s.Token(), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown fp status = %d, want 404", resp.StatusCode)
	}
}

func TestHostHeaderCheckRejectsForeignHost(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	// Build a request manually with a forged Host header. This is the
	// DNS-rebinding scenario: evil.com's DNS rebinds to 127.0.0.1 but
	// browser still sends Host: evil.com.
	req, err := http.NewRequest("GET", "http://"+s.Addr()+"/api/findings?t="+s.Token(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("DNS-rebind status = %d, want 403; body = %q", resp.StatusCode, body)
	}
}

func TestIndexServesEmbeddedDashboard(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	resp := mustDo(t, s, "GET", "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"audr", "dashboard.js", "dashboard.css"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestStaticAssetsServedWithoutAuth(t *testing.T) {
	s := newTestServer(t)
	go func() { _ = s.Run(context.Background()) }()
	t.Cleanup(func() { _ = s.Close() })

	// JS + CSS are static markup; no auth boundary lives here.
	for _, path := range []string{"/dashboard.js", "/dashboard.css"} {
		resp := mustDo(t, s, "GET", path, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %q = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestRunHonorsContextCancel(t *testing.T) {
	s := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Give server a beat to start serving.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run err = %v, want nil/canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// mustDo issues a GET request to s.Addr() + path and fails the test on
// transport error.
func mustDo(t *testing.T, s *Server, method, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, fmt.Sprintf("http://%s%s", s.Addr(), path), strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
