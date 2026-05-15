package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/state"

	// Register built-in rules so handleGetPolicy returns a real catalog.
	_ "github.com/harshmaur/audr/internal/rules/builtin"
)

// TestPolicyRoutes_Get returns the current policy with the rule
// catalog. With no policy file on disk, the response is the default
// (empty overrides) plus the canonical YAML header.
func TestPolicyRoutes_Get(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	req, _ := http.NewRequest("GET", baseURL+"/api/policy?t="+token, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var body policyAPIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Policy.Version != 1 {
		t.Errorf("policy version = %d, want 1", body.Policy.Version)
	}
	if !strings.HasPrefix(body.YAML, "# ~/.audr/policy.yaml") {
		t.Errorf("canonical YAML header missing:\n%s", body.YAML)
	}
	if len(body.Rules) == 0 {
		t.Errorf("rule catalog empty — built-in rules must be registered")
	}
}

// TestPolicyRoutes_PutValidPolicy: a valid POST persists and returns
// the canonical YAML the server actually wrote.
func TestPolicyRoutes_PutValidPolicy(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	enabled := false
	bodyBytes, _ := json.Marshal(map[string]any{
		"version": 1,
		"rules": map[string]any{
			"mcp-unpinned-npx": map[string]any{
				"enabled": &enabled,
				"notes":   "test fixture",
			},
		},
	})
	req, _ := http.NewRequest("POST", baseURL+"/api/policy?t="+token,
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := readAllBody(res)
		t.Fatalf("status = %d (want 200), body: %s", res.StatusCode, body)
	}
	var respBody policyAPIResponse
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		t.Fatal(err)
	}
	if _, ok := respBody.Policy.Rules["mcp-unpinned-npx"]; !ok {
		t.Errorf("saved policy missing the rule we just POSTed: %+v", respBody.Policy.Rules)
	}
	if !strings.Contains(respBody.YAML, "test fixture") {
		t.Errorf("canonical YAML should contain notes string:\n%s", respBody.YAML)
	}
}

// TestPolicyRoutes_PutRejectsInvalid: a malformed severity returns 422.
func TestPolicyRoutes_PutRejectsInvalid(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	bodyBytes := []byte(`{
		"version": 1,
		"rules": {
			"x": {"severity": "ULTRA"}
		}
	}`)
	req, _ := http.NewRequest("POST", baseURL+"/api/policy?t="+token,
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		body, _ := readAllBody(res)
		t.Errorf("status = %d, want 422 (body: %s)", res.StatusCode, body)
	}
}

// TestPolicyRoutes_ValidateEndpoint: POST /api/policy/validate runs
// validation without writing.
func TestPolicyRoutes_ValidateEndpoint(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	// Valid policy.
	valid := []byte(`{"version": 1, "rules": {}}`)
	req, _ := http.NewRequest("POST", baseURL+"/api/policy/validate?t="+token,
		bytes.NewReader(valid))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(res.Body).Decode(&result)
	if v, _ := result["valid"].(bool); !v {
		t.Errorf("valid policy should return valid:true; got %+v", result)
	}

	// Invalid policy.
	invalid := []byte(`{"version": 1, "suppressions": [{"rule": "r"}]}`)
	req2, _ := http.NewRequest("POST", baseURL+"/api/policy/validate?t="+token,
		bytes.NewReader(invalid))
	req2.Header.Set("Content-Type", "application/json")
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var result2 map[string]any
	json.NewDecoder(res2.Body).Decode(&result2)
	if v, _ := result2["valid"].(bool); v {
		t.Errorf("invalid policy should return valid:false; got %+v", result2)
	}
}

// TestPolicyRoutes_RulesList: GET /api/rules returns the catalog
// alone.
func TestPolicyRoutes_RulesList(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	req, _ := http.NewRequest("GET", baseURL+"/api/rules?t="+token, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string][]policyAPIRuleCatalog
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body["rules"]) == 0 {
		t.Errorf("rules array empty")
	}
}

// TestPolicyRoutes_RequiresToken: every /api/policy* endpoint must
// reject unauthenticated requests.
func TestPolicyRoutes_RequiresToken(t *testing.T) {
	srv, baseURL, _, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	for _, path := range []string{
		"/api/policy",
		"/api/policy/validate",
		"/api/rules",
		"/policy/edit",
	} {
		t.Run(path, func(t *testing.T) {
			res, err := http.Get(baseURL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode == http.StatusOK {
				t.Errorf("%s served without token", path)
			}
		})
	}
}

// TestPolicyEditPageRenders: GET /policy/edit with a valid token
// returns the HTML page including the htmx + Alpine script
// references.
func TestPolicyEditPageRenders(t *testing.T) {
	srv, baseURL, token, cleanup := newPolicyTestServer(t)
	defer cleanup()
	_ = srv

	req, _ := http.NewRequest("GET", baseURL+"/policy/edit?t="+token, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	body, _ := readAllBody(res)
	for _, want := range []string{
		`x-data="policyEditor()"`,
		"vendor/htmx.min.js",
		"vendor/alpine.min.js",
		"policy.css",
		"policy.js",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("policy.html missing %q", want)
		}
	}
}

// ----- helpers --------------------------------------------------

// newPolicyTestServer spins up the real audr daemon server on
// 127.0.0.1:<random>. Sets HOME to a temp dir so the policy file
// lands somewhere safe and doesn't pollute the developer's real
// ~/.audr/. Returns base URL + auto-generated token.
//
// Uses the real Bind+Run path (not httptest.NewServer with
// buildMux directly) so the hostCheck middleware sees the
// expected 127.0.0.1:<port> Host header.
func newPolicyTestServer(t *testing.T) (*Server, string, string, func()) {
	t.Helper()
	tmpHome := t.TempDir()
	prev := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	_ = os.MkdirAll(filepath.Join(tmpHome, ".audr"), 0o700)

	dir := t.TempDir()
	p := daemon.Paths{
		State: filepath.Join(dir, "state"),
		Logs:  filepath.Join(dir, "logs"),
	}
	if err := p.Ensure(); err != nil {
		t.Fatalf("ensure paths: %v", err)
	}
	store, err := state.Open(state.Options{Path: filepath.Join(p.State, "audr.db")})
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = store.Run(ctx) }()
	time.Sleep(5 * time.Millisecond)

	rem, err := NewDemoRemediation()
	if err != nil {
		t.Fatalf("NewDemoRemediation: %v", err)
	}

	srv, err := NewServer(Options{
		Paths:       p,
		Store:       store,
		Remediation: rem,
		ListenHost:  "127.0.0.1",
		Version:     "test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	go func() { _ = srv.Run(context.Background()) }()

	cleanup := func() {
		_ = srv.Close()
		_ = store.Close()
		os.Setenv("HOME", prev)
	}
	return srv, "http://" + srv.Addr(), srv.Token(), cleanup
}

func readAllBody(res *http.Response) ([]byte, error) {
	buf := make([]byte, 16<<10)
	n, err := res.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return buf[:n], err
	}
	return buf[:n], nil
}
