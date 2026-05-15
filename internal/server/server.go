package server

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"os"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/notify"
	"github.com/harshmaur/audr/internal/orchestrator"
	"github.com/harshmaur/audr/internal/state"
)

//go:embed dashboard
var dashboardFS embed.FS

// Options configures a server.Server. Most callers can leave fields at
// zero — the constructor fills in production defaults.
type Options struct {
	// Paths controls where the state file (port + token) lives.
	// Required.
	Paths daemon.Paths

	// Store is the audr state store the server reads findings + scans
	// + scanner statuses from, and subscribes to for live SSE deltas.
	// Required.
	Store *state.Store

	// Remediation looks up a (human_steps, ai_prompt) pair for a
	// fingerprint. Phase 6 ships a real template library backed by
	// rule-id / ecosystem / detector dispatch; Phase 2 ships a demo
	// map. Required.
	Remediation RemediationLookup

	// ListenHost defaults to "127.0.0.1". The server hard-fails at
	// construction time if anything tries to bind 0.0.0.0 — the auth
	// model (token only) is only sound on a loopback interface.
	ListenHost string

	// ListenPort is the TCP port to bind. Use 0 to let the kernel pick
	// a free ephemeral port (recommended for production: avoids
	// collisions between different audr installs on multi-user
	// machines).
	ListenPort int

	// Version is the audr binary version, surfaced in the dashboard
	// footer.
	Version string

	// UpdateProbe, when non-nil, is queried on each /api/findings
	// snapshot to determine whether the daemon should advertise an
	// "update available" banner. nil disables the banner — useful
	// for tests + for users who pin their version.
	UpdateProbe UpdateProbe

	// WatcherProbe, when non-nil, surfaces watcher-side limitations
	// to the dashboard (inotify limit, remote-FS roots). nil
	// disables those two banners — useful for tests + for the
	// one-shot CLI path which doesn't have a long-running watcher.
	WatcherProbe WatcherProbe

	// shutdownTimeout caps how long Close() waits for in-flight
	// requests after the listener is closed. 5s default.
	shutdownTimeout time.Duration
}

// RemediationLookup resolves a finding to its (manual steps, AI
// prompt) pair. Phase 6 ships the real template library via
// internal/templates; the Lookup contract takes a full state.Finding
// so handlers can parameterize templates on the locator + severity +
// category without re-fetching the row.
type RemediationLookup interface {
	Lookup(f state.Finding) (humanSteps, aiPrompt string, ok bool)
}

// UpdateProbe reports whether a newer audr release is available. The
// concrete implementation is internal/updater.Checker; the server
// only needs the read API so tests can fake it without spinning up
// HTTP machinery. Returning nil means "no update available."
type UpdateProbe interface {
	Latest() *UpdateAvailable
}

// WatcherProbe is the read-side surface the server needs from the
// watch subsystem. internal/watch.Watcher satisfies it natively;
// the indirection keeps server independent of the watch package.
//
// InotifyMode returns one of "full" / "degraded" / "n/a" — the
// server maps "degraded" to DaemonInfo.InotifyLow=true.
// RemoteRoots returns the slice of scope paths that resolved to a
// remote filesystem at watcher startup; the server reports the
// count on DaemonInfo.RemoteFsSkipped.
type WatcherProbe interface {
	InotifyMode() string
	RemoteRoots() []string
}

// Server is the audr daemon's local HTTP surface. Implements
// daemon.Subsystem so it slots straight into daemon.Lifecycle.
type Server struct {
	opts     Options
	token    string
	listener net.Listener
	httpSrv  *http.Server
	addr     string // resolved 127.0.0.1:<port> after Bind

	// runningPort is the port we wrote to the state file. Stored
	// atomically so tests can read it concurrently.
	runningPort atomic.Int64
}

// NewServer constructs a server but does not bind yet. Use Bind() to
// take the port (or call Run() which does both).
func NewServer(opts Options) (*Server, error) {
	if opts.Paths.State == "" {
		return nil, errors.New("server: Paths.State is required")
	}
	if opts.Store == nil {
		return nil, errors.New("server: Store is required")
	}
	if opts.Remediation == nil {
		return nil, errors.New("server: Remediation is required")
	}
	if opts.ListenHost == "" {
		opts.ListenHost = "127.0.0.1"
	}
	// Hard refusal: the token-only auth model only protects on loopback.
	// Defense in depth: if someone wires up 0.0.0.0 (or :: etc.) by
	// accident, we crash at construction rather than expose findings
	// to the LAN.
	if !isLoopbackHost(opts.ListenHost) {
		return nil, fmt.Errorf("server: ListenHost must be a loopback address, got %q", opts.ListenHost)
	}
	if opts.shutdownTimeout <= 0 {
		opts.shutdownTimeout = 5 * time.Second
	}

	token, err := NewToken()
	if err != nil {
		return nil, fmt.Errorf("server: generate token: %w", err)
	}

	s := &Server{opts: opts, token: token}
	return s, nil
}

// Token returns the per-startup auth token. Useful for tests that
// construct a server and need to call into it; production code reads
// the token from the state file.
func (s *Server) Token() string { return s.token }

// Addr returns the bound address (e.g., "127.0.0.1:54321") after Bind
// completes. Empty until then.
func (s *Server) Addr() string { return s.addr }

// Port returns the bound port (0 until Bind succeeds).
func (s *Server) Port() int { return int(s.runningPort.Load()) }

// Name implements daemon.Subsystem.
func (s *Server) Name() string { return "server" }

// Bind takes the TCP port and writes the daemon state file but does not
// start serving yet. Tests that want to drive the server with an
// in-process http.Client without spinning up Lifecycle should use this.
func (s *Server) Bind() error {
	addr := fmt.Sprintf("%s:%d", s.opts.ListenHost, s.opts.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", addr, err)
	}
	s.listener = ln
	s.addr = ln.Addr().String()
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.runningPort.Store(int64(tcpAddr.Port))
	}

	// Write the state file so `audr open` can find us.
	state := daemon.State{
		Port:      s.Port(),
		Token:     s.token,
		WrittenAt: daemon.NowUnix(),
	}
	if err := daemon.WriteStateFile(s.opts.Paths.StateFile(), state); err != nil {
		_ = ln.Close()
		return fmt.Errorf("server: write state file: %w", err)
	}

	s.httpSrv = &http.Server{
		Handler:           s.buildMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return nil
}

// Run implements daemon.Subsystem. Binds (if Bind wasn't already
// called) and blocks serving until ctx is cancelled or a fatal listener
// error occurs. Always returns nil on graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		if err := s.Bind(); err != nil {
			return err
		}
	}

	// Shut down on context cancel: the goroutine watching ctx triggers
	// http.Server.Shutdown, which causes Serve to return cleanly.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.opts.shutdownTimeout)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}()

	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close implements daemon.Subsystem. Removes the state file (so a
// stale-port lookup by `audr open` doesn't pretend the daemon is still
// available) and closes the listener if it's still around. Idempotent.
func (s *Server) Close() error {
	var firstErr error
	if s.opts.Paths.State != "" {
		if err := daemon.RemoveStateFile(s.opts.Paths.StateFile()); err != nil {
			firstErr = err
		}
	}
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	return firstErr
}

// buildMux wires the route table. Layout:
//
//   /                         dashboard index.html (no auth — static markup)
//   /dashboard.js | .css      embedded assets        (no auth)
//   /healthz                  liveness probe         (no auth)
//   /api/findings             snapshot               (token required)
//   /api/events               SSE stream             (token required)
//   /api/remediation/:fp      remediation lookup     (token required)
//
// Every route goes through hostCheck — DNS-rebinding mitigation (D16).
// /api/* routes additionally go through tokenCheck.
func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()

	// Static assets. Use the embedded sub-FS rooted at "dashboard/"
	// so URLs are clean (/dashboard.js, not /dashboard/dashboard.js).
	subFS, err := fs.Sub(dashboardFS, "dashboard")
	if err != nil {
		// Compile-time guarantee: dashboardFS contains the dashboard/
		// directory because of //go:embed. If this fails the build is
		// already broken; panic is the right response.
		panic("server: dashboard sub-FS: " + err.Error())
	}
	staticHandler := http.FileServer(http.FS(subFS))

	mux.HandleFunc("GET /", s.handleIndex(staticHandler))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/findings", s.requireToken(s.handleFindings))
	mux.HandleFunc("GET /api/events", s.requireToken(s.handleEvents))
	mux.HandleFunc("GET /api/remediation/{fp}", s.requireToken(s.handleRemediation))
	mux.HandleFunc("DELETE /api/notify/pending", s.requireToken(s.handleNotifyPendingDismiss))
	mux.HandleFunc("POST /api/scanners", s.requireToken(s.handleScannersToggle))

	// Policy editor (v1.2 — user-editable rule overlay).
	mux.HandleFunc("GET /policy/edit", s.requireToken(s.handlePolicyPage))
	mux.HandleFunc("GET /api/policy", s.requireToken(s.handleGetPolicy))
	mux.HandleFunc("POST /api/policy", s.requireToken(s.handlePutPolicy))
	mux.HandleFunc("POST /api/policy/validate", s.requireToken(s.handleValidatePolicy))
	mux.HandleFunc("GET /api/rules", s.requireToken(s.handleRulesList))

	return s.hostCheck(mux)
}

// handleIndex serves the dashboard root and other static assets. We
// special-case "/" by reading index.html directly because
// http.FileServer would otherwise redirect "/index.html" back to "/"
// (its canonicalization rule), causing a redirect loop. Reading the
// embed.FS by hand avoids that round trip and preserves the
// ?t=<token> query the user landed on.
func (s *Server) handleIndex(static http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			s.serveEmbedded(w, r, "index.html", "text/html; charset=utf-8")
			return
		}
		static.ServeHTTP(w, r)
	}
}

// serveEmbedded writes a single embedded asset to the response with
// the requested Content-Type. Used for "/" so FileServer's redirect
// behavior doesn't bounce us out of the token-bearing URL.
func (s *Server) serveEmbedded(w http.ResponseWriter, _ *http.Request, name, contentType string) {
	subFS, err := fs.Sub(dashboardFS, "dashboard")
	if err != nil {
		http.Error(w, "embed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body, err := fs.ReadFile(subFS, name)
	if err != nil {
		http.Error(w, "embed: read "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// handleScannersToggle flips a single scanner category's enabled
// flag in scanner.config.json. The dashboard's click-to-toggle UI
// calls this with body {"category": "secrets", "enabled": false}.
// The running orchestrator re-reads the config at the top of every
// scan cycle, so the toggle takes effect within one interval.
//
// Returns 400 on unknown category, 200 with the full new config on
// success. The orchestrator's persisted state is the source of
// truth; the dashboard reflects it on next snapshot.
func (s *Server) handleScannersToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := orchestrator.ReadScannerConfig(s.opts.Paths.State)
	if err != nil {
		http.Error(w, "read scanner config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	updated, err := cfg.SetEnabled(body.Category, body.Enabled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := orchestrator.WriteScannerConfig(s.opts.Paths.State, updated); err != nil {
		http.Error(w, "write scanner config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleNotifyPendingDismiss clears the pending-notify.json file so
// the next dashboard snapshot won't carry the pending count. Called
// by the dashboard JS when the user dismisses the
// NOTIFICATIONS DROPPED banner. Idempotent — missing file is a 204
// not an error.
func (s *Server) handleNotifyPendingDismiss(w http.ResponseWriter, _ *http.Request) {
	if err := notify.ClearPending(s.opts.Paths.State); err != nil && !os.IsNotExist(err) {
		http.Error(w, "clear pending: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := s.opts.Store.SnapshotFindings(ctx)
	if err != nil {
		http.Error(w, "snapshot findings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	statuses, err := s.opts.Store.SnapshotScannerStatuses(ctx)
	if err != nil {
		http.Error(w, "snapshot scanner statuses: "+err.Error(), http.StatusInternalServerError)
		return
	}

	findings := make([]FindingView, 0, len(rows))
	for _, f := range rows {
		if !f.Open() {
			continue // dashboard only renders open findings in the initial snapshot
		}
		findings = append(findings, findingToView(f))
	}
	daemonInfo := DaemonInfo{
		State:   "RUN",
		Version: s.opts.Version,
	}
	// If a scan is currently in progress, surface that so the
	// dashboard's scan-progress strip doesn't misleadingly show
	// "INITIALIZING" until the next scan-started SSE event arrives —
	// a freshly-loaded dashboard can miss the scan-started event of
	// an already-in-flight scan entirely.
	if scans, err := s.opts.Store.SnapshotScans(ctx, 10); err == nil {
		// First pass: an in-progress scan flips ScanInProgress so
		// the dashboard's scan-progress strip can come up correct
		// on initial load. Second pass (in the same loop): the most
		// recent completed scan's completed_at populates
		// LastScanCompleted so the WATCHING state can render a
		// real relative-time clause.
		for _, sc := range scans {
			if sc.Status == "in_progress" {
				daemonInfo.ScanInProgress = true
			}
			if sc.Status == "completed" && sc.CompletedAt != nil &&
				*sc.CompletedAt > daemonInfo.LastScanCompleted {
				daemonInfo.LastScanCompleted = *sc.CompletedAt
			}
		}
	}
	if s.opts.UpdateProbe != nil {
		daemonInfo.UpdateAvailable = s.opts.UpdateProbe.Latest()
	}
	if s.opts.WatcherProbe != nil {
		if s.opts.WatcherProbe.InotifyMode() == "degraded" {
			daemonInfo.InotifyLow = true
		}
		daemonInfo.RemoteFsSkipped = len(s.opts.WatcherProbe.RemoteRoots())
	}
	// Pending-notification fallback: when the OS dropped toasts,
	// `notify` writes ${state_dir}/pending-notify.json. Surface the
	// count so the dashboard banner can prompt the user toward
	// `audr daemon notify --status` + OS settings.
	if pending, err := notify.ReadPending(s.opts.Paths.State); err == nil {
		daemonInfo.PendingNotifications = len(pending)
	}
	// Scanner enable/disable config. The dashboard click-to-toggle
	// UI reads this to render correct on/off state per category.
	if cfg, err := orchestrator.ReadScannerConfig(s.opts.Paths.State); err == nil {
		daemonInfo.ScannerEnabled = map[string]bool{
			"ai-agent": cfg.AIAgent,
			"deps":     cfg.Deps,
			"secrets":  cfg.Secrets,
			"os-pkg":   cfg.OSPkg,
		}
	}
	resp := SnapshotResponse{
		Findings: findings,
		Metrics:  computeMetrics(rows),
		Daemon:   daemonInfo,
		Scanners: scannerStatusesToInfo(statuses),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRemediation(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	f, err := s.opts.Store.FindingByFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no finding for fingerprint " + fp})
			return
		}
		http.Error(w, "lookup finding: "+err.Error(), http.StatusInternalServerError)
		return
	}
	human, ai, ok := s.opts.Remediation.Lookup(f)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no remediation handler matched fingerprint " + fp})
		return
	}
	writeJSON(w, http.StatusOK, RemediationResponse{
		Fingerprint: fp,
		HumanSteps:  human,
		AIPrompt:    ai,
	})
}

// handleEvents subscribes to the state store's event bus and forwards
// events as SSE frames until the request context cancels (browser
// tab closed, daemon shutting down). Per-connection ctx + cancel
// guarantees we never leak the subscriber after the consumer is gone.
//
// SSE wire shape:
//
//   retry: 5000
//
//   event: hello
//   data: {"v":1}
//
//   event: scan-started
//   data: {"id":42,"category":"all","started_at":1700000000,"status":"in_progress"}
//
//   event: finding-opened
//   data: {"fingerprint":"abc","rule_id":"r","severity":"high",...}
//
//   event: heartbeat
//   data: {"ts":1700000000}
//
// The retry hint is the entry into the design's exponential-backoff
// reconnect protocol (D2): the dashboard JS reads the field and
// doubles per reconnect failure up to 60s.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Initial protocol frame: retry hint + hello so the JS can
	// distinguish "I'm connected" from "I'm waiting on snapshot."
	_, _ = fmt.Fprintf(w, "retry: 5000\n\n")
	_, _ = fmt.Fprintf(w, "event: hello\ndata: {\"v\":1}\n\n")
	flusher.Flush()

	// Subscribe BEFORE we read the initial snapshot so we don't miss
	// any events that fire while the snapshot serializes. (The
	// snapshot itself is the dashboard's /api/findings call; this
	// SSE stream is the delta.)
	events, unsub := s.opts.Store.Subscribe()
	defer unsub()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-events:
			if !ok {
				// Subscriber was dropped by the store (slow consumer);
				// closing our writer lets the client SSE retry with
				// the exponential-backoff hint.
				return
			}
			if err := writeSSEFrame(w, flusher, e); err != nil {
				return
			}
		case t := <-heartbeat.C:
			if _, err := fmt.Fprintf(w, "event: heartbeat\ndata: {\"ts\":%d}\n\n", t.Unix()); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSEFrame serializes a store Event into SSE wire shape. Payloads
// go through json.Marshal directly; FindingView / Scan / ScannerStatus
// shapes are kept stable so the dashboard JS doesn't drift.
func writeSSEFrame(w http.ResponseWriter, flusher http.Flusher, e state.Event) error {
	var payload any
	switch v := e.Payload.(type) {
	case state.Finding:
		payload = findingToView(v)
	case state.Scan:
		payload = v
	case state.ScannerStatus:
		payload = scannerStatusToInfo(v)
	default:
		payload = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, body); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// findingToView lifts the persistence row into the wire shape the
// dashboard JS expects. The wire schema is intentionally separate from
// the storage schema (D17) — wire keys are camelCase-via-json-tags;
// storage uses snake_case columns; the two evolve on different
// cadences.
func findingToView(f state.Finding) FindingView {
	var locator map[string]any
	if len(f.Locator) > 0 {
		_ = json.Unmarshal(f.Locator, &locator)
	}
	firstSeen := time.Unix(f.FirstSeenAt, 0).UTC().Format(time.RFC3339)
	return FindingView{
		Fingerprint:   f.Fingerprint,
		RuleID:        f.RuleID,
		Severity:      f.Severity,
		Category:      f.Category,
		Kind:          f.Kind,
		Locator:       locator,
		Title:         f.Title,
		Description:   f.Description,
		MatchRedacted: f.MatchRedacted,
		FirstSeen:     firstSeen,
	}
}

func computeMetrics(findings []state.Finding) SnapshotMetrics {
	var m SnapshotMetrics
	cutoffResolvedToday := time.Now().Add(-24 * time.Hour).Unix()
	for _, f := range findings {
		if f.Open() {
			m.OpenTotal++
			switch f.Severity {
			case "critical":
				m.OpenCritical++
			case "high":
				m.OpenHigh++
			case "medium":
				m.OpenMedium++
			case "low":
				m.OpenLow++
			}
		} else if f.ResolvedAt != nil && *f.ResolvedAt >= cutoffResolvedToday {
			m.ResolvedToday++
		}
	}
	return m
}

func scannerStatusToInfo(s state.ScannerStatus) ScannerInfo {
	return ScannerInfo{
		Name:      s.Category,
		State:     s.Status,
		ErrorText: s.ErrorText,
	}
}

func scannerStatusesToInfo(in []state.ScannerStatus) []ScannerInfo {
	out := make([]ScannerInfo, 0, len(in))
	for _, ss := range in {
		out = append(out, scannerStatusToInfo(ss))
	}
	return out
}

// hostCheck enforces strict Host-header validation: only requests
// presenting an exact "127.0.0.1:<port>" or "localhost:<port>" Host
// are served. This is the gold-standard DNS-rebinding mitigation
// (/plan-eng-review D16) — a webpage at evil.com whose DNS rebinds to
// 127.0.0.1 still sends Host: evil.com (it's the origin), which we
// reject.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Port lookup deferred to first request — the listener's Port
		// is the source of truth.
		expectedPort := s.Port()
		allowed := host == fmt.Sprintf("127.0.0.1:%d", expectedPort) ||
			host == fmt.Sprintf("localhost:%d", expectedPort)
		if !allowed {
			http.Error(w, "audr daemon: refusing request with unexpected Host header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireToken is the per-route auth middleware: every /api/* request
// must include ?t=<token> matching the daemon's per-startup token.
// Constant-time compare prevents timing-side-channel discovery.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("t")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "audr daemon: missing or invalid auth token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// isLoopbackHost returns true if host is a loopback address spelling
// we accept for binding. We deliberately keep this list short — any
// public-network listener for audr's dashboard would be a security
// regression.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}
