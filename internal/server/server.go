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

	"github.com/harshmaur/audr/internal/daemon"
)

//go:embed dashboard
var dashboardFS embed.FS

// Options configures a server.Server. Most callers can leave fields at
// zero — the constructor fills in production defaults.
type Options struct {
	// Paths controls where the state file (port + token) lives.
	// Required.
	Paths daemon.Paths

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

	// shutdownTimeout caps how long Close() waits for in-flight
	// requests after the listener is closed. 5s default.
	shutdownTimeout time.Duration
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

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	findings := demoFindings()
	resp := SnapshotResponse{
		Findings: findings,
		Metrics:  demoMetrics(findings),
		Daemon: DaemonInfo{
			State:   "RUN",
			Version: s.opts.Version,
		},
		Scanners: []ScannerInfo{
			{Name: "osv-scanner", State: "ok", FoundVersion: "1.8.2", MinVersion: "1.8.0"},
			{Name: "trufflehog", State: "ok", FoundVersion: "3.81.0", MinVersion: "3.63.0"},
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRemediation(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	rem, ok := demoRemediation(fp)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no remediation for fingerprint " + fp})
		return
	}
	writeJSON(w, http.StatusOK, rem)
}

// handleEvents sends one initial "snapshot ready" SSE frame so the
// browser establishes the stream, then heartbeats every 15s. Phase 2
// visual slice doesn't push live deltas — that's Phase 3+ once the
// watch+poll engine produces them. The retry hint enables the
// exponential backoff Phase 2 designed.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// retry: in milliseconds — server-driven exponential backoff
	// (per /plan-eng-review D2). 5s initial, dashboard JS doubles
	// per failure up to 60s.
	_, _ = fmt.Fprintf(w, "retry: 5000\n\n")
	_, _ = fmt.Fprintf(w, "event: hello\ndata: {\"v\":1}\n\n")
	flusher.Flush()

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-tick.C:
			_, err := fmt.Fprintf(w, "event: heartbeat\ndata: {\"ts\":%d}\n\n", t.Unix())
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
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
