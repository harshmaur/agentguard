// Package updater polls GitHub Releases for newer audr versions and
// surfaces "update available" hints to the daemon's dashboard.
//
// This is foundational for shipping rule updates daily without
// requiring users to know audr has new versions out. The dashboard
// renders a banner; the user clicks through to the release page (or,
// in a future slice, runs `audr daemon upgrade` to self-replace).
//
// Design notes:
//
//   - One HTTPS request per poll (the GitHub Releases "latest"
//     endpoint, public, no auth). Unauthenticated rate limit is
//     60 req/hour per IP; we poll once per 24h by default so we
//     stay well under.
//
//   - Results are cached to disk under <State>/update-check.json so
//     daemon restarts don't re-poll. Cache TTL matches the poll
//     interval; a write happens on every poll regardless so the
//     "no update available" answer also gets stored (avoids
//     hammering on restart loops).
//
//   - This is the ONLY outbound network call the daemon makes
//     proactively. Per [[feedback_no_telemetry]] we send no
//     identifying data — just a vanilla User-Agent.
package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Available reports an update the user could install. nil-returning
// Latest() means no update available (or check hasn't run yet — the
// distinction doesn't matter for the dashboard banner case).
type Available struct {
	Version     string `json:"version"`      // "v0.3.0" — tag name from GitHub
	URL         string `json:"url"`          // html_url of the release
	PublishedAt string `json:"published_at"` // RFC3339 from GitHub
}

// Options configures Checker. CurrentVersion is required; everything
// else has production defaults.
type Options struct {
	// CurrentVersion is the running audr binary version (passed from
	// main.Version). The checker compares this against the latest
	// release tag to decide whether to surface an update banner.
	CurrentVersion string

	// Owner / Repo identify the GitHub repo to poll. Defaults to
	// harshmaur / audr.
	Owner string
	Repo  string

	// CacheDir is where update-check.json lives. Typically
	// daemon.Paths.State.
	CacheDir string

	// PollInterval is how often the background loop hits GitHub.
	// Defaults to 24h.
	PollInterval time.Duration

	// Client overrides the HTTP client (test injection). Defaults to
	// a 10-second-timeout client.
	Client *http.Client

	// Now overrides the time source (test injection). Defaults to
	// time.Now.
	Now func() time.Time
}

const (
	defaultOwner    = "harshmaur"
	defaultRepo     = "audr"
	defaultInterval = 24 * time.Hour
	cacheFilename   = "update-check.json"
)

// Checker is a daemon subsystem that periodically polls GitHub
// Releases and stores the result. Implements daemon.Subsystem (Run +
// Close).
type Checker struct {
	opts  Options
	mu    sync.RWMutex
	state cacheRecord
	// dirty signals "we have an update worth telling about" — the
	// server checks this on snapshot. atomic so reads don't block.
	hasUpdate atomic.Bool
}

// cacheRecord is what we persist to update-check.json. Keep this
// small: the dashboard only needs Latest, and the rest is for
// poll-throttling.
type cacheRecord struct {
	LastChecked time.Time  `json:"last_checked"`
	Latest      *Available `json:"latest,omitempty"`
}

// New constructs a Checker with defaults filled in. The constructor
// loads any cached state from disk so the dashboard banner doesn't
// blank between daemon restarts.
func New(opts Options) (*Checker, error) {
	if opts.CurrentVersion == "" {
		return nil, errors.New("updater: CurrentVersion is required")
	}
	if opts.CacheDir == "" {
		return nil, errors.New("updater: CacheDir is required")
	}
	if opts.Owner == "" {
		opts.Owner = defaultOwner
	}
	if opts.Repo == "" {
		opts.Repo = defaultRepo
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultInterval
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &Checker{opts: opts}
	if rec, ok := c.readCache(); ok {
		c.state = rec
		if rec.Latest != nil && IsNewer(opts.CurrentVersion, rec.Latest.Version) {
			c.hasUpdate.Store(true)
		}
	}
	return c, nil
}

// Name implements daemon.Subsystem.
func (c *Checker) Name() string { return "updater" }

// Run implements daemon.Subsystem. Polls immediately at startup (if
// cache is stale), then on the PollInterval ticker until ctx is
// cancelled. Errors from a single poll attempt are logged-and-skipped:
// the daemon never crashes because GitHub is temporarily unreachable.
func (c *Checker) Run(ctx context.Context) error {
	// Initial poll: only if cache is older than the interval. Avoids
	// a network call on every daemon restart in dev.
	if c.cacheStale() {
		if err := c.pollOnce(ctx); err != nil {
			// First-poll failures are common (no network, behind
			// captive portal, etc.) — log to stderr would be noisy;
			// just continue and let the ticker retry later.
			_ = err
		}
	}

	ticker := time.NewTicker(c.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = c.pollOnce(ctx)
		}
	}
}

// Close implements daemon.Subsystem.
func (c *Checker) Close() error { return nil }

// Latest returns the cached "update available" record, or nil. Safe
// for concurrent reads from the HTTP handler hot-path.
func (c *Checker) Latest() *Available {
	if !c.hasUpdate.Load() {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.state.Latest == nil {
		return nil
	}
	cp := *c.state.Latest
	return &cp
}

// pollOnce hits GitHub, parses the response, and persists.
func (c *Checker) pollOnce(ctx context.Context) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		c.opts.Owner, c.opts.Repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	// GitHub recommends the v3 Accept header for stability + a UA.
	// No identifying info per [[feedback_no_telemetry]].
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "audr-daemon")
	resp, err := c.opts.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		// No releases yet — treat as "no update available", refresh
		// timestamp so we don't re-poll for the next interval.
		c.persistResult(nil)
		return nil
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("updater: GitHub returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return err
	}
	var rel struct {
		TagName     string `json:"tag_name"`
		HTMLURL     string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return err
	}
	// Skip drafts + prereleases. The releases API's "/latest"
	// endpoint shouldn't return them, but defense-in-depth.
	if rel.Draft || rel.Prerelease || rel.TagName == "" {
		c.persistResult(nil)
		return nil
	}
	avail := &Available{
		Version:     rel.TagName,
		URL:         rel.HTMLURL,
		PublishedAt: rel.PublishedAt,
	}
	c.persistResult(avail)
	return nil
}

func (c *Checker) persistResult(latest *Available) {
	c.mu.Lock()
	c.state = cacheRecord{
		LastChecked: c.opts.Now(),
		Latest:      latest,
	}
	c.mu.Unlock()
	c.hasUpdate.Store(latest != nil && IsNewer(c.opts.CurrentVersion, latest.Version))
	c.writeCache()
}

func (c *Checker) cacheStale() bool {
	c.mu.RLock()
	last := c.state.LastChecked
	c.mu.RUnlock()
	if last.IsZero() {
		return true
	}
	return c.opts.Now().Sub(last) >= c.opts.PollInterval
}

func (c *Checker) cachePath() string {
	return filepath.Join(c.opts.CacheDir, cacheFilename)
}

func (c *Checker) readCache() (cacheRecord, bool) {
	b, err := os.ReadFile(c.cachePath())
	if err != nil {
		return cacheRecord{}, false
	}
	var rec cacheRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return cacheRecord{}, false
	}
	return rec, true
}

func (c *Checker) writeCache() {
	c.mu.RLock()
	rec := c.state
	c.mu.RUnlock()
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	// Atomic temp + rename so a crash during write doesn't leave
	// partial JSON the next startup can't parse.
	tmp := c.cachePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.cachePath())
}

// IsNewer compares two version tags. Both are normalized by stripping
// a leading "v"; then split on "." and compared numerically. Non-
// numeric segments (e.g., "v0.3.0-alpha.1") compare lexicographically
// AFTER the numeric prefix is exhausted, so "0.3.0" < "0.3.0-rc1" by
// this comparator — but that's fine for our use because the dashboard
// banner only fires when candidate > current; pre-release tags coming
// from GitHub /latest are already filtered by the Prerelease flag.
//
// Returns true iff candidate > current. Returns false on parse
// ambiguity to avoid surfacing spurious banners.
func IsNewer(current, candidate string) bool {
	cur := splitVersion(strings.TrimPrefix(current, "v"))
	can := splitVersion(strings.TrimPrefix(candidate, "v"))
	if len(cur) == 0 || len(can) == 0 {
		return false
	}
	n := len(cur)
	if len(can) > n {
		n = len(can)
	}
	for i := 0; i < n; i++ {
		a, b := getSegment(cur, i), getSegment(can, i)
		if a == b {
			continue
		}
		// Numeric vs numeric: int compare.
		ai, aErr := strconv.Atoi(a)
		bi, bErr := strconv.Atoi(b)
		if aErr == nil && bErr == nil {
			return bi > ai
		}
		// Anything else: lexicographic. Numeric beats non-numeric
		// (so "0.3.0" > "0.3.0-rc1"). This shouldn't matter in
		// practice because /latest filters prereleases.
		if aErr == nil {
			return false // a numeric, b non-numeric → a > b
		}
		if bErr == nil {
			return true // b numeric, a non-numeric → b > a
		}
		return b > a
	}
	return false
}

func splitVersion(v string) []string {
	if v == "" {
		return nil
	}
	// Replace "-" with "." so "0.3.0-rc1" splits into [0 3 0 rc1].
	return strings.Split(strings.ReplaceAll(v, "-", "."), ".")
}

func getSegment(segs []string, i int) string {
	if i < len(segs) {
		return segs[i]
	}
	return "0" // missing segment treated as zero (so "0.3" == "0.3.0")
}
