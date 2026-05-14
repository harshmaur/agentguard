package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	// modernc.org/sqlite registers itself as the "sqlite" driver.
	_ "modernc.org/sqlite"
)

// removeDBFiles deletes the SQLite DB file plus its WAL + shm
// sidecars. Used by Open's self-healing path when migrations fail
// against an existing DB. Missing files are not an error — we just
// want a clean slate, and the next Open() recreates everything.
func removeDBFiles(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		p := path + suffix
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// Store is audr's persistent SQLite-backed state. Implements
// daemon.Subsystem so it slots into Lifecycle.
//
// Concurrency model (eng-review D12):
//
//   - SQLite opened in WAL mode (concurrent reads + one writer).
//   - All writes funnel through a single goroutine that drains a
//     buffered channel of writeRequest. Public Write APIs send and
//     wait for completion via a per-request done channel.
//   - Reads use the *sql.DB connection pool directly — multiple
//     concurrent readers are safe in WAL.
//
// Lifecycle:
//
//   - Open(): opens DB, applies migrations, reconciles crashed scans.
//   - Run(ctx): blocks running the writer goroutine until ctx
//     cancels. Returns nil on graceful shutdown.
//   - Close(): drains pending writes, closes the DB handle, closes
//     all subscriber channels.
type Store struct {
	opts Options
	db   *sql.DB

	// writeQueue is buffered so producers (scan workers, watch loop,
	// retention sweeper) don't block on a slow writer. 1024 deep —
	// holds an entire small scan's worth of finding writes without
	// backpressure.
	writeQueue chan writeRequest

	// Subscribers are SSE-shaped pub-sub. Each subscriber has its own
	// buffered channel (no slow-consumer blocks others). On overflow
	// (subscriber not draining) we close their channel so the server
	// can detect + reconnect.
	subsMu sync.RWMutex
	subs   map[*subscriber]struct{}

	// writerDone closes when the writer goroutine exits. Close()
	// waits on it.
	writerDone chan struct{}

	// closeOnce protects Close from being called more than once
	// (Subsystem.Close is best-effort idempotent per Lifecycle's
	// contract).
	closeOnce sync.Once
	closed    chan struct{}
}

// Options configures a Store.
type Options struct {
	// Path is the SQLite DB file path. Typically Paths.State + "audr.db".
	Path string

	// WriteBuffer is the depth of the writer goroutine's input channel.
	// Defaults to 1024. Higher == more headroom against bursty writes;
	// lower == tighter backpressure on producers.
	WriteBuffer int

	// SubscriberBuffer is the per-SSE-subscriber channel depth.
	// Defaults to 256. Bigger than typical SSE redraw cadence so a
	// slow client doesn't immediately overflow; small enough that we
	// don't pin a megabyte per dead tab.
	SubscriberBuffer int
}

// Open initializes the store: opens SQLite in WAL mode, applies
// schema migrations, reconciles any scans left in_progress by a
// previous crash. The Run() method must be called to start the
// writer goroutine; until then, write APIs will block.
//
// Self-healing fallback: if migrations fail (corrupt DB, version
// drift from a downgrade, partial-write file from a crash), Open
// nukes the DB file + sidecars (-wal, -shm) and retries from
// scratch. The daemon's state is reproducible from the
// filesystem, so losing the SQLite DB just means the next scan
// will re-detect everything as new findings. ResetForRebuild
// returns true via the error when a rebuild happened so callers
// can surface a banner / log message.
func Open(opts Options) (*Store, error) {
	s, err := openOnce(opts)
	if err == nil {
		return s, nil
	}
	// First attempt failed. Treat any migration/open error as a
	// corrupted-DB signal and try once more with a fresh file.
	// Failing twice is genuinely fatal (file-permission issues,
	// path unwritable, etc.) and we bubble up the second error.
	if rmErr := removeDBFiles(opts.Path); rmErr != nil {
		return nil, fmt.Errorf("state: open failed (%v) and DB cleanup failed (%w)", err, rmErr)
	}
	s2, err2 := openOnce(opts)
	if err2 != nil {
		return nil, fmt.Errorf("state: open failed twice, second after rebuild: %w (first: %v)", err2, err)
	}
	// Best-effort log: tests inject a stub logger via Options
	// (none yet); for now we use the package-level fmt to stderr
	// so the daemon log records the rebuild. The daemon's slog
	// handler picks up stderr.
	fmt.Fprintf(os.Stderr, "audr state: migrations failed (%v) — DB rebuilt from scratch; next scan will repopulate findings\n", err)
	return s2, nil
}

// openOnce is the actual open logic; Open wraps it with a single
// retry-after-nuke fallback. Factored out so the retry path is
// trivially correct.
func openOnce(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("state: Options.Path is required")
	}
	if opts.WriteBuffer <= 0 {
		opts.WriteBuffer = 1024
	}
	if opts.SubscriberBuffer <= 0 {
		opts.SubscriberBuffer = 256
	}

	// Pragmas embedded in the DSN per eng-review D12:
	//   - WAL: concurrent reads + one writer
	//   - synchronous=NORMAL: durable enough; fast enough
	//   - busy_timeout=5s: wait on writer contention rather than
	//     immediately erroring with SQLITE_BUSY
	//   - foreign_keys: ON for the scan_id FKs
	//   - cache_size: 8MB page cache
	//   - temp_store: in-memory temp tables
	q := url.Values{}
	q.Set("_pragma", "journal_mode=WAL")
	q.Add("_pragma", "synchronous=NORMAL")
	q.Add("_pragma", "busy_timeout=5000")
	q.Add("_pragma", "foreign_keys=ON")
	q.Add("_pragma", "temp_store=MEMORY")
	q.Add("_pragma", "cache_size=-8192")

	dsn := opts.Path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: open %s: %w", opts.Path, err)
	}
	// Cap connection pool: WAL allows concurrent reads but writes
	// serialize. modernc.org/sqlite handles internal locking, but
	// extra connections add overhead without parallelism benefit.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: ping %s: %w", opts.Path, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runMigrations(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: migrations: %w", err)
	}

	s := &Store{
		opts:       opts,
		db:         db,
		writeQueue: make(chan writeRequest, opts.WriteBuffer),
		subs:       make(map[*subscriber]struct{}),
		writerDone: make(chan struct{}),
		closed:     make(chan struct{}),
	}

	// Crash-recovery (Lifecycle Concerns): any scan still in_progress
	// at startup means the previous daemon died mid-scan. Mark them
	// crashed; subsequent scans resume with a fresh ID.
	if err := s.reconcileCrashedScans(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: reconcile crashed scans: %w", err)
	}

	// Start the writer goroutine immediately so the store is fully
	// usable for writes after Open. Run() (called by Lifecycle) just
	// blocks until ctx cancels; Close() drains the writer.
	go s.writerLoop()

	return s, nil
}

// Name implements daemon.Subsystem.
func (s *Store) Name() string { return "state" }

// Run implements daemon.Subsystem. Blocks until ctx cancels. The
// writer goroutine started in Open is doing the real work in the
// background; this just keeps the subsystem alive in the errgroup.
func (s *Store) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close implements daemon.Subsystem. Stops accepting new writes by
// closing the queue, waits for the writer to drain, closes all
// subscribers, then closes the DB. Idempotent.
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		close(s.writeQueue)
		<-s.writerDone

		s.subsMu.Lock()
		for sub := range s.subs {
			close(sub.ch)
		}
		s.subs = nil
		s.subsMu.Unlock()

		err = s.db.Close()
	})
	return err
}

// reconcileCrashedScans is idempotent: marks any in_progress scan as
// crashed and stamps a completed_at so the row falls under retention's
// 90-day window.
func (s *Store) reconcileCrashedScans(ctx context.Context) error {
	now := NowUnix()
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET status='crashed', completed_at=?
		WHERE status='in_progress'
	`, now)
	return err
}

// writeRequest is the message a public write API sends to the
// writer goroutine. The fn closes over the actual work; done
// signals completion (and carries any error back).
type writeRequest struct {
	fn   func(*sql.Tx) error
	done chan error
	// emit, when non-nil, is published to subscribers AFTER the
	// transaction commits. Bundling emit into the request guarantees
	// "no one sees the event before the row is durable."
	emit []Event
}

// writerLoop drains the writeQueue until it closes. Each request
// runs in its own SQLite transaction so failures isolate. Events
// are published only after commit.
func (s *Store) writerLoop() {
	defer close(s.writerDone)
	for req := range s.writeQueue {
		err := s.runWrite(req.fn)
		req.done <- err
		if err == nil {
			for _, e := range req.emit {
				s.publish(e)
			}
		}
	}
}

func (s *Store) runWrite(fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// submitWrite hands a request to the writer goroutine and blocks for
// the result. Returns ErrStoreClosed if Close already ran.
func (s *Store) submitWrite(fn func(*sql.Tx) error, emit ...Event) error {
	select {
	case <-s.closed:
		return ErrStoreClosed
	default:
	}
	req := writeRequest{fn: fn, done: make(chan error, 1), emit: emit}
	select {
	case s.writeQueue <- req:
	case <-s.closed:
		return ErrStoreClosed
	}
	return <-req.done
}

// ErrStoreClosed is returned by write operations when Close() ran
// first. Callers should treat this as the store going away — usually
// a sign of orderly daemon shutdown, not a real failure to surface.
var ErrStoreClosed = errors.New("state: store is closed")

// NowUnix is the store's clock. Swappable in tests so deterministic
// timestamps make golden assertions readable.
var NowUnix = func() int64 { return time.Now().Unix() }
