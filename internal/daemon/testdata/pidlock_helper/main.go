// pidlock_helper is a tiny test binary used by daemon_test to verify
// cross-process PID-lock contention. It acquires the lock at argv[1],
// signals "ready" on stdout, then blocks until killed.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pidlock_helper <path>")
		os.Exit(2)
	}
	lock, err := daemon.AcquirePIDLock(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire: %v\n", err)
		os.Exit(1)
	}
	defer lock.Release()

	// Signal parent that we have the lock. Newline is the read terminator.
	fmt.Println("ready")
	// stdout is line-buffered by default for pipes; force a flush so the
	// parent sees the line immediately.
	_ = os.Stdout.Sync()

	// Block until killed.
	for {
		time.Sleep(time.Second)
	}
}
