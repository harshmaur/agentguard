package watch

import (
	"testing"
	"time"
)

func TestQuiescenceGateFiresOnceAfterBurst(t *testing.T) {
	gate := NewQuiescenceGate(100 * time.Millisecond)

	// Burst of bumps. The gate must NOT fire while bumps continue.
	for i := 0; i < 20; i++ {
		gate.Bump("")
		time.Sleep(20 * time.Millisecond) // shorter than stability window
	}

	// At this point we've been bumping for ~400ms, with no quiet
	// interval longer than 20ms — no trigger should have fired.
	select {
	case <-gate.Triggers():
		t.Fatal("gate fired during burst; quiescence violated")
	default:
	}

	// Stop bumping. After stability + a little jitter, exactly one
	// trigger should fire.
	select {
	case <-gate.Triggers():
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("gate did not fire after burst settled")
	}

	// No further trigger should fire without new Bumps.
	select {
	case <-gate.Triggers():
		t.Fatal("gate fired again without new Bump")
	case <-time.After(200 * time.Millisecond):
		// good
	}
}

func TestQuiescenceGateDefaultsStability(t *testing.T) {
	// Zero / negative stability → default 5s. Verify the default path
	// runs without panicking; we don't wait 5s.
	gate := NewQuiescenceGate(0)
	if gate.stability != 5*time.Second {
		t.Errorf("default stability = %v, want 5s", gate.stability)
	}
	if gate := NewQuiescenceGate(-1); gate.stability != 5*time.Second {
		t.Errorf("negative stability = %v, want 5s", gate.stability)
	}
}

func TestQuiescenceGateCloseStopsFiring(t *testing.T) {
	gate := NewQuiescenceGate(100 * time.Millisecond)
	gate.Bump("")
	_ = gate.Close()

	// Even after stability elapses, no trigger.
	select {
	case <-gate.Triggers():
		t.Fatal("closed gate still fired")
	case <-time.After(300 * time.Millisecond):
		// good
	}

	// Bumping a closed gate is a no-op (no panic).
	gate.Bump("")
	// Double-close is also safe.
	if err := gate.Close(); err != nil {
		t.Errorf("double-close err = %v, want nil", err)
	}
}

func TestQuiescenceGateConcurrentBumpsCoalesce(t *testing.T) {
	// 100 concurrent bumps — should still produce exactly one trigger
	// after stability.
	gate := NewQuiescenceGate(100 * time.Millisecond)
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			gate.Bump("")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	// Wait for stability.
	select {
	case <-gate.Triggers():
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("gate did not fire")
	}

	// Drain channel — should have at most one queued event from
	// the burst (we allow some imprecision under high contention but
	// it should never be >2).
	extra := 0
loop:
	for {
		select {
		case <-gate.Triggers():
			extra++
		case <-time.After(150 * time.Millisecond):
			break loop
		}
	}
	if extra > 1 {
		t.Errorf("gate fired %d extra times after burst, want 0-1", extra)
	}
}
