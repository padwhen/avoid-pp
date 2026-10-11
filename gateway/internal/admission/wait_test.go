package admission

import (
	"context"
	"testing"
	"time"
)

// Queue-wait instrumentation, added at C32.
//
// The number exists to separate "the provider is slow" from "we are
// overloaded", which look identical in end-to-end latency and have opposite
// remedies. A wrong wait number is worse than none, so the three ways it
// could be wrong are each asserted: counting requests that never waited,
// losing the waits of requests that gave up, and reporting a mean that hides
// the worst case.

func TestAnUncontendedRequestIsNotCountedAsWaiting(t *testing.T) {
	controller, err := New(Config{MaxActive: 2, MaxQueued: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()

	stats := controller.Stats()
	if stats.WaitCount != 0 {
		t.Errorf("WaitCount = %d, want 0 for a request that took a free slot", stats.WaitCount)
	}
	if stats.MeanWait() != 0 {
		t.Errorf("MeanWait = %s, want 0", stats.MeanWait())
	}
	// Diluting the mean across traffic that never waited would make a queue
	// look healthy at any contention, given enough uncontended requests.
	if stats.WaitTotal != 0 {
		t.Errorf("WaitTotal = %s, want 0", stats.WaitTotal)
	}
}

func TestAQueuedRequestRecordsItsWait(t *testing.T) {
	controller, err := New(Config{MaxActive: 1, MaxQueued: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	holder, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	const held = 40 * time.Millisecond
	admitted := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		release, acquireErr := controller.Acquire(context.Background())
		if acquireErr != nil {
			admitted <- -1
			return
		}
		release()
		admitted <- time.Since(started)
	}()

	time.Sleep(held)
	holder()

	observed := <-admitted
	if observed < 0 {
		t.Fatal("the queued request was refused")
	}

	stats := controller.Stats()
	if stats.WaitCount != 1 {
		t.Fatalf("WaitCount = %d, want 1", stats.WaitCount)
	}
	// Generous bounds: this asserts the clock is running and attributed to
	// the right request, not that the scheduler is punctual.
	if stats.MaxWait < held/2 {
		t.Errorf("MaxWait = %s, want at least %s", stats.MaxWait, held/2)
	}
	if stats.MaxWait > observed+time.Second {
		t.Errorf("MaxWait = %s, longer than the caller observed (%s)", stats.MaxWait, observed)
	}
	if stats.MeanWait() != stats.WaitTotal {
		t.Errorf("MeanWait = %s, want %s for a single sample", stats.MeanWait(), stats.WaitTotal)
	}
}

func TestAnAbandonedWaitIsStillRecorded(t *testing.T) {
	// The failure this prevents: dropping the waits of requests that gave up
	// would make the queue look healthiest exactly when it is worst, because
	// the abandoned waits are the long ones.
	controller, err := New(Config{MaxActive: 1, MaxQueued: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	holder, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer holder()

	const budget = 30 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	if _, err := controller.Acquire(ctx); err == nil {
		t.Fatal("Acquire succeeded while the only slot was held")
	}

	stats := controller.Stats()
	if stats.WaitCount != 1 {
		t.Errorf("WaitCount = %d, want 1 for the abandoned wait", stats.WaitCount)
	}
	if stats.MaxWait < budget/2 {
		t.Errorf("MaxWait = %s, want at least %s", stats.MaxWait, budget/2)
	}
	if stats.Cancelled != 1 {
		t.Errorf("Cancelled = %d, want 1", stats.Cancelled)
	}
}

func TestARefusedRequestDidNotWait(t *testing.T) {
	// A full queue refuses immediately, so there is no wait to record and
	// counting one would inflate the mean with zeroes.
	controller, err := New(Config{MaxActive: 1, MaxQueued: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	holder, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer holder()

	if _, err := controller.Acquire(context.Background()); err != ErrQueueFull {
		t.Fatalf("Acquire error = %v, want ErrQueueFull", err)
	}
	if stats := controller.Stats(); stats.WaitCount != 0 {
		t.Errorf("WaitCount = %d, want 0 for an immediate refusal", stats.WaitCount)
	}
}

func TestMaxWaitSurvivesAShorterLaterWait(t *testing.T) {
	// A high-water mark, not a last-value gauge: a mean plus a recent sample
	// hides exactly the request that timed out.
	controller, err := New(Config{MaxActive: 1, MaxQueued: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, held := range []time.Duration{40 * time.Millisecond, 5 * time.Millisecond} {
		holder, err := controller.Acquire(context.Background())
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		done := make(chan struct{})
		go func() {
			release, acquireErr := controller.Acquire(context.Background())
			if acquireErr == nil {
				release()
			}
			close(done)
		}()
		time.Sleep(held)
		holder()
		<-done
	}

	if stats := controller.Stats(); stats.MaxWait < 20*time.Millisecond {
		t.Errorf("MaxWait = %s, want the earlier long wait to survive", stats.MaxWait)
	}
}
