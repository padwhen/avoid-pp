// C22: capping inference concurrency and queued work.
package admission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func build(t *testing.T, active, queued int) *Controller {
	t.Helper()
	controller, err := New(Config{MaxActive: active, MaxQueued: queued})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return controller
}

// C22-AC1: the configured concurrency is never exceeded.
func TestActiveNeverExceedsTheLimit(t *testing.T) {
	const active = 3
	controller := build(t, active, 0)

	releases := make([]func(), 0, active)
	for i := range active {
		release, err := controller.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v", i+1, err)
		}
		releases = append(releases, release)
	}

	if stats := controller.Stats(); stats.Active != active {
		t.Errorf("Active = %d, want %d", stats.Active, active)
	}

	// With no queue, the next request is refused rather than waiting.
	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Errorf("error = %v, want ErrQueueFull", err)
	}

	// Releasing one admits exactly one more.
	releases[0]()
	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Errorf("error = %v, want ErrQueueFull after refilling the slot", err)
	}
	release()
	for _, r := range releases[1:] {
		r()
	}

	if stats := controller.Stats(); stats.Active != 0 {
		t.Errorf("Active = %d after releasing everything, want 0", stats.Active)
	}
	if stats := controller.Stats(); stats.PeakActive != active {
		t.Errorf("PeakActive = %d, want %d", stats.PeakActive, active)
	}
}

// C22-AC1: the queue length is never exceeded either.
func TestQueueNeverExceedsTheLimit(t *testing.T) {
	const (
		active = 1
		queued = 2
	)
	controller := build(t, active, queued)

	// Fill the single slot.
	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Fill the queue. These block, so they run in goroutines whose outcome is
	// collected after the slot frees.
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []error
	)
	for range queued {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := controller.Acquire(context.Background())
			if r != nil {
				r()
			}
			mu.Lock()
			results = append(results, err)
			mu.Unlock()
		}()
	}

	// Wait for both to be queued, rather than sleeping a guessed interval.
	waitFor(t, func() bool { return controller.Stats().Queued == queued })

	// The queue is full, so the next arrival is shed immediately.
	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Errorf("error = %v, want ErrQueueFull with a full queue", err)
	}
	if stats := controller.Stats(); stats.Queued > queued {
		t.Errorf("Queued = %d, over the limit of %d", stats.Queued, queued)
	}

	release()
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("queued request %d failed: %v", i, err)
		}
	}
	if stats := controller.Stats(); stats.PeakQueued != queued {
		t.Errorf("PeakQueued = %d, want %d", stats.PeakQueued, queued)
	}
}

// C22-AC2: a cancellation while queued releases the place in the queue.
func TestCancellationWhileQueuedReleasesThePlace(t *testing.T) {
	controller := build(t, 1, 1)

	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	queueErr := make(chan error, 1)
	go func() {
		_, err := controller.Acquire(ctx)
		queueErr <- err
	}()

	waitFor(t, func() bool { return controller.Stats().Queued == 1 })

	// The queue is full while that one waits.
	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("error = %v, want ErrQueueFull", err)
	}

	cancel()
	if err := <-queueErr; !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}

	// The place is given back, so a new arrival can queue.
	waitFor(t, func() bool { return controller.Stats().Queued == 0 })
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := controller.Acquire(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the deadline rather than a full queue", err)
	}
}

// C22-AC2: a deadline that passes while queued releases the place too.
func TestDeadlineWhileQueuedReleasesThePlace(t *testing.T) {
	controller := build(t, 1, 4)

	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	if _, err := controller.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
	waitFor(t, func() bool { return controller.Stats().Queued == 0 })
	if stats := controller.Stats(); stats.Cancelled != 1 {
		t.Errorf("Cancelled = %d, want 1", stats.Cancelled)
	}
}

// An already-finished context must not take a slot it cannot use.
func TestAnExpiredContextTakesNoSlot(t *testing.T) {
	controller := build(t, 2, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := controller.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if stats := controller.Stats(); stats.Active != 0 {
		t.Errorf("Active = %d, want 0; an expired context took capacity", stats.Active)
	}
}

// A double release would return a slot nobody held, raising the effective
// limit permanently. That is a silent, cumulative failure, so release is
// made idempotent rather than merely documented.
func TestDoubleReleaseCannotRaiseTheLimit(t *testing.T) {
	controller := build(t, 1, 0)

	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	for range 5 {
		release()
	}

	// Exactly one slot should be available, not six.
	first, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	defer first()

	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Error("a repeated release raised the effective concurrency limit")
	}
}

// Zero queue is a legal configuration: refuse immediately rather than wait.
func TestZeroQueueRefusesImmediately(t *testing.T) {
	controller := build(t, 1, 0)

	release, err := controller.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	started := time.Now()
	if _, err := controller.Acquire(context.Background()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("error = %v, want ErrQueueFull", err)
	}
	// It must not have waited. A generous bound, since this only needs to
	// distinguish "returned immediately" from "blocked".
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Errorf("refusal took %v; a zero queue must not wait", elapsed)
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	for name, cfg := range map[string]Config{
		"zero active":     {MaxActive: 0, MaxQueued: 1},
		"negative active": {MaxActive: -1, MaxQueued: 1},
		"negative queued": {MaxActive: 1, MaxQueued: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("New() error = nil, want error")
			}
		})
	}
	if _, err := New(Config{MaxActive: 1, MaxQueued: 0}); err != nil {
		t.Errorf("one slot and no queue was rejected: %v", err)
	}
}

// C22-AC1 under load: the whole point of the peak counters.
//
// Many goroutines contend for a small number of slots, and the invariant is
// that the observed maximums never exceed what was configured. A sampled
// Stats() call could miss an overshoot; the peaks cannot.
func TestConcurrentLoadNeverExceedsEitherBound(t *testing.T) {
	const (
		active     = 4
		queued     = 8
		goroutines = 200
	)
	controller := build(t, active, queued)

	// Tracks concurrency independently of the controller's own counters, so
	// the assertion does not trust the thing it is testing.
	var (
		observed atomic.Int64
		peak     atomic.Int64
		admitted atomic.Int64
		shed     atomic.Int64
		wg       sync.WaitGroup
	)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			release, err := controller.Acquire(ctx)
			if err != nil {
				shed.Add(1)
				return
			}
			defer release()

			admitted.Add(1)
			current := observed.Add(1)
			for {
				high := peak.Load()
				if current <= high || peak.CompareAndSwap(high, current) {
					break
				}
			}
			// Hold the slot briefly, so contention is real rather than
			// theoretical.
			time.Sleep(time.Millisecond)
			observed.Add(-1)
		}()
	}
	wg.Wait()

	if high := peak.Load(); high > active {
		t.Errorf("observed %d concurrent holders, over the limit of %d", high, active)
	}
	stats := controller.Stats()
	if stats.PeakActive > active {
		t.Errorf("PeakActive = %d, over the limit of %d", stats.PeakActive, active)
	}
	if stats.PeakQueued > queued {
		t.Errorf("PeakQueued = %d, over the limit of %d", stats.PeakQueued, queued)
	}
	if stats.Active != 0 || stats.Queued != 0 {
		t.Errorf("not drained: active=%d queued=%d", stats.Active, stats.Queued)
	}
	if total := admitted.Load() + shed.Load(); total != goroutines {
		t.Errorf("accounted for %d of %d requests", total, goroutines)
	}
	t.Logf("admitted %d, shed %d, peak active %d, peak queued %d",
		admitted.Load(), shed.Load(), stats.PeakActive, stats.PeakQueued)
}

// Capacity must not drain over time when callers keep giving up. A slot
// leaked on cancellation makes the service die slowly, at a rate set by how
// often clients disconnect — which is the kind of failure that looks like a
// memory leak and is not one.
func TestCapacityDoesNotDrainUnderRepeatedCancellation(t *testing.T) {
	const active = 2
	controller := build(t, active, 4)

	for round := range 200 {
		ctx, cancel := context.WithCancel(context.Background())
		release, err := controller.Acquire(ctx)
		if err != nil {
			t.Fatalf("round %d: acquire failed, capacity has drained: %v", round, err)
		}
		// The caller goes away mid-call, then the handler releases.
		cancel()
		release()
	}

	// Full capacity must still be available.
	releases := make([]func(), 0, active)
	for i := range active {
		release, err := controller.Acquire(context.Background())
		if err != nil {
			t.Fatalf("slot %d unavailable after 200 cancelled rounds: %v", i+1, err)
		}
		releases = append(releases, release)
	}
	for _, r := range releases {
		r()
	}
}

// waitFor polls a condition instead of sleeping a guessed interval, so the
// test is neither slow nor timing-dependent.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within the deadline")
}
