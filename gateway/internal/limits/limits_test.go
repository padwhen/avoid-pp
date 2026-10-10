// C21: bounded per-caller rate limits.
//
// Every test drives the limiter with an explicit time rather than the wall
// clock. rate.Limiter takes a time on every method for exactly this reason,
// and a limiter test that sleeps is slow when it passes and flaky when it
// fails.
package limits

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func bucket(perSecond float64, burst int) Bucket {
	return Bucket{PerSecond: perSecond, Burst: burst}
}

func build(t *testing.T, cfg Config, callers ...string) *Limiter {
	t.Helper()
	if len(callers) == 0 {
		callers = []string{"lukea"}
	}
	limiter, err := New(cfg, callers)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return limiter
}

// C21-AC1: burst admits a batch, then the sustained rate takes over.
func TestBurstThenSustainedRate(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(1, 5),
		Global:          bucket(100, 100),
		Unauthenticated: bucket(100, 100),
	})

	// Five at the same instant: the whole burst.
	for i := range 5 {
		if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}

	// The sixth, still at the same instant, has nothing left.
	sixth := limiter.AllowCaller("lukea", epoch)
	if sixth.Allowed {
		t.Fatal("a sixth request was admitted with a burst of 5")
	}
	if sixth.Scope != ScopeCaller {
		t.Errorf("scope = %q, want caller", sixth.Scope)
	}
	// At one per second, the next token is a second away.
	if sixth.RetryAfter <= 0 || sixth.RetryAfter > time.Second {
		t.Errorf("RetryAfter = %v, want just under a second", sixth.RetryAfter)
	}

	// One second later exactly one token has refilled.
	if d := limiter.AllowCaller("lukea", epoch.Add(time.Second)); !d.Allowed {
		t.Error("no token after a full second at 1/s")
	}
	if d := limiter.AllowCaller("lukea", epoch.Add(time.Second)); d.Allowed {
		t.Error("two tokens refilled in one second at 1/s")
	}

	// And after five seconds the burst is back, but not more than the burst:
	// a bucket that kept filling while idle would hand out a huge batch to a
	// caller that had simply been quiet.
	later := epoch.Add(10 * time.Second)
	admitted := 0
	for range 20 {
		if limiter.AllowCaller("lukea", later).Allowed {
			admitted++
		}
	}
	if admitted != 5 {
		t.Errorf("after a long idle period %d requests were admitted, want 5", admitted)
	}
}

// C21-AC1: the retry hint is exact rather than a fixed guess.
func TestRetryAfterIsExact(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(2, 1), // one token every 500ms
		Global:          bucket(100, 100),
		Unauthenticated: bucket(100, 100),
	})

	if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
		t.Fatal("the first request was refused")
	}

	refused := limiter.AllowCaller("lukea", epoch)
	if refused.Allowed {
		t.Fatal("a second request was admitted with a burst of 1")
	}
	// Half a second at two per second.
	if refused.RetryAfter < 490*time.Millisecond || refused.RetryAfter > 510*time.Millisecond {
		t.Errorf("RetryAfter = %v, want about 500ms", refused.RetryAfter)
	}

	// Part-way through the interval the remaining wait has shrunk.
	partial := limiter.AllowCaller("lukea", epoch.Add(300*time.Millisecond))
	if partial.Allowed {
		t.Fatal("admitted before the interval elapsed")
	}
	if partial.RetryAfter > 210*time.Millisecond {
		t.Errorf("RetryAfter = %v, want about 200ms remaining", partial.RetryAfter)
	}
}

// A caller refused by the shared limit is told so with the global scope.
//
// Note the configuration is legal: global and per-caller limits are equal,
// which New accepts. The global scope is reachable not by making the shared
// limit tighter than a caller's, but by having two callers compete for it —
// one caller spends the shared budget and the other is refused while its own
// bucket is still full. That is the realistic shape of this refusal.
func TestGlobalLimitRefusesWithGlobalScope(t *testing.T) {
	const burst = 3
	limiter := build(t, Config{
		PerCaller:       bucket(1, burst),
		Global:          bucket(1, burst),
		Unauthenticated: bucket(100, 100),
	}, "lukea", "evals")

	// One caller spends the whole shared budget.
	for i := range burst {
		if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
			t.Fatalf("request %d was refused while the global bucket had capacity", i+1)
		}
	}

	// The other caller still has its own full burst, so the only thing that
	// can refuse it is the shared limit — and the scope says so, which is
	// what makes the log line useful when a caller complains about a 429 it
	// did not cause.
	for range 10 {
		refused := limiter.AllowCaller("evals", epoch)
		if refused.Allowed {
			t.Fatal("admitted past a drained global bucket")
		}
		if refused.Scope != ScopeGlobal {
			t.Fatalf("scope = %q, want global", refused.Scope)
		}
	}
}

// A request refused by the shared limit must not consume the caller's own
// tokens. Without the rollback in AllowCaller, one busy caller would throttle
// another twice over: once by the shared limit, and again by a bucket drained
// for requests that were never served.
func TestGlobalRefusalsDoNotDrainTheCallerBucket(t *testing.T) {
	const burst = 3
	limiter := build(t, Config{
		PerCaller:       bucket(1, burst),
		Global:          bucket(1, burst),
		Unauthenticated: bucket(100, 100),
	}, "lukea", "evals")

	// One caller drains the shared bucket.
	for range burst {
		if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
			t.Fatal("refused within the shared burst")
		}
	}

	// Twenty refusals for the second caller, all global-scoped.
	for range 20 {
		if d := limiter.AllowCaller("evals", epoch); d.Allowed {
			t.Fatal("admitted past the global limit")
		}
	}

	// The shared bucket refills at one per second. The second caller's own
	// bucket should still hold its full burst, so one request per second is
	// admitted for each of the next three seconds. If the refusals had been
	// charged to its bucket it would be empty and refilling at the same
	// 1/s, which this sequence would expose.
	for i := range burst {
		at := epoch.Add(time.Duration(i+1) * time.Second)
		if d := limiter.AllowCaller("evals", at); !d.Allowed {
			t.Errorf("request %d at +%v was refused; the caller bucket was drained by refusals",
				i+1, at.Sub(epoch))
		}
	}
}

// Callers are isolated from each other's traffic.
func TestCallersHaveSeparateBuckets(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(1, 2),
		Global:          bucket(100, 100),
		Unauthenticated: bucket(100, 100),
	}, "lukea", "evals")

	// Drain one caller entirely.
	for range 2 {
		if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
			t.Fatal("refused within the burst")
		}
	}
	if d := limiter.AllowCaller("lukea", epoch); d.Allowed {
		t.Fatal("admitted past the burst")
	}

	// The other is unaffected.
	for i := range 2 {
		if d := limiter.AllowCaller("evals", epoch); !d.Allowed {
			t.Errorf("request %d from an idle caller was refused", i+1)
		}
	}
}

// C21-AC2: the state cannot grow. Nothing is allocated per request, and an
// unknown name is refused rather than given a bucket.
func TestStateCannotGrow(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(100, 100),
		Global:          bucket(1e6, 1e6),
		Unauthenticated: bucket(1e6, 1e6),
	}, "lukea", "evals")

	before := limiter.BucketCount()
	if before != 4 {
		t.Fatalf("BucketCount() = %d, want 4 (two callers plus two shared)", before)
	}

	// Ten thousand distinct unknown caller names, which is what an attacker
	// would try if the map were filled on demand.
	for i := range 10_000 {
		name := fmt.Sprintf("attacker-%d", i)
		decision := limiter.AllowCaller(name, epoch)
		if decision.Allowed {
			t.Fatalf("an unconfigured caller %q was admitted", name)
		}
		if decision.Scope != ScopeUnknownCaller {
			t.Fatalf("scope = %q, want unknown_caller", decision.Scope)
		}
	}

	// A large volume of unauthenticated traffic, which shares one bucket and
	// is keyed by nothing.
	for range 10_000 {
		limiter.AllowUnauthenticated(epoch)
	}

	if after := limiter.BucketCount(); after != before {
		t.Errorf("BucketCount() grew from %d to %d", before, after)
	}
	if names := limiter.Callers(); len(names) != 2 {
		t.Errorf("Callers() = %v, want the two configured names", names)
	}
}

// Unauthenticated traffic shares one bucket, so it is bounded in aggregate
// without any per-source state.
func TestUnauthenticatedTrafficSharesOneBucket(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(1, 1),
		Global:          bucket(100, 100),
		Unauthenticated: bucket(1, 3),
	})

	for i := range 3 {
		if d := limiter.AllowUnauthenticated(epoch); !d.Allowed {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	refused := limiter.AllowUnauthenticated(epoch)
	if refused.Allowed {
		t.Fatal("admitted past the unauthenticated burst")
	}
	if refused.Scope != ScopeUnauthenticated {
		t.Errorf("scope = %q, want unauthenticated", refused.Scope)
	}

	// Authenticated traffic is untouched by an unauthenticated flood, which
	// is the property that makes one shared bucket acceptable.
	if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
		t.Error("an authenticated caller was refused after an unauthenticated flood")
	}
}

// A caller holding two keys mid-rotation must share one bucket. Two buckets
// would double its effective rate for the length of the rotation.
func TestARepeatedCallerNameSharesOneBucket(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(1, 2),
		Global:          bucket(100, 100),
		Unauthenticated: bucket(100, 100),
	}, "lukea", "lukea")

	if count := limiter.BucketCount(); count != 3 {
		t.Errorf("BucketCount() = %d, want 3 (one caller plus two shared)", count)
	}
	for range 2 {
		if d := limiter.AllowCaller("lukea", epoch); !d.Allowed {
			t.Fatal("refused within the burst")
		}
	}
	if d := limiter.AllowCaller("lukea", epoch); d.Allowed {
		t.Error("the repeated name got a second bucket, doubling the rate")
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	ok := bucket(10, 10)

	cases := map[string]struct {
		cfg     Config
		callers []string
	}{
		"zero caller rate":     {Config{bucket(0, 5), ok, ok}, []string{"a"}},
		"negative caller rate": {Config{bucket(-1, 5), ok, ok}, []string{"a"}},
		"zero burst":           {Config{bucket(1, 0), ok, ok}, []string{"a"}},
		"negative burst":       {Config{bucket(1, -1), ok, ok}, []string{"a"}},
		"zero global rate":     {Config{ok, bucket(0, 5), ok}, []string{"a"}},
		"zero unauth rate":     {Config{ok, ok, bucket(0, 5)}, []string{"a"}},
		"no callers":           {Config{ok, ok, ok}, nil},
		"an empty caller name": {Config{ok, ok, ok}, []string{""}},
		// A global rate below one caller's rate makes the per-caller limit
		// unreachable: it reads like a working config and behaves like a much
		// tighter one.
		"global rate below per-caller":  {Config{bucket(10, 10), bucket(1, 10), ok}, []string{"a"}},
		"global burst below per-caller": {Config{bucket(10, 10), bucket(10, 5), ok}, []string{"a"}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.cfg, tc.callers); err == nil {
				t.Fatal("New() error = nil, want error")
			}
		})
	}

	// A burst of exactly 1 is usable, if tight.
	if _, err := New(Config{bucket(1, 1), ok, ok}, []string{"a"}); err != nil {
		t.Errorf("a burst of 1 was rejected: %v", err)
	}
	// Equal global and per-caller rates are fine: one caller may use it all.
	if _, err := New(Config{bucket(10, 10), bucket(10, 10), ok}, []string{"a"}); err != nil {
		t.Errorf("equal rates were rejected: %v", err)
	}
}

// C21-AC3: concurrent admission is race-free. Run with -race, which is what
// make check-go does.
func TestConcurrentAdmissionIsRaceFree(t *testing.T) {
	const (
		callerCount  = 8
		goroutines   = 64
		perGoroutine = 200
		burst        = 50
	)

	callers := make([]string, callerCount)
	for i := range callers {
		callers[i] = fmt.Sprintf("caller-%d", i)
	}

	limiter := build(t, Config{
		PerCaller:       bucket(1, burst),
		Global:          bucket(1e6, 1e6),
		Unauthenticated: bucket(1e6, 1e6),
	}, callers...)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted = map[string]int{}
	)

	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			name := callers[g%callerCount]
			local := 0
			for range perGoroutine {
				// One frozen instant, so no tokens refill during the run and
				// the expected total is exactly the burst.
				if limiter.AllowCaller(name, epoch).Allowed {
					local++
				}
				// Unauthenticated traffic on the same limiter concurrently.
				limiter.AllowUnauthenticated(epoch)
			}
			mu.Lock()
			admitted[name] += local
			mu.Unlock()
		}(g)
	}
	wg.Wait()

	// With time frozen, each caller can admit exactly its burst. More than
	// that would mean tokens were double-counted under contention.
	for _, name := range callers {
		if admitted[name] != burst {
			t.Errorf("caller %s admitted %d requests, want exactly %d",
				name, admitted[name], burst)
		}
	}
	if count := limiter.BucketCount(); count != callerCount+2 {
		t.Errorf("BucketCount() = %d, want %d", count, callerCount+2)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	cases := map[time.Duration]int{
		// Never zero: a Retry-After of 0 invites an immediate retry, which is
		// the same mistake as no guidance at all.
		0:                               1,
		-time.Second:                    1,
		time.Nanosecond:                 1,
		500 * time.Millisecond:          1,
		time.Second:                     1,
		1500 * time.Millisecond:         2,
		2 * time.Second:                 2,
		2*time.Second + time.Nanosecond: 3,
		90 * time.Second:                90,
	}

	for delay, want := range cases {
		if got := RetryAfterSeconds(delay); got != want {
			t.Errorf("RetryAfterSeconds(%v) = %d, want %d", delay, got, want)
		}
	}
}

// Rounding up is the safe direction: rounding down tells a client to retry
// before capacity exists, producing a second rejection.
func TestRetryAfterNeverUnderstatesTheWait(t *testing.T) {
	for _, delay := range []time.Duration{
		1 * time.Millisecond, 999 * time.Millisecond, time.Second,
		1001 * time.Millisecond, 3 * time.Second, 3*time.Second + 1,
	} {
		seconds := RetryAfterSeconds(delay)
		if time.Duration(seconds)*time.Second < delay {
			t.Errorf("RetryAfterSeconds(%v) = %d, which is less than the actual wait",
				delay, seconds)
		}
	}
}

func TestDescribeCarriesEveryRate(t *testing.T) {
	limiter := build(t, Config{
		PerCaller:       bucket(1, 5),
		Global:          bucket(2, 10),
		Unauthenticated: bucket(3, 15),
	})
	description := limiter.Describe()
	for _, want := range []string{"1.00/s", "burst 5", "2.00/s", "burst 10", "3.00/s", "burst 15"} {
		if !strings.Contains(description, want) {
			t.Errorf("Describe() = %q, missing %q", description, want)
		}
	}
}
