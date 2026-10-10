package config

import (
	"math"
	"testing"
	"time"
)

// Whether the shipped limits still follow from the measurements they were
// chosen from.
//
// C32 derived every default here from a number in measured.go. Those
// derivations are the kind of reasoning that is written once, lives in a
// comment, and is quietly invalidated by a one-line change to a constant
// three files away. Each one is therefore an assertion, with the arithmetic
// visible, so the failure message explains what broke rather than reporting
// an unexpected integer.

// TestTheQueueNeverAcceptsWorkItCannotFinish is the derivation that changed a
// default.
//
// A request at the back of a full queue waits for the queue to drain and then
// needs its own turn. If that total exceeds the scan budget, the request
// reaches a slot with too little time left, starts a *paid* provider call and
// is cancelled in the middle of it. The money is spent and nobody gets an
// answer.
//
// MaxQueued was 8, which failed this at p95. It is 6.
func TestTheQueueNeverAcceptsWorkItCannotFinish(t *testing.T) {
	deepest := DeepestQueuedRequestLatency(
		DefaultMaxActive, DefaultMaxQueued, ProviderLatencyP95)

	if deepest > DefaultScanTimeout {
		t.Errorf(
			"at p95 (%s) the last of %d queued requests finishes in %s, over the "+
				"%s scan budget: it would start a paid call it cannot complete. "+
				"Either lower MaxQueued to %d or raise the scan timeout.",
			ProviderLatencyP95, DefaultMaxQueued, deepest, DefaultScanTimeout,
			largestQueueWithin(DefaultScanTimeout, ProviderLatencyP95))
	}
}

// TestTheOldQueueDepthWouldHaveFailed pins why the number moved.
//
// Without this, a later change back to 8 would look like a tidy-up.
func TestTheOldQueueDepthWouldHaveFailed(t *testing.T) {
	const before = 8
	deepest := DeepestQueuedRequestLatency(DefaultMaxActive, before, ProviderLatencyP95)
	if deepest <= DefaultScanTimeout {
		t.Errorf("a queue of %d now fits in %s (%s); the C32 derivation no longer "+
			"explains why the default was lowered and should be revisited",
			before, DefaultScanTimeout, deepest)
	}
}

// TestTheQueueWaitIsAStepFunction is the correction the measurement forced.
//
// The first derivation modelled the wait as (MaxQueued/MaxActive) x L and
// chose 6. The load profile then measured the same 5.670s maximum wait at 6
// and at 8, because under a burst slots are released in whole groups of
// MaxActive and both depths need two of them.
//
// This asserts the shape, so a future change cannot quietly reintroduce the
// continuous model: there must exist a larger queue depth that costs exactly
// the same worst case as the shipped one, and the shipped one must sit at the
// top of its step rather than wasting room below it.
func TestTheQueueWaitIsAStepFunction(t *testing.T) {
	shipped := DeepestQueuedRequestLatency(
		DefaultMaxActive, DefaultMaxQueued, ProviderLatencyP95)

	oneDeeper := DeepestQueuedRequestLatency(
		DefaultMaxActive, DefaultMaxQueued+1, ProviderLatencyP95)
	if oneDeeper <= shipped {
		t.Errorf("a queue one deeper costs %s against the shipped %s; the "+
			"shipped depth is below the top of its step and is giving up "+
			"capacity for nothing", oneDeeper, shipped)
	}

	if DefaultMaxQueued >= DefaultMaxActive {
		sameStep := DeepestQueuedRequestLatency(
			DefaultMaxActive, DefaultMaxQueued-1, ProviderLatencyP95)
		if sameStep != shipped {
			t.Errorf("a queue one shallower costs %s against the shipped %s; "+
				"the wait is behaving continuously, not as whole batches, and "+
				"the derivation in measured.go no longer describes it",
				sameStep, shipped)
		}
	}
}

// TestAnAdmittedRequestCanFinishAtTheDesignPoint is the property the queue
// depth was actually chosen for.
//
// A request that reaches a slot with less budget left than the call needs
// starts a paid provider call and is cancelled in the middle of it. At the
// design point - p95, which is where a queue is supposed to work - that must
// not happen to any admitted request.
func TestAnAdmittedRequestCanFinishAtTheDesignPoint(t *testing.T) {
	worstWait := worstQueueWait(DefaultMaxQueued, ProviderLatencyP95)
	remaining := DefaultScanTimeout - worstWait

	if worstWait < DefaultScanTimeout && remaining < ProviderLatencyP95 {
		t.Errorf("at p95 (%s) the deepest queued request is admitted with %s "+
			"left and needs %s: it would start a paid call it cannot finish",
			ProviderLatencyP95, remaining, ProviderLatencyP95)
	}
}

// TestTheTailExposureIsBoundedAndKnown records what is *not* fixed.
//
// No queue depth is free of this. At p99 a queue of 4 admits a request with
// 4.8s left that needs 10.2s, and a queue deep enough to avoid that (6 or 8)
// instead admits doomed requests at p95, which is far more common. The
// shipped depth chooses to waste rarely rather than often:
//
//	           p50        p95                    p99
//	Q = 4   completes   completes              wastes a call
//	Q = 6   completes   wastes a call          times out queued
//	Q = 8   completes   wastes a call          times out queued
//
// The real remedy is deadline-aware admission - refusing a slot when the
// remaining budget cannot cover a call - which is a behaviour change C32
// records rather than makes. This test exists so the exposure stays bounded
// to the tail: if it ever reaches p95, something regressed.
func TestTheTailExposureIsBoundedAndKnown(t *testing.T) {
	for _, point := range []struct {
		name    string
		latency time.Duration
		wasteOK bool
	}{
		{"p50", ProviderLatencyP50, false},
		{"p95", ProviderLatencyP95, false},
		{"p99", ProviderLatencyP99, true},
	} {
		wait := worstQueueWait(DefaultMaxQueued, point.latency)
		admitted := wait < DefaultScanTimeout
		wastes := admitted && DefaultScanTimeout-wait < point.latency

		if wastes && !point.wasteOK {
			t.Errorf("%s (%s): the deepest queued request now starts a paid "+
				"call it cannot finish; the exposure was confined to the tail",
				point.name, point.latency)
		}
		if !wastes && point.wasteOK {
			t.Logf("%s (%s): no longer wastes a call - the comment above and "+
				"docs/c32-capacity.md should be updated", point.name, point.latency)
		}
	}
}

// worstQueueWait is the measured relationship: whole batches, not a division.
func worstQueueWait(queued int, provider time.Duration) time.Duration {
	batches := math.Ceil(float64(queued) / float64(DefaultMaxActive))
	return time.Duration(batches * float64(provider))
}

// TestTheGlobalRateDoesNotExceedWhatAdmissionCanServe keeps the shed signal
// honest.
//
// A limiter that admits faster than the service completes converts rate
// limiting into admission shedding: callers see `overloaded`, which reads as
// a capacity incident, when the true statement is `rate_limited`. Both fail
// closed, so this is about whether the dashboards tell the truth.
func TestTheGlobalRateDoesNotExceedWhatAdmissionCanServe(t *testing.T) {
	cfg, err := parseRates(env(map[string]string{}))
	if err != nil {
		t.Fatalf("parseRates: %v", err)
	}
	ceiling := ThroughputCeiling(DefaultMaxActive)

	if cfg.Global.PerSecond > ceiling {
		t.Errorf("global rate %.2f/s exceeds the admission ceiling of %.2f/s "+
			"(%d slots / %s); excess traffic would be shed as overloaded rather "+
			"than rate limited",
			cfg.Global.PerSecond, ceiling, DefaultMaxActive, ProviderLatencyP50)
	}
}

// TestTheGlobalBurstFillsTheSystemExactlyOnce explains the burst number.
//
// MaxActive + MaxQueued is every place a request can be. A larger burst
// admits requests with nowhere to go; a smaller one refuses while the system
// has room.
func TestTheGlobalBurstFillsTheSystemExactlyOnce(t *testing.T) {
	cfg, err := parseRates(env(map[string]string{}))
	if err != nil {
		t.Fatalf("parseRates: %v", err)
	}
	want := DefaultMaxActive + DefaultMaxQueued
	if cfg.Global.Burst != want {
		t.Errorf("global burst = %d, want %d (MaxActive %d + MaxQueued %d)",
			cfg.Global.Burst, want, DefaultMaxActive, DefaultMaxQueued)
	}
}

// TestTheSpendCeilingIsStated turns the rate limit back into money.
//
// The limits exist as a spend bound, so the bound should be a number someone
// has looked at rather than an implication of two other numbers.
func TestTheSpendCeilingIsStated(t *testing.T) {
	perDay := ThroughputCeiling(DefaultMaxActive) * USDPerTypicalScan * 86400

	// Not a correctness property - a guard against the defaults drifting into
	// a different order of magnitude without anyone noticing what it costs.
	if perDay > 2000 {
		t.Errorf("sustained spend ceiling is USD %.0f/day at the shipped "+
			"defaults; C32 recorded USD 1,145 and a change this large should be "+
			"deliberate", perDay)
	}
}

// largestQueueWithin is the depth the derivation would choose.
func largestQueueWithin(budget, provider time.Duration) int {
	depth := float64(DefaultMaxActive) * (budget.Seconds()/provider.Seconds() - 1)
	if depth < 0 {
		return 0
	}
	return int(depth)
}
