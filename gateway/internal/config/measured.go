package config

import (
	"math"
	"time"
)

// Measured provider behaviour, from C32.
//
// These are observations, not settings. They live here because the defaults
// above are derived from them, and a derivation whose inputs are in a
// document drifts the moment the document is not read. With them in code,
// coherence_test.go can assert that the limits still follow from the numbers
// they were chosen from.
//
// Sources, both reproducible:
//
//	evals/reports/milestones/c26-live-development.json   434 live scans
//	evals/reports/milestones/c32-provider-profile.json   9 live scans by size
//
// They describe claude-opus-5 with prompt translate_fi_en-v1 on short Finnish
// passages. Changing the model or the prompt invalidates them, which is why
// ProviderLatencySource names both.
const (
	// ProviderLatencyP50 is the median end-to-end detector latency.
	ProviderLatencyP50 = 2833 * time.Millisecond
	// ProviderLatencyP95 is what the queue is sized against: deep enough to
	// absorb ordinary jitter, not so deep that it accepts work it cannot
	// finish.
	ProviderLatencyP95 = 5851 * time.Millisecond
	// ProviderLatencyP99 is the tail the queue deliberately does not try to
	// serve. See admission.go.
	ProviderLatencyP99 = 10191 * time.Millisecond

	// ProviderLatencySource identifies what the numbers describe.
	ProviderLatencySource = "claude-opus-5, prompt translate_fi_en-v1 " +
		"(5f42eb70), 434 scans, C26 development run"
)

// USDPerTypicalScan is the measured cost of one scan of a typical passage.
//
// From the C32 provider profile: 1,176 input and 127 output tokens at the
// 2026-06-24 list prices. It is what makes a rate limit a spend bound rather
// than a throughput guess.
const USDPerTypicalScan = 0.0090

// ThroughputCeiling is how many scans per second the admission bounds allow.
//
// A function rather than a constant so it cannot fall out of step with
// MaxActive, which is the number it is derived from.
func ThroughputCeiling(maxActive int) float64 {
	return float64(maxActive) / ProviderLatencyP50.Seconds()
}

// DeepestQueuedRequestLatency is how long the last request in a full queue
// takes end to end, at a given provider latency.
//
// # The ceiling, and why it is not a division
//
// The obvious model is continuous: slots free at MaxActive/L per second, so
// MaxQueued of them take (MaxQueued/MaxActive) x L. C32 derived a queue depth
// from exactly that and the load profile contradicted it.
//
// Under a burst - which is the case a queue exists for - the in-flight
// requests start together and therefore finish together, so slots are
// released in groups of MaxActive every L rather than smoothly. A queued
// request waits for whole groups:
//
//	ceil(MaxQueued / MaxActive) x L
//
// The measurement is unambiguous. At MaxActive 4 and L 2.833s the profile
// recorded a maximum wait of 5.670s - two whole batches - for MaxQueued 8
// *and* for MaxQueued 6, because ceil(8/4) and ceil(6/4) are both 2. Lowering
// the queue from 8 to 6 changed the worst case by nothing at all.
//
// Only crossing a ceiling boundary helps, which is why MaxQueued is 4.
func DeepestQueuedRequestLatency(
	maxActive, maxQueued int, provider time.Duration,
) time.Duration {
	batches := math.Ceil(float64(maxQueued) / float64(maxActive))
	return time.Duration((batches + 1) * float64(provider))
}
