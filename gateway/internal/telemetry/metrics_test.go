package telemetry

import (
	"strings"
	"sync"
	"testing"
)

func TestEverySeriesExistsBeforeItsFirstEvent(t *testing.T) {
	// A counter that is absent until something happens cannot answer "were
	// there any blocks in the last hour" - the query returns no data, which
	// reads the same as a broken exporter.
	exposed := NewRegistry().Expose()

	for _, want := range []string{
		`avoidpp_scans_total{outcome="complete"} 0`,
		`avoidpp_scans_total{outcome="shed"} 0`,
		`avoidpp_errors_total{code="overloaded"} 0`,
		`avoidpp_decisions_total{action="block",label="suspicious",reason_code="suspicious_enforced"} 0`,
	} {
		if !strings.Contains(exposed, want) {
			t.Errorf("missing series before any event: %s", want)
		}
	}
}

func TestAnUndeclaredValueFoldsIntoOther(t *testing.T) {
	// The cardinality guarantee: whatever Count is handed, it lands in a
	// series that already exists.
	r := NewRegistry()
	before := len(strings.Split(r.Expose(), "\n"))

	r.Count(MetricScans, map[string]string{"outcome": "a-value-from-the-future"})
	r.Count(MetricErrors, map[string]string{"code": "not_a_contract_code"})

	after := strings.Split(r.Expose(), "\n")
	if len(after) != before {
		t.Errorf("exposition grew from %d to %d lines; a label value created a series",
			before, len(after))
	}
	if !strings.Contains(r.Expose(), `avoidpp_scans_total{outcome="other"} 1`) {
		t.Error("an unknown outcome was not folded into other")
	}
	if !strings.Contains(r.Expose(), `avoidpp_errors_total{code="other"} 1`) {
		t.Error("an unknown code was not folded into other")
	}
}

func TestAMissingLabelIsOtherRatherThanADroppedEvent(t *testing.T) {
	// A measurement nobody can interpret still happened. Dropping it would
	// make the totals disagree with reality in the direction that hides
	// problems.
	r := NewRegistry()
	r.Count(MetricDecisions, map[string]string{"action": "allow"})

	if !strings.Contains(r.Expose(),
		`avoidpp_decisions_total{action="allow",label="other",reason_code="other"} 1`) {
		t.Errorf("a partially labelled event was not recorded:\n%s", r.Expose())
	}
}

func TestAnInventedLabelCannotCreateASeries(t *testing.T) {
	r := NewRegistry()
	before := r.Expose()
	r.Count(MetricScans, map[string]string{
		"outcome":    "complete",
		"request_id": "deadbeef", // exactly what AC3 forbids
	})
	after := r.Expose()

	if strings.Contains(after, "request_id") {
		t.Fatal("a request id reached the exposition output")
	}
	if strings.Count(after, "\n") != strings.Count(before, "\n") {
		t.Error("an invented label created a series")
	}
	if !strings.Contains(after, `avoidpp_scans_total{outcome="complete"} 1`) {
		t.Error("the event was dropped rather than recorded under its declared labels")
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	r := NewRegistry()
	for _, seconds := range []float64{0.001, 2.5, 2.5, 11, 400} {
		r.Observe(MetricScanDuration, map[string]string{"outcome": "complete"}, seconds)
	}
	exposed := r.Expose()

	for _, want := range []string{
		// 0.001 only
		`avoidpp_scan_duration_seconds_bucket{outcome="complete",le="0.005"} 1`,
		// 0.001 + two at 2.5
		`avoidpp_scan_duration_seconds_bucket{outcome="complete",le="3"} 3`,
		// plus 11
		`avoidpp_scan_duration_seconds_bucket{outcome="complete",le="12"} 4`,
		// 400 only lands in +Inf, which is the total
		`avoidpp_scan_duration_seconds_bucket{outcome="complete",le="+Inf"} 5`,
		`avoidpp_scan_duration_seconds_count{outcome="complete"} 5`,
	} {
		if !strings.Contains(exposed, want) {
			t.Errorf("missing or wrong: %s", want)
		}
	}
}

func TestBucketsStraddleTheMeasuredDistribution(t *testing.T) {
	// C32 measured a provider median of 2.8s, p95 5.9s and p99 10.2s against
	// a 15s timeout. Buckets that do not bracket those produce a p95 that is
	// an artefact of the ladder rather than of the service.
	for _, point := range []float64{2.833, 5.851, 10.191, 15} {
		var below, above bool
		for _, upper := range durationBuckets {
			if upper < point {
				below = true
			}
			if upper >= point {
				above = true
			}
		}
		if !below || !above {
			t.Errorf("%.3fs is not bracketed by the buckets %v", point, durationBuckets)
		}
	}
}

func TestGaugesTrackOccupancy(t *testing.T) {
	r := NewRegistry()
	r.SetGauge(MetricAdmissionState, "active", 3)
	r.SetGauge(MetricAdmissionState, "queued", 2)
	// An undeclared state is ignored rather than created.
	r.SetGauge(MetricAdmissionState, "imaginary", 99)

	exposed := r.Expose()
	if !strings.Contains(exposed, `avoidpp_admission_slots{state="active"} 3`) ||
		!strings.Contains(exposed, `avoidpp_admission_slots{state="queued"} 2`) {
		t.Errorf("gauges not exposed:\n%s", exposed)
	}
	if strings.Contains(exposed, "imaginary") {
		t.Error("an undeclared gauge state was created")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Count(MetricScans, map[string]string{"outcome": "complete"})
			r.Observe(MetricQueueWait, nil, 0.5)
			r.SetGauge(MetricAdmissionState, "active", 1)
			_ = r.Expose()
		}()
	}
	wg.Wait()

	if !strings.Contains(r.Expose(), `avoidpp_scans_total{outcome="complete"} 50`) {
		t.Error("counts were lost under concurrency")
	}
}

func TestTotalCardinalityIsComputableAndSmall(t *testing.T) {
	// The whole point of declaring values: the number of time series is a
	// property of this file, not of traffic. If it ever becomes large, it
	// became large here, in a diff.
	r := NewRegistry()
	series := 0
	for _, line := range strings.Split(r.Expose(), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			series++
		}
	}
	if series > 1200 {
		t.Errorf("%d exposed series; the registry has grown enough to be "+
			"worth a deliberate decision", series)
	}
	t.Logf("%d exposed series", series)
}
