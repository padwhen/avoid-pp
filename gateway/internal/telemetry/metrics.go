package telemetry

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// # Why the label values are enumerated rather than validated
//
// A metrics system fails in one direction: unbounded label cardinality. Every
// distinct combination of label values is a new time series held forever, so
// one request id as a label is one series per request, and the thing that
// notices is the monitoring system falling over rather than a test.
//
// C33-AC3 says it outright: request ids are not metric labels. That is not a
// rule this package asks callers to follow. Every label this registry can
// emit is declared below with its complete set of permitted values, and a
// value outside the set is recorded as "other" rather than created. The
// cardinality of the whole gateway is therefore a number you can compute by
// multiplying the lengths of these lists, and no input can raise it.
//
// `request_id` is allowed in logs - obs.AllowedKeys permits it, because
// correlating one request is exactly what a log is for - and cannot be a
// label here. privacy_test.go asserts both halves.

// labelDomain is the permitted values for one label.
type labelDomain struct {
	name   string
	values []string
}

// OutcomeValues are the ways a scan ends.
//
// These are the handler's own outcome names, verbatim. They were already a
// bounded, developer-written vocabulary - scan.go logs exactly one of them
// per request - so mapping them onto a shorter list would have lost detail
// to no purpose and added a translation table to keep in step.
//
// C33-AC2 asks telemetry to distinguish overload, provider error,
// uncertainty and an actual policy block. Three are here, and the fourth is
// on MetricDecisions, because uncertainty is a property of the verdict
// rather than of the request:
//
//	overload        outcome="shed"
//	provider error  outcome="detector_unavailable" or "invalid_response"
//	uncertainty     label="uncertain" on avoidpp_decisions_total
//	policy block    action="block" on avoidpp_decisions_total
//
// They look alike from outside - all four are a request that produced no
// translation - and they have nothing in common operationally.
var OutcomeValues = []string{
	"complete",
	// Refused before any provider work was done.
	"rejected", "decode_error", "unauthenticated", "unauthorized_task",
	"passage_too_large", "token_budget_exceeded",
	// Capacity.
	"shed", "abandoned",
	// The dependency.
	"detector_unavailable", "invalid_response", "deadline_exceeded",
	// This service's own fault.
	"policy_error",
	"other",
}

// ActionValues are the policy outcomes. "none" covers requests that never
// reached a decision.
var ActionValues = []string{"allow", "flag", "block", "none", "other"}

// LabelValues are the detector's assessments, which is where "uncertainty"
// becomes countable separately from an error.
var LabelValues = []string{
	"no_injection_detected", "suspicious", "uncertain", "none", "other",
}

// ReasonValues are the contract's reason codes.
var ReasonValues = []string{
	"clean_complete_scan",
	"suspicious_monitoring", "suspicious_enforced",
	"uncertain_monitoring", "uncertain_enforced",
	"none", "other",
}

// CodeValues are the contract's error codes. Bounded by the contract, which
// is what makes them safe as labels.
var CodeValues = []string{
	"malformed_json", "schema_invalid", "unknown_task_id",
	"unauthenticated", "unauthorized_task", "payload_too_large",
	"unsupported_media_type", "token_budget_exceeded", "rate_limited",
	"detector_unavailable", "overloaded", "deadline_exceeded",
	"internal_error", "none", "other",
}

// Metric names. Prefixed so a scrape mixing several services stays readable.
const (
	MetricScans          = "avoidpp_scans_total"
	MetricDecisions      = "avoidpp_decisions_total"
	MetricErrors         = "avoidpp_errors_total"
	MetricScanDuration   = "avoidpp_scan_duration_seconds"
	MetricQueueWait      = "avoidpp_admission_queue_wait_seconds"
	MetricDetectorCall   = "avoidpp_detector_duration_seconds"
	MetricAdmissionState = "avoidpp_admission_slots"
)

// durationBuckets are cumulative upper bounds in seconds.
//
// Chosen from the C32 measurements rather than from a default ladder: the
// provider median is 2.8s, p95 5.9s and p99 10.2s, and the scan timeout is
// 15s. Buckets clustered where the distribution actually lives make the
// difference between "most scans are under 16 seconds" and a usable p95.
var durationBuckets = []float64{
	0.005, 0.05, // the gateway alone, which is microseconds
	1, 2, 3, 4, 6, 8, 10, 12, 15, 30,
}

// Registry holds the gateway's metrics.
//
// Every series is created at construction, so the memory is fixed at startup
// and a scrape never allocates. That also means a counter reads zero rather
// than being absent before its first event, which is what lets a query say
// "no blocks in the last hour" instead of "no data".
type Registry struct {
	mu sync.Mutex

	counters   map[string]map[string]*uint64Counter
	histograms map[string]map[string]*histogram
	gauges     map[string]*int64Gauge

	// Declared label sets, kept so exposition can emit every series.
	series map[string][]map[string]string
	// Permitted values per metric per label, for normalise.
	declared map[string]map[string]map[string]bool
}

type uint64Counter struct{ value uint64 }

type int64Gauge struct{ value int64 }

type histogram struct {
	counts []uint64
	sum    float64
	total  uint64
}

// NewRegistry builds every series this gateway can emit.
func NewRegistry() *Registry {
	r := &Registry{
		counters:   map[string]map[string]*uint64Counter{},
		histograms: map[string]map[string]*histogram{},
		gauges:     map[string]*int64Gauge{},
		series:     map[string][]map[string]string{},
		declared:   map[string]map[string]map[string]bool{},
	}

	r.declareCounter(MetricScans, labelDomain{"outcome", OutcomeValues})
	r.declareCounter(MetricDecisions,
		labelDomain{"action", ActionValues},
		labelDomain{"label", LabelValues},
		labelDomain{"reason_code", ReasonValues})
	r.declareCounter(MetricErrors, labelDomain{"code", CodeValues})

	r.declareHistogram(MetricScanDuration, labelDomain{"outcome", OutcomeValues})
	r.declareHistogram(MetricQueueWait)
	r.declareHistogram(MetricDetectorCall)

	r.gauges[MetricAdmissionState+`{state="active"}`] = &int64Gauge{}
	r.gauges[MetricAdmissionState+`{state="queued"}`] = &int64Gauge{}

	return r
}

// cross returns every combination of the declared label domains.
func cross(domains []labelDomain) []map[string]string {
	combinations := []map[string]string{{}}
	for _, domain := range domains {
		next := make([]map[string]string, 0, len(combinations)*len(domain.values))
		for _, base := range combinations {
			for _, value := range domain.values {
				extended := maps.Clone(base)
				extended[domain.name] = value
				next = append(next, extended)
			}
		}
		combinations = next
	}
	return combinations
}

// record stores the permitted values so normalise is a lookup.
func (r *Registry) record(name string, domains []labelDomain) {
	permitted := map[string]map[string]bool{}
	for _, domain := range domains {
		values := map[string]bool{}
		for _, value := range domain.values {
			values[value] = true
		}
		permitted[domain.name] = values
	}
	r.declared[name] = permitted
}

func (r *Registry) declareCounter(name string, domains ...labelDomain) {
	r.record(name, domains)
	r.counters[name] = map[string]*uint64Counter{}
	for _, labels := range cross(domains) {
		r.counters[name][encodeLabels(labels)] = &uint64Counter{}
		r.series[name] = append(r.series[name], labels)
	}
}

func (r *Registry) declareHistogram(name string, domains ...labelDomain) {
	r.record(name, domains)
	r.histograms[name] = map[string]*histogram{}
	for _, labels := range cross(domains) {
		r.histograms[name][encodeLabels(labels)] = &histogram{
			counts: make([]uint64, len(durationBuckets)),
		}
		r.series[name] = append(r.series[name], labels)
	}
}

// Count increments a counter.
//
// An undeclared label value is folded into "other" rather than rejected or
// created: telemetry must not drop a signal because an enum grew, and it must
// not grow a time series because an enum grew either.
func (r *Registry) Count(name string, labels map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	series, ok := r.counters[name]
	if !ok {
		return
	}
	if counter, ok := series[encodeLabels(r.normalise(name, labels))]; ok {
		counter.value++
	}
}

// Observe records a duration against a histogram.
func (r *Registry) Observe(name string, labels map[string]string, seconds float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	series, ok := r.histograms[name]
	if !ok {
		return
	}
	bucket, ok := series[encodeLabels(r.normalise(name, labels))]
	if !ok {
		return
	}
	bucket.total++
	bucket.sum += seconds
	for i, upper := range durationBuckets {
		if seconds <= upper {
			bucket.counts[i]++
		}
	}
}

// SetGauge records a current occupancy.
func (r *Registry) SetGauge(name, state string, value int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if gauge, ok := r.gauges[name+`{state="`+state+`"}`]; ok {
		gauge.value = value
	}
}

// normalise maps a caller's labels onto a declared series.
//
// Three cases, all resolved the same way - to a series that already exists:
//
//   - a value outside the declared set becomes "other", so an enum that grows
//     in the contract cannot grow the registry;
//   - a label the caller omitted becomes "other" too, because a missing
//     dimension is a measurement nobody can interpret, not a reason to drop
//     the event;
//   - a label the caller invented is ignored, since the series it would
//     belong to was never declared.
//
// The result is that Count and Observe can never allocate. Whatever they are
// handed, it lands in one of the series built at startup.
func (r *Registry) normalise(name string, labels map[string]string) map[string]string {
	permitted, ok := r.declared[name]
	if !ok {
		return labels
	}
	out := make(map[string]string, len(permitted))
	for key, values := range permitted {
		value := labels[key]
		if !values[value] {
			value = "other"
		}
		out[key] = value
	}
	return out
}

func encodeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := slices.Collect(maps.Keys(labels))
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Quote(labels[key]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Expose renders the registry in Prometheus text exposition format.
//
// Hand-written rather than pulled from a client library, for the same reason
// the rest of this package is: the format is a dozen lines of text and the
// library is a dependency tree.
func (r *Registry) Expose() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out strings.Builder
	for _, name := range slices.Sorted(maps.Keys(r.counters)) {
		fmt.Fprintf(&out, "# TYPE %s counter\n", name)
		for _, key := range slices.Sorted(maps.Keys(r.counters[name])) {
			fmt.Fprintf(&out, "%s%s %d\n", name, key, r.counters[name][key].value)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(r.histograms)) {
		fmt.Fprintf(&out, "# TYPE %s histogram\n", name)
		for _, key := range slices.Sorted(maps.Keys(r.histograms[name])) {
			h := r.histograms[name][key]
			for i, upper := range durationBuckets {
				fmt.Fprintf(&out, "%s_bucket%s %d\n",
					name, withBucket(key, formatFloat(upper)), h.counts[i])
			}
			fmt.Fprintf(&out, "%s_bucket%s %d\n", name, withBucket(key, "+Inf"), h.total)
			fmt.Fprintf(&out, "%s_sum%s %s\n", name, key, formatFloat(h.sum))
			fmt.Fprintf(&out, "%s_count%s %d\n", name, key, h.total)
		}
	}
	// One TYPE line per metric, not per series. A repeated TYPE is a
	// malformed exposition and some scrapers reject the whole scrape over
	// it - which would turn a cosmetic bug into no metrics at all.
	gaugeTyped := map[string]bool{}
	for _, series := range slices.Sorted(maps.Keys(r.gauges)) {
		name := series
		if brace := strings.IndexByte(series, '{'); brace >= 0 {
			name = series[:brace]
		}
		if !gaugeTyped[name] {
			fmt.Fprintf(&out, "# TYPE %s gauge\n", name)
			gaugeTyped[name] = true
		}
		fmt.Fprintf(&out, "%s %d\n", series, r.gauges[series].value)
	}
	return out.String()
}

func withBucket(encoded, le string) string {
	if encoded == "" {
		return `{le="` + le + `"}`
	}
	return encoded[:len(encoded)-1] + `,le="` + le + `"}`
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

// Seconds converts a duration for Observe.
func Seconds(d time.Duration) float64 { return d.Seconds() }

type registryKey struct{}

// WithRegistry puts a registry on a context.
//
// Threaded through the context rather than passed as an argument because the
// error-writing helpers in the api package take only (w, r) - and counting at
// the point an envelope is written, rather than at each of the dozen branches
// that decide to write one, is what stops a newly added branch from being
// invisible in exactly the dashboard built to catch it.
func WithRegistry(ctx context.Context, r *Registry) context.Context {
	return context.WithValue(ctx, registryKey{}, r)
}

// RegistryFrom returns the registry carried by ctx, if any.
//
// A missing registry is not an error: handlers constructed in tests have no
// telemetry, and recording nothing is the right behaviour there.
func RegistryFrom(ctx context.Context) (*Registry, bool) {
	registry, ok := ctx.Value(registryKey{}).(*Registry)
	return registry, ok && registry != nil
}

// DeclaredLabels returns the complete label surface: every metric, every
// label it can carry, and every value that label may take.
//
// Exported so the cardinality of the gateway can be asserted from outside
// rather than described in a comment. privacy_test.go walks it to check that
// no label is named request_id and that no permitted value looks like text
// rather than an enum member - both of which are properties of this data,
// not of the code paths that happen to call Count today.
func (r *Registry) DeclaredLabels() map[string]map[string][]string {
	out := make(map[string]map[string][]string, len(r.declared))
	for metric, labels := range r.declared {
		out[metric] = make(map[string][]string, len(labels))
		for label, values := range labels {
			out[metric][label] = slices.Sorted(maps.Keys(values))
		}
	}
	return out
}
