// Package limits bounds how fast requests may arrive.
//
// # Why the state here cannot grow
//
// The usual shape of a rate limiter is a map from some request attribute to a
// token bucket, filled in on first sight. That map is the vulnerability: if
// the key is anything the caller controls — an IP, a header, a body field —
// then sending a million distinct values creates a million buckets, and a
// rate limiter becomes a memory-exhaustion primitive.
//
// So nothing here is created on demand. Every limiter is allocated once, at
// construction, from configuration:
//
//   - one bucket per configured caller, and the configured callers are a
//     fixed list that only a restart can change;
//   - one global bucket shared by all authenticated traffic;
//   - one bucket shared by *all* unauthenticated traffic, keyed by nothing at
//     all.
//
// That last one is the deliberate choice. Keying unauthenticated traffic by
// source address would be fairer and would also hand an attacker an unbounded
// map. One shared bucket means a flood from a single source can exhaust the
// unauthenticated budget for every other unauthenticated request — and that
// is an acceptable loss, because legitimate traffic is authenticated and
// unaffected. The blast radius is that unrecognised callers receive 429 rather
// than 401, which discloses less rather than more.
//
// The map is written once and only read afterwards, so concurrent lookups need
// no lock, and rate.Limiter is itself safe for concurrent use.
//
// # Eviction
//
// There is none, because there is nothing to evict. Eviction exists to bound
// state that would otherwise grow without limit; state that cannot grow does
// not need it, and an LRU here would be machinery guarding against a condition
// the design makes unreachable.
//
// That reasoning depends entirely on callers coming from configuration. If
// callers ever become dynamic — per end user, per tenant loaded from a
// database — this stops being true and bounded eviction becomes necessary.
// The test that asserts the map never grows is what will fail at that point,
// which is the intended way to find out.
//
// # These limits are per process
//
// Each gateway instance has its own buckets. Two replicas admit twice the
// configured rate, three admit three times. There is no shared counter, no
// Redis, no coordination. A deployment that needs a cluster-wide limit has to
// either run one instance or divide the configured rate by the replica count,
// and knowing which is a deployment decision rather than something this code
// can discover.
package limits

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/time/rate"
)

// Scope names which bucket refused a request. It appears in logs, never in a
// response: telling a caller whether they hit their own limit or a shared one
// discloses other callers' traffic.
type Scope string

const (
	ScopeCaller          Scope = "caller"
	ScopeGlobal          Scope = "global"
	ScopeUnauthenticated Scope = "unauthenticated"
	// ScopeUnknownCaller is refused outright: a caller with no configured
	// bucket is a wiring mistake, and guessing a limit for it would be worse
	// than failing.
	ScopeUnknownCaller Scope = "unknown_caller"
)

// Bucket is one configured rate.
type Bucket struct {
	// PerSecond is the sustained rate, refilled continuously rather than in
	// steps, so a caller is not rewarded for aligning with a window boundary.
	PerSecond float64
	// Burst is how many requests may arrive at once. It must be at least 1:
	// a burst of zero never admits anything, which is fail-closed in the
	// least useful possible way.
	Burst int
}

func (b Bucket) validate(name string) error {
	if b.PerSecond <= 0 {
		return fmt.Errorf("%s: rate must be greater than zero", name)
	}
	if b.Burst < 1 {
		return fmt.Errorf("%s: burst must be at least 1, or nothing is ever admitted", name)
	}
	return nil
}

func (b Bucket) limiter() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(b.PerSecond), b.Burst)
}

// Config is the full set of configured rates.
type Config struct {
	PerCaller       Bucket
	Global          Bucket
	Unauthenticated Bucket
}

// Decision is the outcome of one admission check.
type Decision struct {
	Allowed bool
	// RetryAfter is how long until the request would succeed. It is exact
	// rather than a fixed guess, because a fixed guess is either too short —
	// and the client retries into another rejection — or too long, and the
	// client waits for capacity that already exists.
	RetryAfter time.Duration
	Scope      Scope
}

// Limiter holds every bucket. Its contents are fixed after New.
type Limiter struct {
	perCaller       map[string]*rate.Limiter
	global          *rate.Limiter
	unauthenticated *rate.Limiter
	config          Config
}

// New allocates one bucket per configured caller plus the two shared buckets.
//
// callers is the complete list. A name absent from it can never be admitted,
// which is why authentication has to run first: by the time a request reaches
// AllowCaller, its caller name came from configuration and not from the wire.
func New(cfg Config, callers []string) (*Limiter, error) {
	var problems []error
	if err := cfg.PerCaller.validate("per-caller"); err != nil {
		problems = append(problems, err)
	}
	if err := cfg.Global.validate("global"); err != nil {
		problems = append(problems, err)
	}
	if err := cfg.Unauthenticated.validate("unauthenticated"); err != nil {
		problems = append(problems, err)
	}
	if len(callers) == 0 {
		problems = append(problems, errors.New("no callers to allocate buckets for"))
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}

	// A global limit below one caller's own limit makes the per-caller limit
	// unreachable. Such a configuration reads like a working one and behaves
	// like a much tighter one, which is the kind of thing that gets debugged
	// for an afternoon. Both halves of the pair are checked, since either
	// alone produces the same surprise.
	if cfg.Global.PerSecond < cfg.PerCaller.PerSecond {
		return nil, fmt.Errorf(
			"global rate %.2f/s is below the per-caller rate %.2f/s, so no caller "+
				"can reach its own rate", cfg.Global.PerSecond, cfg.PerCaller.PerSecond)
	}
	if cfg.Global.Burst < cfg.PerCaller.Burst {
		return nil, fmt.Errorf(
			"global burst %d is below the per-caller burst %d, so no caller can "+
				"reach its own burst", cfg.Global.Burst, cfg.PerCaller.Burst)
	}

	buckets := make(map[string]*rate.Limiter, len(callers))
	for _, name := range callers {
		if name == "" {
			return nil, errors.New("a caller has no name")
		}
		if _, exists := buckets[name]; exists {
			// Callers may hold two keys during a rotation, so a repeated name
			// is expected here and must share one bucket rather than get a
			// second: two buckets would double the caller's effective rate
			// for as long as the rotation lasted.
			continue
		}
		buckets[name] = cfg.PerCaller.limiter()
	}

	return &Limiter{
		perCaller:       buckets,
		global:          cfg.Global.limiter(),
		unauthenticated: cfg.Unauthenticated.limiter(),
		config:          cfg,
	}, nil
}

// AllowCaller admits one request from an authenticated caller.
//
// Both the caller's bucket and the global bucket must have capacity, and a
// refused request consumes neither. That rollback matters: without it, a
// caller refused by the global limit would still pay a token from its own
// bucket, so heavy traffic from one caller would quietly throttle another
// twice over — once by the shared limit and again by a bucket drained for
// requests that were never served.
func (l *Limiter) AllowCaller(name string, now time.Time) Decision {
	bucket, known := l.perCaller[name]
	if !known {
		// Unreachable through the normal path, since names come from the same
		// configuration these buckets were built from. Refusing rather than
		// allocating keeps the "state cannot grow" property true even if some
		// future caller reaches this with a name from elsewhere.
		return Decision{Scope: ScopeUnknownCaller}
	}

	callerReservation := bucket.ReserveN(now, 1)
	callerDelay := callerReservation.DelayFrom(now)
	if !callerReservation.OK() || callerDelay > 0 {
		callerReservation.CancelAt(now)
		return Decision{
			RetryAfter: callerDelay,
			Scope:      ScopeCaller,
		}
	}

	globalReservation := l.global.ReserveN(now, 1)
	globalDelay := globalReservation.DelayFrom(now)
	if !globalReservation.OK() || globalDelay > 0 {
		globalReservation.CancelAt(now)
		// Give the caller its token back: it did nothing wrong.
		callerReservation.CancelAt(now)
		return Decision{
			RetryAfter: globalDelay,
			Scope:      ScopeGlobal,
		}
	}

	return Decision{Allowed: true}
}

// AllowUnauthenticated admits one request that failed authentication.
//
// It is charged after the credential has been checked, not before. The check
// is a SHA-256 and a few fixed-length comparisons, so the work saved by
// limiting first is negligible, and limiting first would mean charging a
// legitimate caller's first request against the unauthenticated bucket before
// anyone knows it was legitimate.
func (l *Limiter) AllowUnauthenticated(now time.Time) Decision {
	reservation := l.unauthenticated.ReserveN(now, 1)
	delay := reservation.DelayFrom(now)
	if !reservation.OK() || delay > 0 {
		reservation.CancelAt(now)
		return Decision{RetryAfter: delay, Scope: ScopeUnauthenticated}
	}
	return Decision{Allowed: true}
}

// Callers lists the names with an allocated bucket, sorted, for startup
// logging and for the test that asserts the map never grows.
func (l *Limiter) Callers() []string {
	out := make([]string, 0, len(l.perCaller))
	for name := range l.perCaller {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// BucketCount reports how many buckets exist in total. It is a constant for
// the life of the process, and a test depends on that.
func (l *Limiter) BucketCount() int { return len(l.perCaller) + 2 }

// Describe renders the configured rates for one startup log line.
func (l *Limiter) Describe() string {
	return fmt.Sprintf(
		"per-caller %.2f/s burst %d, global %.2f/s burst %d, unauthenticated %.2f/s burst %d",
		l.config.PerCaller.PerSecond, l.config.PerCaller.Burst,
		l.config.Global.PerSecond, l.config.Global.Burst,
		l.config.Unauthenticated.PerSecond, l.config.Unauthenticated.Burst,
	)
}

// RetryAfterSeconds converts a delay to the whole seconds an HTTP header and
// the error body carry.
//
// It rounds up and floors at 1. Rounding down would tell a client to retry
// before capacity exists, which produces a second rejection and makes the
// guidance worse than none; and a Retry-After of 0 invites an immediate retry,
// which is the same mistake written differently.
func RetryAfterSeconds(delay time.Duration) int {
	if delay <= 0 {
		return 1
	}
	seconds := int(delay / time.Second)
	if delay%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}
