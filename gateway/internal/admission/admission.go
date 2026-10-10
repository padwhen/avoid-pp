// Package admission caps how much inference work is in flight at once.
//
// Rate limits and admission control answer different questions, and a service
// calling a slow dependency needs both. A rate limit bounds how fast requests
// *arrive*; it says nothing about how many are still running. With a provider
// call measured at 4.4 seconds, a perfectly compliant two requests per second
// leaves roughly nine in flight at steady state — and if the provider slows to
// thirty seconds, sixty. Each one holds a connection, a goroutine and a
// buffer, and nothing in the rate limiter notices.
//
// So this bounds concurrency instead: how many calls may be running, and how
// many may be waiting for a slot. Both numbers are fixed at startup.
//
// # Why a bounded queue rather than no queue
//
// With no queue, a momentarily full set of slots rejects a request that would
// have been served a few milliseconds later, which makes the service fragile
// under ordinary jitter. With an unbounded queue, every arrival is accepted
// and the queue becomes the place where memory and latency go to die — callers
// wait behind work that will outlive their own deadlines, and the service
// reports healthy while serving nobody.
//
// A small bounded queue takes the jitter and refuses the overload. The refusal
// is the point: a 503 now is strictly better information than a response that
// may arrive in two minutes.
//
// # Releasing on cancellation
//
// A slot is held by whoever is making the call, and released when they stop
// making it — including when they stop because the caller hung up or the
// deadline passed. A slot that leaks on cancellation is worse than no limit
// at all: capacity drains monotonically and the service dies slowly, at a rate
// set by how often clients disconnect.
package admission

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ErrQueueFull means both the slots and the waiting queue were full.
//
// It is deliberately distinct from a context error. Overload is a server
// condition that the caller should retry against, while a cancelled context is
// the caller's own doing, and conflating them makes a 503 look like a client
// problem in every dashboard that counts them.
var ErrQueueFull = errors.New("admission queue is full")

// Config bounds the in-flight work.
type Config struct {
	// MaxActive is how many inference calls may run at once.
	MaxActive int
	// MaxQueued is how many may wait for a slot. Zero is legal and means
	// refuse immediately rather than wait.
	MaxQueued int
}

func (c Config) validate() error {
	if c.MaxActive < 1 {
		return fmt.Errorf("max active must be at least 1, got %d", c.MaxActive)
	}
	if c.MaxQueued < 0 {
		return fmt.Errorf("max queued must not be negative, got %d", c.MaxQueued)
	}
	return nil
}

// Controller admits work up to a fixed concurrency, with a bounded queue.
//
// Its state is two integers and a channel sized at construction. Nothing here
// grows with traffic.
type Controller struct {
	// slots is a counting semaphore: a send takes a slot, a receive returns
	// one. Its capacity is the concurrency limit, so the limit is a property
	// of the channel rather than of a counter something could forget to check.
	slots chan struct{}

	maxActive int
	maxQueued int64

	queued atomic.Int64

	// Peaks are observability, and the only reason the tests can assert a
	// maximum rather than a sample. They never decrease.
	peakActive atomic.Int64
	peakQueued atomic.Int64

	// Counters for the same reason. Monotonic, so a scrape can difference them.
	admitted  atomic.Int64
	rejected  atomic.Int64
	cancelled atomic.Int64

	// Time spent waiting for a slot, for requests that had to wait at all.
	//
	// Queue wait is the number that distinguishes "the provider is slow" from
	// "we are overloaded", and nothing here measured it before C32. Both look
	// identical in end-to-end latency, and the two have opposite remedies: a
	// slow provider wants a longer deadline, an overloaded gateway wants more
	// slots or fewer arrivals.
	//
	// A sum and a count rather than a histogram, because the sum answers
	// "what fraction of latency is ours" and a histogram is a dependency.
	// The maximum is kept separately, since a mean hides exactly the request
	// that timed out.
	waitNanos    atomic.Int64
	waitCount    atomic.Int64
	maxWaitNanos atomic.Int64
}

// New builds a controller with fixed capacity.
func New(cfg Config) (*Controller, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Controller{
		slots:     make(chan struct{}, cfg.MaxActive),
		maxActive: cfg.MaxActive,
		maxQueued: int64(cfg.MaxQueued),
	}, nil
}

// Acquire takes a slot, waiting in the bounded queue if necessary.
//
// It returns a release function on success. That function must be called
// exactly once; it is safe to call more than once, because a double release
// would return a slot nobody held and let the limit be exceeded from then on.
//
// On failure it returns ErrQueueFull, or the context's error if the caller
// went away while waiting. The release function is nil in both cases.
func (c *Controller) Acquire(ctx context.Context) (func(), error) {
	// Refuse a context that is already finished rather than racing it into a
	// slot. Without this, a request whose deadline passed during parsing could
	// still take capacity from one that could use it.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Fast path: a free slot right now, no queueing and no bookkeeping.
	select {
	case c.slots <- struct{}{}:
		c.onAdmitted()
		return c.releaser(), nil
	default:
	}

	// No slot free, so this request has to wait — if there is room to wait.
	if c.queued.Add(1) > c.maxQueued {
		c.queued.Add(-1)
		c.rejected.Add(1)
		return nil, ErrQueueFull
	}
	c.observePeak(&c.peakQueued, c.queued.Load())
	defer c.queued.Add(-1)

	// Only the slow path is timed. A request that took a free slot waited
	// zero by construction, and reading a clock for it would charge every
	// uncontended request for a measurement that can only say "nothing
	// happened".
	queuedAt := time.Now()

	select {
	case c.slots <- struct{}{}:
		c.observeWait(time.Since(queuedAt))
		c.onAdmitted()
		return c.releaser(), nil
	case <-ctx.Done():
		// The caller hung up or ran out of deadline while queued. No slot was
		// taken, so there is nothing to release.
		//
		// The wait is still recorded. A request that waited four seconds and
		// then gave up spent four seconds of queue, and omitting it would
		// make the queue look healthiest exactly when it is worst — the
		// abandoned waits are the long ones.
		c.observeWait(time.Since(queuedAt))
		c.cancelled.Add(1)
		return nil, ctx.Err()
	}
}

func (c *Controller) observeWait(waited time.Duration) {
	nanos := waited.Nanoseconds()
	c.waitNanos.Add(nanos)
	c.waitCount.Add(1)
	c.observePeak(&c.maxWaitNanos, nanos)
}

// releaser returns a release function that cannot be made to over-release.
//
// sync.Once rather than a bare closure: a release called twice would take a
// token the caller never held, raising the effective limit permanently. That
// is a silent, cumulative failure, and the cost of preventing it is one
// allocation per request against an operation that takes seconds.
func (c *Controller) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() { <-c.slots })
	}
}

func (c *Controller) onAdmitted() {
	c.admitted.Add(1)
	c.observePeak(&c.peakActive, int64(len(c.slots)))
}

// observePeak raises a high-water mark, retrying against concurrent writers.
func (c *Controller) observePeak(peak *atomic.Int64, observed int64) {
	for {
		current := peak.Load()
		if observed <= current || peak.CompareAndSwap(current, observed) {
			return
		}
	}
}

// Stats is a snapshot for logging and for the load tests.
type Stats struct {
	Active     int
	Queued     int
	MaxActive  int
	MaxQueued  int
	PeakActive int
	PeakQueued int
	Admitted   int64
	Rejected   int64
	Cancelled  int64

	// WaitCount is how many requests queued at all; WaitTotal is their summed
	// wait and MaxWait the worst single one. Requests that took a free slot
	// immediately are not counted, so MeanWait answers "when we queued, how
	// long for" rather than diluting it across traffic that never waited.
	WaitCount int64
	WaitTotal time.Duration
	MaxWait   time.Duration
}

// MeanWait is the average wait among requests that actually queued.
func (s Stats) MeanWait() time.Duration {
	if s.WaitCount == 0 {
		return 0
	}
	return s.WaitTotal / time.Duration(s.WaitCount)
}

// Stats reports current and peak occupancy.
//
// The fields are read independently, so a snapshot taken under load is not a
// single instant. That is fine for logging and for asserting a maximum was
// never exceeded, which is the only thing it is used for.
func (c *Controller) Stats() Stats {
	return Stats{
		Active:     len(c.slots),
		Queued:     int(c.queued.Load()),
		MaxActive:  c.maxActive,
		MaxQueued:  int(c.maxQueued),
		PeakActive: int(c.peakActive.Load()),
		PeakQueued: int(c.peakQueued.Load()),
		Admitted:   c.admitted.Load(),
		Rejected:   c.rejected.Load(),
		Cancelled:  c.cancelled.Load(),
		WaitCount:  c.waitCount.Load(),
		WaitTotal:  time.Duration(c.waitNanos.Load()),
		MaxWait:    time.Duration(c.maxWaitNanos.Load()),
	}
}

// Describe renders the configured bounds for one startup log line.
func (c *Controller) Describe() string {
	return fmt.Sprintf("max active %d, max queued %d", c.maxActive, c.maxQueued)
}
