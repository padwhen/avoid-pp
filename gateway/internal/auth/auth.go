// Package auth authenticates application callers and authorises them per task.
//
// It is deliberately free of HTTP response concerns: it resolves a presented
// credential to a caller, or reports why it could not. Turning that into a 401
// or a 403 belongs to the api package, which owns the error envelope.
//
// Three properties are worth stating outright:
//
//   - Keys are compared in constant time, against their SHA-256 rather than
//     their plaintext. A byte-by-byte string comparison leaks the length of
//     the matching prefix through timing, which is enough to recover a key one
//     character at a time. Hashing first also makes every comparison
//     fixed-length, so the loop cannot reveal how long the real key is.
//   - Identity comes from the credential, never from the request body. A
//     caller cannot name its own tenant, role, or permitted task; it presents
//     a key and the server decides what that key may do.
//   - A weak key is refused at startup. A development key short enough to
//     guess is not a development convenience, it is an open door that nobody
//     remembers to close.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

// MinKeyLength is the shortest credential accepted at startup.
//
// 32 characters of mixed alphabet is well past brute force. The check exists
// because the failure it prevents is a human one: a key like "test" added
// during development and never rotated.
const MinKeyLength = 32

var (
	// ErrNoCredential means no credential was presented at all.
	ErrNoCredential = errors.New("no credential presented")
	// ErrUnknownCredential means a credential was presented and did not match.
	ErrUnknownCredential = errors.New("unknown credential")
)

// Caller is an authenticated application, as the server understands it.
//
// Every field comes from configuration. None of it is readable from, or
// influenced by, the request body.
type Caller struct {
	Name  string
	tasks map[contract.TaskID]bool
}

// MayUse reports whether this caller is authorised for a task.
//
// The zero Caller has a nil task set and so may use nothing: an unauthenticated
// request that somehow reached a handler is denied rather than waved through.
func (c Caller) MayUse(task contract.TaskID) bool { return c.tasks[task] }

// Tasks lists the permitted tasks, sorted, for startup logging.
func (c Caller) Tasks() []string {
	out := make([]string, 0, len(c.tasks))
	for task := range c.tasks {
		out = append(out, string(task))
	}
	sort.Strings(out)
	return out
}

type entry struct {
	caller Caller
	digest [sha256.Size]byte
}

// KeySpec is one configured caller.
type KeySpec struct {
	Name  string
	Key   string
	Tasks []contract.TaskID
}

// Registry holds the configured callers.
type Registry struct {
	entries []entry
}

// NewRegistry validates and loads the configured callers.
//
// An empty set is rejected rather than treated as "allow everyone": a service
// configured with no keys should refuse to start, not silently open.
//
// A caller name may appear more than once, with a different key each time.
// That is what makes a key change possible without downtime: the replacement
// is added, callers move over, and the old entry is then removed. Repeated
// names must declare the same task set, because otherwise which tasks a
// caller may use would depend on which of its own keys it happened to
// present, and that is a difference nobody would predict from the config.
func NewRegistry(specs []KeySpec) (*Registry, error) {
	if len(specs) == 0 {
		return nil, errors.New("no API keys configured")
	}

	reg := &Registry{}
	tasksByName := map[string][]string{}
	seenDigests := map[[sha256.Size]byte]string{}

	for _, spec := range specs {
		// Every message below names the caller and the requirement, never the
		// key. Configuration errors are logged, and a message that quotes the
		// offending value has just written a credential to the log.
		if spec.Name == "" {
			return nil, errors.New("a configured key has no caller name")
		}
		if len(spec.Key) < MinKeyLength {
			return nil, fmt.Errorf(
				"key for caller %q is shorter than %d characters", spec.Name, MinKeyLength)
		}
		if len(spec.Tasks) == 0 {
			return nil, fmt.Errorf("caller %q is permitted no tasks", spec.Name)
		}

		digest := sha256.Sum256([]byte(spec.Key))
		if other, clash := seenDigests[digest]; clash {
			// Two callers sharing a key makes their requests indistinguishable,
			// which defeats both revocation and attribution.
			return nil, fmt.Errorf("callers %q and %q share a key", other, spec.Name)
		}
		seenDigests[digest] = spec.Name

		tasks := make(map[contract.TaskID]bool, len(spec.Tasks))
		named := make([]string, 0, len(spec.Tasks))
		for _, task := range spec.Tasks {
			if !task.Valid() {
				// Authorising a caller for a task the contract does not define
				// is almost always a typo, and a typo here would silently
				// grant nothing rather than what was intended.
				return nil, fmt.Errorf("caller %q: unknown task_id", spec.Name)
			}
			tasks[task] = true
			named = append(named, string(task))
		}
		sort.Strings(named)

		if previous, repeated := tasksByName[spec.Name]; repeated {
			if !slices.Equal(previous, named) {
				return nil, fmt.Errorf(
					"caller %q appears twice with different task sets", spec.Name)
			}
		}
		tasksByName[spec.Name] = named

		reg.entries = append(reg.entries, entry{
			caller: Caller{Name: spec.Name, tasks: tasks},
			digest: digest,
		})
	}
	return reg, nil
}

// Callers lists the distinct configured callers, sorted, for startup logging.
//
// A caller holding two keys mid-rotation appears once; KeyCount reports how
// many keys are live, which is the number an operator checks after finishing
// a rotation to confirm the old one is gone.
func (r *Registry) Callers() []Caller {
	seen := map[string]bool{}
	out := make([]Caller, 0, len(r.entries))
	for _, e := range r.entries {
		if seen[e.caller.Name] {
			continue
		}
		seen[e.caller.Name] = true
		out = append(out, e.caller)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// KeyCount reports how many keys are configured across all callers.
func (r *Registry) KeyCount() int { return len(r.entries) }

// Authenticate resolves a presented credential to a caller.
//
// Every configured entry is compared even after a match, so the time taken
// does not reveal how early in the list a key sits.
func (r *Registry) Authenticate(presented string) (Caller, error) {
	if presented == "" {
		return Caller{}, ErrNoCredential
	}

	digest := sha256.Sum256([]byte(presented))
	var found Caller
	matched := 0

	for _, e := range r.entries {
		if subtle.ConstantTimeCompare(digest[:], e.digest[:]) == 1 {
			found = e.caller
			matched++
		}
	}
	if matched == 0 {
		return Caller{}, ErrUnknownCredential
	}
	return found, nil
}

// CredentialFrom extracts a presented key from a request.
//
// Only the Authorization header is read. A key in a query string lands in
// access logs, proxy logs, browser history and referrer headers, so that
// spelling is not accepted at all rather than accepted and warned about.
func CredentialFrom(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

type contextKey struct{}

// WithCaller stores the authenticated caller on a request context.
func WithCaller(ctx context.Context, caller Caller) context.Context {
	return context.WithValue(ctx, contextKey{}, caller)
}

// CallerFrom returns the authenticated caller. The second result is false if
// the request did not pass through authentication, which handlers treat as a
// failure rather than as an anonymous caller.
func CallerFrom(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(contextKey{}).(Caller)
	return caller, ok
}
