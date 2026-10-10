# C19 · Authenticating application callers

The gateway serves scans only to configured callers, and only for the tasks
those callers are configured to use. Health endpoints stay open.

Configuration format, key generation, replacement and revocation are in
[configuration.md](configuration.md). This document covers why the design is
shaped the way it is.

## What this does and does not protect

It establishes *who is asking*, which is what makes rate limits (C21),
admission control (C22) and per-caller audit (C23) attributable to somebody.
It is not a defence against prompt injection: the attacker in the threat model
is the text inside a passage, not the application sending it. A fully
authenticated caller submits hostile passages all day — that is the whole job.

So authentication's contribution is narrower than it looks. It stops an
unrelated process on the same network from spending the provider budget, and
it makes abuse traceable to a caller rather than to a request id.

## Constant-time comparison, over digests

Keys are compared with `subtle.ConstantTimeCompare` against their SHA-256,
never as plaintext strings.

A byte-by-byte comparison returns as soon as it finds a difference, so the time
it takes reveals how long the matching prefix was. That is enough to recover a
key one character at a time: guess, measure, keep the guess that took longest.
Hashing before comparing adds a second property — every comparison is over 32
bytes regardless of what was presented, so the loop cannot reveal how long the
real key is either.

Every configured entry is compared even after a match, so the time taken does
not reveal how early in the list a key sits.

The test for this asserts the property the code depends on — fixed-length
digests — rather than attempting to measure timing, which is too noisy on
shared CI to fail honestly.

## Identity comes from the credential

A caller presents a key. The server decides what that key may do. There is no
request field for a caller name, a tenant, a role or a task grant, and the
decoder rejects unknown fields, so adding one produces a 400 rather than being
ignored.

This is the same rule the policy mode already follows, for the same reason: a
request that can describe its own privileges has none.

## Where each check happens

Authentication is middleware wrapped around the scan route. Authorisation is
in the handler, because which task a request asks for is in its body, and the
body is not parsed, bounded or validated until the handler runs. Peeking at it
from middleware would mean reading it twice or buffering it ahead of the size
limit.

Both run before the detector is called. That ordering is the part worth
testing: authentication that returns a 401 after spending a provider request
has protected the response code and nothing else. The tests assert a call
count of zero on every rejected path, against a detector fake that would
otherwise answer successfully.

Authentication also runs before parsing, so an unauthenticated caller learns
nothing about the request schema and a malformed body from a stranger costs no
work.

## Status codes

| Situation | Status | Code |
| --- | --- | --- |
| No credential | 401 | `unauthenticated` |
| Unrecognised credential | 401 | `unauthenticated` |
| Credential in a query string | 401 | `unauthenticated` |
| Known caller, task not granted | 403 | `unauthorized_task` |
| Known caller, task not in the contract | 422 | `unknown_task_id` |

The two 401 rows produce byte-identical responses. Distinguishing "no
credential" from "wrong credential" tells a prober whether a credential
exists, and the caller's own fix is the same either way.

An unknown task is 422 rather than 403 because the task list is published
contract: saying it does not exist discloses nothing, while reporting it as a
permission problem would send a caller to file an access request for what was
actually a typo.

A rejected caller still receives a request id, in the body and the
`X-Request-Id` header, because without one they cannot ask about the rejection
and the log line recording it cannot be found.

## Fail-closed choices

- A registry with no keys is rejected at startup. A service configured with no
  callers should refuse to start, not accept everybody.
- The scan route is not registered at all when the caller registry is nil, so
  it 404s. A route that scans for anybody is worse than a missing route, and
  this makes a wiring mistake a startup-visible absence rather than an open
  endpoint.
- The handler refuses a request whose context carries no caller. A route wired
  up without the middleware fails loudly instead of serving anonymous scans.
- The zero `Caller` value permits nothing, so an uninitialised caller cannot
  be mistaken for a privileged one.
- Two callers configured with the same key is a startup error. Sharing a key
  makes their requests indistinguishable, which breaks revocation and
  attribution at once.

## Where the credential is read from

Only the `Authorization: Bearer` header. A key in a query string is recorded
by every proxy on the path, plus browser history and referrer headers, so that
spelling is not read at all rather than read and deprecated. A test asserts
the query string is ignored.

## Secrets

- No key appears in any error message. Configuration errors name the caller
  and the requirement; parse errors name the entry's position. Tests assert
  that neither a full key nor a 12-character prefix of one appears, because a
  prefix is still a credential — it narrows a brute force.
- No key appears in any log line. Rejections log the reason (`no_credential`,
  `unknown_credential`), the request id and the remote address. A mistyped key
  is still a key, and a near-miss in a log is a credential in a log.
- No key appears in a response body or header, including the rejection that
  was caused by it.
- The loaded configuration holds digests, not keys, so a config dump carries
  no credential.
- `.env` is gitignored, and `.env.example` carries no key — only the format.
- CI greps the tree for `${{ secrets.` to catch a workflow interpolating one
  into a command line.

## The open question this commit does not answer

The planned first caller, a language-learning application, has no
authenticated service identity of its own today. If the guard ends up deployed
as a private-network service reachable only from that application, most of
this commit and most of C21's per-caller limits would be the wrong shape —
network reachability would be the boundary, and per-caller keys would be
ceremony around a single trusted caller.

It is built as specified because the alternative is deciding the deployment
topology by omission, and because the caller identity it establishes is what
C21, C22 and C23 attribute their behaviour to. Worth settling before C21.
