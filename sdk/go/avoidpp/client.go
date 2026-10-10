package avoidpp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// scanPath is the only endpoint this client calls.
const scanPath = "v1/scans"

// maxFailureBodyBytes bounds what is read from a failure response.
//
// A failure body is an error envelope of at most a few hundred bytes. The
// limit is here because the thing at the base URL is not necessarily the
// gateway, and an intermediary's error page can be arbitrarily large.
const maxFailureBodyBytes = 64 << 10

// maxScanBodyBytes bounds what is read from a 200 response.
//
// A scan response carries up to eight evidence quotations of 512 characters
// each, so this is generous by two orders of magnitude and still finite. An
// unbounded read on a response is a way for a compromised or confused server
// to exhaust a client's memory.
const maxScanBodyBytes = 1 << 20

// localHosts are the hosts for which an unencrypted base URL is accepted.
//
// Anywhere else, http:// would put a bearer token on the wire in clear text,
// and the service it authenticates spends money.
var localHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// Retry says when to send a scan again.
//
// The zero value is one attempt and no retries, which is the right default: a
// scan is a paid provider call, and a retry that is not certain the first
// attempt failed is a way to spend twice for one verdict.
type Retry struct {
	// MaxAttempts counts the first attempt. Zero means one attempt.
	MaxAttempts int
	// MaxDelay caps the wait, however long the server asked for. A gateway
	// under load can legitimately advise 30 seconds, and a client that obeys
	// silently has turned one slow scan into a hang.
	MaxDelay time.Duration
	// FallbackDelay is used when a retryable failure carries no advice.
	FallbackDelay time.Duration
}

func (r Retry) attempts() int {
	if r.MaxAttempts < 1 {
		return 1
	}
	return r.MaxAttempts
}

// Options configures a Client.
type Options struct {
	// BaseURL of the gateway. https, unless the host is loopback.
	BaseURL string
	// APIKey is sent as a bearer token and nowhere else.
	APIKey string
	// Timeout bounds one attempt, end to end. Required: there is no default,
	// because the right value depends on the gateway's configured scan budget
	// and the failure of omitting it is a stalled application rather than an
	// error.
	Timeout time.Duration
	// TaskID defaults to TaskTranslateFiEnV1.
	TaskID TaskID
	// LanguageHint is routing metadata only - it never shortens, bypasses or
	// disables a scan. Empty omits it.
	LanguageHint string
	// Retry is no retries unless set.
	Retry Retry
	// HTTPClient replaces the one this package would build. Its Timeout and
	// CheckRedirect are overwritten: a redirect on an authenticated POST is
	// an invitation to send the bearer token to whatever host the Location
	// header names, and that is not a caller's decision to reverse.
	HTTPClient *http.Client
}

// Client calls POST /v1/scans.
//
// Thin, and the thinness is the feature. Every convenience a client like this
// could grow - a cached verdict, a fallback, a circuit breaker that opens into
// allow - is a way for a passage to reach a model without having been
// scanned. So it builds the request, sends it, classifies the outcome, and
// refuses.
//
// Safe for concurrent use.
type Client struct {
	baseURL      *url.URL
	apiKey       string
	taskID       TaskID
	languageHint string
	retry        Retry
	http         *http.Client
}

// New validates the options and returns a client.
//
// Every check here is a way a guard ends up not guarding, so each is a
// startup failure rather than something discovered on the first real passage.
func New(opts Options) (*Client, error) {
	if opts.APIKey == "" {
		return nil, &ConfigError{Detail: "APIKey must not be empty"}
	}
	if opts.Timeout <= 0 {
		return nil, &ConfigError{Detail: "Timeout must be greater than zero"}
	}
	if opts.Retry.MaxDelay < 0 || opts.Retry.FallbackDelay < 0 {
		return nil, &ConfigError{Detail: "retry delays must not be negative"}
	}

	parsed, err := url.Parse(opts.BaseURL)
	if err != nil {
		// err quotes the offending URL, which may carry userinfo.
		return nil, &ConfigError{Detail: "BaseURL must be a valid URL"}
	}
	switch {
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return nil, &ConfigError{Detail: "BaseURL must be an http or https URL"}
	case parsed.Hostname() == "":
		return nil, &ConfigError{Detail: "BaseURL must include a host"}
	case parsed.User != nil:
		// Credentials in a URL reach logs and process listings, and this
		// client authenticates with a bearer token anyway.
		return nil, &ConfigError{Detail: "BaseURL must not embed credentials"}
	case parsed.Scheme == "http" && !localHosts[parsed.Hostname()]:
		return nil, &ConfigError{Detail: "BaseURL must use https for a " +
			"non-local host, because the API key would otherwise be sent in " +
			"clear text"}
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	httpClient.Timeout = opts.Timeout
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	taskID := opts.TaskID
	if taskID == "" {
		taskID = TaskTranslateFiEnV1
	}

	return &Client{
		baseURL:      parsed,
		apiKey:       opts.APIKey,
		taskID:       taskID,
		languageHint: opts.LanguageHint,
		retry:        opts.Retry,
		http:         httpClient,
	}, nil
}

// String is redacted, always.
//
// A client value reaches a log line, a panic dump or a debugger eventually,
// and the default rendering of the struct would carry the key into all three.
func (c *Client) String() string {
	return fmt.Sprintf("avoidpp.Client{BaseURL: %q, APIKey: <redacted>}", c.baseURL.String())
}

// Input is one passage to scan.
type Input struct {
	// Text is sent byte for byte. No trimming, no Unicode normalisation, no
	// whitespace collapsing: these are the bytes the caller is about to use,
	// so they are the bytes that get scanned. A client that tidied the
	// passage first would produce a verdict about text existing nowhere else.
	Text string
	// ContentID is echoed back on evidence so a quote can be traced.
	ContentID string
}

// scanRequest is the wire body.
//
// There is deliberately no field for policy, mode, threshold or trust level.
// The scan request schema has none, so a caller cannot weaken its own scan,
// and a client that invented one would be sending something the gateway
// rejects.
type scanRequest struct {
	TaskID  TaskID `json:"task_id"`
	Content struct {
		ID           string     `json:"id"`
		SourceType   SourceType `json:"source_type"`
		LanguageHint string     `json:"language_hint,omitempty"`
		Text         string     `json:"text"`
	} `json:"content"`
}

// Scan scans one passage and returns the decision.
//
// Every outcome that is not a complete, internally consistent verdict about
// exactly this passage returns an error wrapping ErrScanFailed. There is no
// return value that means "the scan did not happen", and the zero Verdict
// permits nothing - so a caller who ignores the error still does not get an
// allow.
func (c *Client) Scan(ctx context.Context, in Input) (Verdict, error) {
	if in.Text == "" {
		// The contract requires a non-empty passage, and sending an empty one
		// would spend a round trip to be told so.
		return Verdict{}, &ConfigError{Detail: "Text must not be empty"}
	}
	if len([]rune(in.Text)) > MaxTextChars {
		return Verdict{}, &ConfigError{Detail: fmt.Sprintf(
			"Text is %d characters and the contract allows %d",
			len([]rune(in.Text)), MaxTextChars)}
	}
	if in.ContentID == "" || len(in.ContentID) > MaxContentIDChars {
		return Verdict{}, &ConfigError{Detail: fmt.Sprintf(
			"ContentID must be 1 to %d characters", MaxContentIDChars)}
	}

	var body scanRequest
	body.TaskID = c.taskID
	body.Content.ID = in.ContentID
	body.Content.SourceType = SourceTranslationInput
	body.Content.LanguageHint = c.languageHint
	body.Content.Text = in.Text

	encoded, err := json.Marshal(body)
	if err != nil {
		return Verdict{}, &ConfigError{Detail: "the passage could not be encoded"}
	}

	for attempt := 1; ; attempt++ {
		verdict, err := c.attempt(ctx, encoded, in.Text)
		if err == nil {
			return verdict, nil
		}
		if attempt >= c.retry.attempts() || !Retryable(err) {
			return Verdict{}, err
		}
		if waitErr := sleep(ctx, c.delayFor(err)); waitErr != nil {
			// The caller's context ended while waiting. Report that rather
			// than the retryable failure: the reason this scan has no verdict
			// is now the cancellation.
			return Verdict{}, &TransportError{
				CauseType: "ContextDone",
				cause:     waitErr,
			}
		}
	}
}

func (c *Client) attempt(ctx context.Context, body []byte, sentText string) (Verdict, error) {
	endpoint := c.baseURL.JoinPath(scanPath).String()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, &ConfigError{Detail: "the request could not be built"}
	}
	// The Authorization header, and nowhere else. A key in a query string
	// lands in access logs, proxy logs, browser history and referrer headers.
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return Verdict{}, &TransportError{CauseType: causeTypeOf(err), cause: err}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Verdict{}, c.serviceFailure(response)
	}

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxScanBodyBytes))
	if err != nil {
		return Verdict{}, &TransportError{CauseType: causeTypeOf(err), cause: err}
	}
	return ParseVerdict(raw, sentText)
}

// serviceFailure classifies a non-200 response.
//
// The status and the contract's code are read; the message is not surfaced. A
// gateway message is ours and safe by construction, but this client talks to
// whatever is at the base URL, and an intermediary's error page is neither.
func (c *Client) serviceFailure(response *http.Response) error {
	failure := &ServiceError{Status: response.StatusCode, Code: CodeUnknown}

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxFailureBodyBytes))
	if err == nil {
		var envelope struct {
			RequestID string `json:"request_id"`
			Error     *struct {
				Code              ErrorCode `json:"code"`
				RetryAfterSeconds *int      `json:"retry_after_seconds"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			failure.RequestID = envelope.RequestID
			if envelope.Error != nil {
				if envelope.Error.Code.Known() {
					failure.Code = envelope.Error.Code
				}
				if envelope.Error.RetryAfterSeconds != nil {
					failure.RetryAfterSeconds = *envelope.Error.RetryAfterSeconds
					failure.HasRetryAfter = true
				}
			}
		}
	}

	if !failure.HasRetryAfter {
		if header := response.Header.Get("Retry-After"); header != "" {
			if seconds, convErr := strconv.Atoi(strings.TrimSpace(header)); convErr == nil {
				failure.RetryAfterSeconds = seconds
				failure.HasRetryAfter = true
			}
			// An HTTP-date is legal here and deliberately not parsed: a date
			// means trusting the server's clock against ours, and the
			// fallback delay is a safe answer.
		}
	}
	return failure
}

// delayFor is how long to wait before sending a scan again.
func (c *Client) delayFor(err error) time.Duration {
	var service *ServiceError
	if errors.As(err, &service) && service.HasRetryAfter && service.RetryAfterSeconds >= 0 {
		advised := time.Duration(service.RetryAfterSeconds) * time.Second
		if advised > c.retry.MaxDelay {
			return c.retry.MaxDelay
		}
		return advised
	}
	return c.retry.FallbackDelay
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// causeTypeOf names the failure without quoting its message.
//
// A transport error's text embeds the URL, and a URL can carry userinfo. The
// two context cases are named rather than reported as *url.Error, because
// "the caller gave up" and "the gateway is unreachable" are different things
// to see in a log.
func causeTypeOf(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "DeadlineExceeded"
	case errors.Is(err, context.Canceled):
		return "Canceled"
	default:
		return fmt.Sprintf("%T", err)
	}
}
