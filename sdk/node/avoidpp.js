'use strict';
/**
 * A client for POST /v1/scans, in one file with no dependencies.
 *
 * The third implementation of the same contract. It reads the same
 * expectations table as the Python and Go clients (sdk/contract-expectations
 * .json), so a disagreement between the three fails a test rather than being
 * discovered by whichever caller hits it first - which is how the Python and
 * Go clients were found to disagree about wrong-typed JSON fields.
 *
 * CommonJS and global fetch, so it runs on Node 18+ with no build step and
 * can be copied into a project rather than installed.
 *
 *   const { ScanClient, permitsTranslation, ScanFailed } = require('./avoidpp');
 *
 *   const client = new ScanClient({ baseUrl, apiKey, timeoutMs: 20000 });
 *   const verdict = await client.scan(passage, { contentId: 'doc-17' });
 *   if (permitsTranslation(verdict) && verdict.covers(passage)) {
 *     await translate(passage);
 *   }
 */

const { createHash } = require('node:crypto');

const SCAN_PATH = 'v1/scans';
const MAX_TEXT_CHARS = 32768;
const MAX_CONTENT_ID_CHARS = 128;

const ACTIONS = Object.freeze({ ALLOW: 'allow', FLAG: 'flag', BLOCK: 'block' });
const LABELS = Object.freeze({
  CLEAN: 'no_injection_detected',
  SUSPICIOUS: 'suspicious',
  UNCERTAIN: 'uncertain',
});
const CATEGORIES = Object.freeze([
  'task_redirection',
  'detector_targeting',
  'system_prompt_extraction',
  'output_format_hijack',
]);
const ERROR_CODES = Object.freeze([
  'malformed_json',
  'schema_invalid',
  'unknown_task_id',
  'unauthenticated',
  'unauthorized_task',
  'payload_too_large',
  'unsupported_media_type',
  'token_budget_exceeded',
  'rate_limited',
  'detector_unavailable',
  'overloaded',
  'deadline_exceeded',
  'internal_error',
]);

// Retry only where the server has said the work definitively did not happen.
// A scan is a paid provider call, so retrying a request that may already have
// reached the model doubles the spend to buy a verdict the caller is probably
// about to turn into a block anyway.
const RETRYABLE_CODES = Object.freeze(['rate_limited', 'overloaded']);
const RETRYABLE_STATUS = Object.freeze([429]);

// Hosts for which an unencrypted base URL is accepted. Anywhere else http://
// would put a bearer token on the wire in clear text, and the service it
// authenticates spends money.
//
// A caller on a private encrypted network - Fly's 6PN, a service mesh, a VPC
// with no egress - can add hosts with `allowPlaintextHosts`. That option
// exists because the alternative people actually choose is worse: given a
// client that refuses, they terminate TLS by publishing the gateway to the
// internet. It is deliberately a list of named hosts rather than a boolean,
// so the thing being trusted is written down and greppable.
const LOCAL_HOSTS = Object.freeze(['localhost', '127.0.0.1', '::1', '[::1]']);

/** SHA-256 over the exact UTF-8 bytes, with no normalisation of any kind. */
function digestOf(text) {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

/**
 * Base class. A scan that did not produce a usable verdict.
 *
 * No subclass carries an action, and none has a default that fills in when a
 * scan did not happen. A caller that catches this and refuses to proceed is
 * correct for every failure this client can report.
 */
class ScanFailed extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScanFailed';
  }
  get retryable() {
    return false;
  }
}

/** The request did not complete: connection, TLS, abort, or a client timeout. */
class TransportFailed extends ScanFailed {
  constructor(causeType) {
    super(`the gateway could not be reached (${causeType})`);
    this.name = 'TransportFailed';
    // The provoking error's name, never its message: an HTTP library's error
    // text can embed the request URL, and a URL can carry userinfo.
    this.causeType = causeType;
  }
}

/** The gateway answered with a failure. `code` is always set. */
class ServiceFailed extends ScanFailed {
  constructor({ status, code, requestId = null, retryAfterSeconds = null }) {
    super(`the gateway returned ${status} (${code})`);
    this.name = 'ServiceFailed';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfterSeconds = retryAfterSeconds;
  }
  get retryable() {
    return RETRYABLE_CODES.includes(this.code) || RETRYABLE_STATUS.includes(this.status);
  }
}

/** HTTP 200, and no decision this client is willing to derive from it. */
class ResponseUnusable extends ScanFailed {
  constructor(reason, detail) {
    super(`the gateway returned an unusable scan (${reason}): ${detail}`);
    this.name = 'ResponseUnusable';
    this.reason = reason;
  }
}

/**
 * The client was built or used wrongly.
 *
 * A ScanFailed rather than a TypeError, so a caller wrapping scans in
 * `catch (e) { if (e instanceof ScanFailed) refuse() }` cannot be bypassed by
 * a misconfiguration. Misconfiguration is one of the likelier ways a guard
 * ends up not guarding.
 */
class NotConfigured extends ScanFailed {
  constructor(message) {
    super(message);
    this.name = 'NotConfigured';
  }
}

/** A 200 body that parsing refused. Internal; surfaced as ResponseUnusable. */
class ResponseRejected extends Error {
  constructor(reason, detail) {
    super(`${reason}: ${detail}`);
    this.reason = reason;
  }
}

class Verdict {
  constructor(fields) {
    Object.assign(this, fields);
    Object.freeze(this);
  }

  /**
   * Whether this verdict is about exactly these bytes.
   *
   * The check an integration needs immediately before acting. A scan and a
   * translation can both be real while being about different text, and every
   * realistic bug in that shape - a trim before display, a retry carrying an
   * edit, an excerpt scanned and a document used - is this returning false.
   */
  covers(text) {
    return digestOf(text) === this.scannedDigest;
  }
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value, name) {
  if (typeof value !== 'string') {
    throw new ResponseRejected('unreadable_body', `${name} is not a string`);
  }
  return value;
}

function asInteger(value, name) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ResponseRejected('unreadable_body', `${name} is not an integer`);
  }
  return value;
}

function asBoolean(value, name) {
  if (typeof value !== 'boolean') {
    throw new ResponseRejected('unreadable_body', `${name} is not a boolean`);
  }
  return value;
}

function asObject(value, name) {
  if (!isObject(value)) {
    throw new ResponseRejected('unreadable_body', `${name} is not an object`);
  }
  return value;
}

function asArray(value, name) {
  if (!Array.isArray(value)) {
    throw new ResponseRejected('unreadable_body', `${name} is not an array`);
  }
  return value;
}

function coverageOf(raw) {
  const coverage = asObject(raw, 'coverage');
  for (const name of ['original_utf8_bytes', 'scanned_utf8_bytes', 'truncated']) {
    if (!(name in coverage)) {
      // Absent, which for `truncated` is not the same claim as false: "we do
      // not know whether this was truncated" and "it was not truncated" are
      // different statements, and only one is safe to act on.
      throw new ResponseRejected('missing_field', `coverage has no ${name}`);
    }
  }
  return {
    originalUtf8Bytes: asInteger(coverage.original_utf8_bytes, 'original_utf8_bytes'),
    scannedUtf8Bytes: asInteger(coverage.scanned_utf8_bytes, 'scanned_utf8_bytes'),
    truncated: asBoolean(coverage.truncated, 'truncated'),
  };
}

function categoriesOf(raw) {
  // Advisory - the label and action carry the decision - so a category from a
  // later contract version is dropped rather than made fatal. Safe here in a
  // way it would not be for the action, because no branch anywhere becomes
  // permissive through a category being absent.
  if (raw === undefined || raw === null) return [];
  return asArray(raw, 'categories')
    .map((item) => asString(item, 'category'))
    .filter((item) => CATEGORIES.includes(item));
}

function evidenceOf(raw) {
  if (raw === undefined || raw === null) return [];
  return asArray(raw, 'evidence').map((item) => {
    const entry = asObject(item, 'evidence item');
    const category = asString(entry.category ?? '', 'evidence category');
    return {
      contentId: asString(entry.content_id, 'evidence content_id'),
      // Untrusted text. Already verified to occur in the passage, so a
      // fabricated citation cannot reach here - but it is a fragment of
      // attacker-controlled input and needs the escaping the passage needs.
      quote: asString(entry.quote, 'evidence quote'),
      category: CATEGORIES.includes(category) ? category : null,
    };
  });
}

function versionsOf(raw) {
  // Not fatal, because versions identify a result rather than authorise
  // anything. Not silently blank either: a record that cannot say which
  // detector and prompt produced a verdict is not a record.
  const versions = raw === undefined || raw === null ? {} : asObject(raw, 'versions');
  const value = (key) => {
    if (!(key in versions)) return 'unknown';
    return asString(versions[key], `versions.${key}`) || 'unknown';
  };
  return {
    contract: value('contract'),
    detector: value('detector'),
    prompt: value('prompt'),
    policy: value('policy'),
  };
}

/**
 * Turn a 200 body into a verdict, or refuse.
 *
 * The checks run in a fixed order, and the order is the contract's reasoning
 * rather than convenience: shape, then scan status, then coverage, then label,
 * then action, then consistency. See docs/c41-sdk.md.
 */
function parseVerdict(body, sentText) {
  if (!isObject(body)) {
    throw new ResponseRejected('unreadable_body', 'the response body is not a JSON object');
  }
  for (const required of ['request_id', 'scan_status', 'assessment', 'decision', 'coverage']) {
    if (!(required in body)) {
      throw new ResponseRejected('missing_field', `the response has no '${required}'`);
    }
  }

  if (body.scan_status !== 'complete') {
    throw new ResponseRejected(
      'scan_not_complete',
      "scan_status is not 'complete', so no clean verdict is possible",
    );
  }

  const coverage = coverageOf(body.coverage);
  const sentBytes = Buffer.byteLength(sentText, 'utf8');
  if (coverage.truncated) {
    throw new ResponseRejected('coverage_truncated', 'the gateway reported the passage truncated');
  }
  if (coverage.scannedUtf8Bytes !== coverage.originalUtf8Bytes) {
    throw new ResponseRejected(
      'coverage_partial',
      `${coverage.scannedUtf8Bytes} of ${coverage.originalUtf8Bytes} bytes were scanned`,
    );
  }
  if (coverage.originalUtf8Bytes !== sentBytes) {
    throw new ResponseRejected(
      'coverage_mismatch',
      `the gateway scanned ${coverage.originalUtf8Bytes} bytes and ${sentBytes} were sent, ` +
        'so this verdict is about other text',
    );
  }

  const assessment = asObject(body.assessment, 'assessment');
  if (!('label' in assessment)) {
    throw new ResponseRejected('missing_field', 'the assessment has no label');
  }
  const label = asString(assessment.label, 'label');
  if (!Object.values(LABELS).includes(label)) {
    // Refused outright: the consistency check below cannot be performed
    // against a label whose meaning is unknown, and an unknown label is not a
    // fourth kind of clean.
    throw new ResponseRejected('unknown_label', 'the assessment label is not one this client defines');
  }

  const decision = asObject(body.decision, 'decision');
  if (!('action' in decision)) {
    throw new ResponseRejected('missing_field', 'the decision has no action');
  }
  const rawAction = asString(decision.action, 'action');
  let action = rawAction;
  let unrecognisedAction = null;
  if (!Object.values(ACTIONS).includes(rawAction)) {
    // common.schema.json: "any value not recognized by the client MUST be
    // treated as block". Not an error and not a rejection - a block. This is
    // the one place the contract tells clients what to do with data they
    // cannot understand, so the enum can grow without old clients failing
    // closed into an outage.
    action = ACTIONS.BLOCK;
    unrecognisedAction = rawAction;
  }

  if (!('reason_code' in decision)) {
    throw new ResponseRejected('missing_field', 'the decision has no reason_code');
  }
  const reasonCode = asString(decision.reason_code, 'reason_code');
  if (!reasonCode) {
    throw new ResponseRejected('missing_field', 'the decision has an empty reason_code');
  }

  // Consistency, in one direction only. A non-clean label with an allow
  // action is the exact failure this service exists to prevent, arriving as a
  // well-formed response. The mirror case - a clean label blocked anyway - is
  // honoured: a server being stricter than its schema is not a safety
  // problem, and overriding it would be this client second-guessing a
  // server-side decision.
  if (action === ACTIONS.ALLOW) {
    if (label !== LABELS.CLEAN) {
      throw new ResponseRejected(
        'allow_contradicts_label',
        `the action is allow and the label is '${label}'`,
      );
    }
    if (reasonCode !== 'clean_complete_scan') {
      throw new ResponseRejected(
        'allow_without_clean_reason',
        `the action is allow and the reason code is '${reasonCode}'`,
      );
    }
  }

  return new Verdict({
    action,
    label,
    reasonCode,
    requestId: String(body.request_id),
    categories: Object.freeze(categoriesOf(assessment.categories)),
    evidence: Object.freeze(evidenceOf(assessment.evidence)),
    coverage: Object.freeze(coverage),
    versions: Object.freeze(versionsOf(body.versions)),
    scannedDigest: digestOf(sentText),
    unrecognisedAction,
  });
}

/**
 * Whether an application may act on this verdict.
 *
 * A free function taking an explicit policy argument rather than a
 * `verdict.isSafe`, because whether a flag proceeds is a property of the
 * deployment and not of the verdict. A method would have had to pick a
 * default, and that default would become the policy of every caller who did
 * not know there was a question.
 *
 * Written as an allowlist: an action this build does not recognise does not
 * translate.
 */
function permitsTranslation(verdict, { translateOnFlag = false } = {}) {
  if (verdict.action === ACTIONS.ALLOW) return true;
  if (verdict.action === ACTIONS.FLAG) return translateOnFlag;
  return false;
}

/** How long to wait before sending a scan again. */
function retryDelayMs(failure, retry) {
  const advised = failure && failure.retryAfterSeconds;
  if (!Number.isInteger(advised) || advised < 0) return retry.fallbackDelayMs;
  // The cap is the interesting part: a gateway under load can legitimately
  // ask for 30 seconds, and a client that obeys that silently has converted
  // one slow scan into a hang.
  return Math.min(advised * 1000, retry.maxDelayMs);
}

const NO_RETRY = Object.freeze({ maxAttempts: 1, maxDelayMs: 5000, fallbackDelayMs: 500 });

class ScanClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl       gateway origin; https unless local
   * @param {string} options.apiKey        bearer token for this caller
   * @param {number} options.timeoutMs     per-attempt deadline
   * @param {string} [options.languageHint] routing metadata only
   * @param {object} [options.retry]       {maxAttempts, maxDelayMs, fallbackDelayMs}
   * @param {string[]} [options.allowPlaintextHosts] hosts reachable over http
   *   because the network itself is private and encrypted
   * @param {Function} [options.fetch]     injected for tests
   */
  constructor({
    baseUrl,
    apiKey,
    timeoutMs,
    taskId = 'translate_fi_en_v1',
    languageHint = null,
    retry = NO_RETRY,
    allowPlaintextHosts = [],
    fetch: fetchImpl = globalThis.fetch,
  } = {}) {
    if (typeof apiKey !== 'string' || apiKey === '') {
      throw new NotConfigured('apiKey must be a non-empty string');
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new NotConfigured('timeoutMs must be greater than zero');
    }
    if (typeof fetchImpl !== 'function') {
      throw new NotConfigured('no fetch implementation is available (Node 18+ or inject one)');
    }

    let parsed;
    try {
      parsed = new URL(baseUrl);
    } catch {
      throw new NotConfigured('baseUrl must be an absolute URL');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new NotConfigured('baseUrl must be an http or https URL');
    }
    if (!Array.isArray(allowPlaintextHosts)) {
      throw new NotConfigured('allowPlaintextHosts must be an array of host names');
    }
    const plaintextOk = LOCAL_HOSTS.includes(parsed.hostname) || allowPlaintextHosts.includes(parsed.hostname);
    if (parsed.protocol === 'http:' && !plaintextOk) {
      throw new NotConfigured(
        'baseUrl must use https for a non-local host, because the API key ' +
          'would otherwise be sent in clear text. Name the host in ' +
          'allowPlaintextHosts if the network between you and it is private ' +
          'and encrypted.',
      );
    }
    if (parsed.username || parsed.password) {
      // Credentials in a URL end up in logs and process listings, and this
      // client authenticates with a bearer token anyway.
      throw new NotConfigured('baseUrl must not embed credentials');
    }
    if (retry.maxAttempts < 1) {
      throw new NotConfigured('retry.maxAttempts must be at least 1');
    }

    this._url = new URL(SCAN_PATH, parsed.href.endsWith('/') ? parsed.href : parsed.href + '/').href;
    this._apiKey = apiKey;
    this._timeoutMs = timeoutMs;
    this._taskId = taskId;
    this._languageHint = languageHint;
    this._retry = { ...NO_RETRY, ...retry };
    this._fetch = fetchImpl;
  }

  /**
   * Scan one passage and return the decision, or throw.
   *
   * `text` is sent byte for byte. No trimming, no Unicode normalisation, no
   * whitespace collapsing: the bytes handed in are the bytes scanned, because
   * they are the bytes the caller is about to use.
   *
   * Throws a ScanFailed subclass on every outcome that is not a complete,
   * internally consistent verdict about exactly this passage. There is no
   * return value that means "failed".
   */
  async scan(text, { contentId } = {}) {
    if (typeof text !== 'string' || text === '') {
      throw new NotConfigured('text must be a non-empty string');
    }
    if (text.length > MAX_TEXT_CHARS) {
      throw new NotConfigured(
        `text is ${text.length} characters and the contract allows ${MAX_TEXT_CHARS}`,
      );
    }
    if (typeof contentId !== 'string' || contentId === '' || contentId.length > MAX_CONTENT_ID_CHARS) {
      throw new NotConfigured(`contentId must be 1 to ${MAX_CONTENT_ID_CHARS} characters`);
    }

    const body = {
      task_id: this._taskId,
      content: { id: contentId, source_type: 'translation_input', text },
    };
    if (this._languageHint) {
      // Routing metadata only. It never shortens, bypasses or disables a
      // scan, and the gateway treats it as an assertion by the caller rather
      // than a verified result.
      body.content.language_hint = this._languageHint;
    }

    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this._attempt(body, text);
      } catch (failure) {
        if (attempt >= this._retry.maxAttempts || !failure.retryable) throw failure;
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs(failure, this._retry)));
      }
    }
  }

  async _attempt(body, sentText) {
    let response;
    try {
      response = await this._fetch(this._url, {
        method: 'POST',
        headers: {
          // The Authorization header and nowhere else. A key in a query
          // string lands in access logs, proxy logs and referrer headers.
          Authorization: `Bearer ${this._apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        // Not followed. A redirect on an authenticated POST is an invitation
        // to send the bearer token to whatever host the Location header
        // names. 'manual' rather than 'error' so a 3xx arrives as a non-200
        // service failure, which is what it is.
        redirect: 'manual',
        signal: AbortSignal.timeout(this._timeoutMs),
      });
    } catch (exc) {
      throw new TransportFailed(exc && exc.name ? exc.name : 'Error');
    }

    if (response.status !== 200) throw await this._serviceFailure(response);

    let decoded;
    try {
      decoded = JSON.parse(await response.text());
    } catch {
      throw new ResponseUnusable('unreadable_body', 'the response body is not JSON');
    }

    try {
      return parseVerdict(decoded, sentText);
    } catch (exc) {
      if (exc instanceof ResponseRejected) throw new ResponseUnusable(exc.reason, exc.message);
      throw exc;
    }
  }

  /**
   * Classify a non-200 response.
   *
   * The status and the contract's code are read; the message is not
   * surfaced. A gateway message is ours and safe by construction, but this
   * client talks to whatever is at the base URL, and an intermediary's error
   * page is neither.
   */
  async _serviceFailure(response) {
    let code = 'unknown';
    let requestId = null;
    let retryAfterSeconds = null;

    let payload = null;
    try {
      payload = JSON.parse(await response.text());
    } catch {
      payload = null;
    }

    if (isObject(payload)) {
      if (typeof payload.request_id === 'string' && payload.request_id) {
        requestId = payload.request_id;
      }
      if (isObject(payload.error)) {
        const rawCode = payload.error.code;
        // A code from a later contract version stays 'unknown' rather than
        // becoming an absence of error.
        if (typeof rawCode === 'string' && ERROR_CODES.includes(rawCode)) code = rawCode;
        const seconds = payload.error.retry_after_seconds;
        if (Number.isInteger(seconds)) retryAfterSeconds = seconds;
      }
    }

    const header = response.headers && response.headers.get && response.headers.get('Retry-After');
    if (retryAfterSeconds === null && header) {
      const parsedHeader = Number.parseInt(String(header).trim(), 10);
      // An HTTP-date is legal here and deliberately not parsed: a date
      // requires trusting the server's clock against ours, and the fallback
      // delay is a safe answer.
      if (Number.isInteger(parsedHeader) && String(parsedHeader) === String(header).trim()) {
        retryAfterSeconds = parsedHeader;
      }
    }

    return new ServiceFailed({ status: response.status, code, requestId, retryAfterSeconds });
  }
}

module.exports = {
  ScanClient,
  Verdict,
  permitsTranslation,
  digestOf,
  parseVerdict,
  retryDelayMs,
  ScanFailed,
  TransportFailed,
  ServiceFailed,
  ResponseUnusable,
  NotConfigured,
  ACTIONS,
  LABELS,
  CATEGORIES,
  ERROR_CODES,
  RETRYABLE_CODES,
  MAX_TEXT_CHARS,
  MAX_CONTENT_ID_CHARS,
  NO_RETRY,
};
