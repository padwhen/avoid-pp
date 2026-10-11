'use strict';
/**
 * The Node half of the cross-language contract test.
 *
 * Every assertion comes from sdk/contract-expectations.json, the same table
 * the Python and Go suites read. Three implementations of one table is a
 * contract test; three suites that happen to agree are three opinions.
 *
 *   node --test sdk/node/        (or: make check-sdk-node)
 *
 * No test framework and no dependencies: node:test and node:assert ship with
 * Node, which keeps this client copy-and-paste deployable.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  ScanClient,
  ServiceFailed,
  ResponseUnusable,
  NotConfigured,
  ScanFailed,
  permitsTranslation,
  parseVerdict,
  retryDelayMs,
  digestOf,
  ERROR_CODES,
  NO_RETRY,
} = require('./avoidpp');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const TABLE = path.join(REPO_ROOT, 'sdk', 'contract-expectations.json');
const FIXTURES = path.join(REPO_ROOT, 'contracts', 'fixtures');

function loadCases() {
  const table = JSON.parse(fs.readFileSync(TABLE, 'utf8'));
  const defaultText = String(table.harness.default_request_text);

  return table.cases.map((raw) => {
    let body = null;
    let bodyText;
    if (raw.fixture !== undefined) {
      bodyText = fs.readFileSync(path.join(FIXTURES, raw.fixture), 'utf8');
      body = JSON.parse(bodyText);
    } else if ('body' in raw) {
      body = raw.body;
      bodyText = JSON.stringify(body);
    } else {
      bodyText = String(raw.raw_body);
    }

    let requestText;
    if ('request_text' in raw) {
      requestText = String(raw.request_text);
    } else if (body !== null && typeof body === 'object' && body.coverage && typeof body.coverage === 'object') {
      // A passage of exactly the byte count the response claims, so the
      // client's byte cross-check participates in the case instead of being
      // the thing that trips every fixture.
      requestText = 'a'.repeat(Number(body.coverage.original_utf8_bytes));
    } else {
      requestText = defaultText;
    }

    return {
      name: String(raw.name),
      status: Number(raw.status),
      rawBody: bodyText,
      headers: raw.headers || {},
      requestText,
      expect: raw.expect,
      fixture: raw.fixture,
    };
  });
}

const CASES = loadCases();

/** A fetch that answers with one case's wire shape and records the request. */
function clientFor(testCase, sent = {}) {
  const fetchImpl = async (url, init) => {
    sent.url = url;
    sent.init = init;
    // 204, 205 and 304 are null-body statuses: the Response constructor
    // throws if given a body with one, even an empty string. Passing null
    // keeps the case about the client rather than about the harness - and
    // this is how the 204 case first failed.
    const nullBody = [204, 205, 304].includes(testCase.status);
    return new Response(nullBody ? null : testCase.rawBody, {
      status: testCase.status,
      headers: { 'Content-Type': 'application/json', ...testCase.headers },
    });
  };
  return new ScanClient({
    baseUrl: 'https://gateway.test',
    apiKey: 'k'.repeat(32),
    timeoutMs: 5000,
    fetch: fetchImpl,
  });
}

for (const testCase of CASES) {
  test(`contract: ${testCase.name}`, async () => {
    const client = clientFor(testCase);
    const expect = testCase.expect;

    if (expect.outcome === 'verdict') {
      const verdict = await client.scan(testCase.requestText, { contentId: 'case-1' });
      assert.equal(verdict.action, expect.action);
      assert.equal(verdict.label, expect.label);
      assert.equal(verdict.reasonCode, expect.reason_code);
      assert.equal(verdict.unrecognisedAction, expect.unrecognised_action ?? null);
      // The verdict is about the passage that was sent, and says so.
      assert.equal(verdict.covers(testCase.requestText), true);
      assert.equal(verdict.covers(testCase.requestText + ' '), false);
      if (expect.no_field_named) {
        assert.equal(Object.hasOwn(verdict, expect.no_field_named), false);
      }
      return;
    }

    if (expect.outcome === 'error') {
      const failure = await client.scan(testCase.requestText, { contentId: 'case-1' }).then(
        () => null,
        (exc) => exc,
      );
      assert.ok(failure instanceof ServiceFailed, `expected ServiceFailed, got ${failure}`);
      assert.equal(failure.code, expect.code);
      assert.equal(failure.status, testCase.status);
      assert.equal(failure.retryable, expect.retries);
      if ('retry_after_seconds' in expect) {
        assert.equal(failure.retryAfterSeconds, expect.retry_after_seconds);
      }
      if (expect.no_field_named) {
        assert.equal(expect.no_field_named in failure, false);
      }
      return;
    }

    if (expect.outcome === 'rejected') {
      const failure = await client.scan(testCase.requestText, { contentId: 'case-1' }).then(
        () => null,
        (exc) => exc,
      );
      assert.ok(failure instanceof ResponseUnusable, `expected ResponseUnusable, got ${failure}`);
      assert.equal(failure.reason, expect.reason);
      // A rejection is never retried: the same request would get the same
      // contradictory answer.
      assert.equal(failure.retryable, false);
      return;
    }

    throw new Error(`unknown expected outcome ${expect.outcome}`);
  });
}

test('every contract fixture has an expectation', () => {
  // Without this, adding a fixture to contracts/fixtures/ would leave the
  // clients untested against it, and the omission would look like coverage.
  const listed = new Set(CASES.map((c) => c.fixture).filter(Boolean));
  const onDisk = new Set();
  for (const kind of ['valid', 'invalid']) {
    for (const name of fs.readdirSync(path.join(FIXTURES, kind))) {
      if (name.endsWith('.json') && (name.startsWith('scan-response.') || name.startsWith('error.'))) {
        onDisk.add(`${kind}/${name}`);
      }
    }
  }
  for (const name of onDisk) assert.ok(listed.has(name), `fixture with no expectation: ${name}`);
  for (const name of listed) assert.ok(onDisk.has(name), `expectation names a missing fixture: ${name}`);
});

test('the passage is sent byte for byte, and only in the content field', async () => {
  const sent = {};
  const passage = '  Hei. Tama​ on  teksti\r\n  ';
  const client = clientFor(
    { ...CASES.find((c) => c.expect.outcome === 'verdict'), requestText: passage },
    sent,
  );
  const body = JSON.parse(
    await (async () => {
      await client.scan(passage, { contentId: 'bytes-1' }).catch(() => {});
      return sent.init.body;
    })(),
  );
  assert.equal(body.content.text, passage, 'the client altered the passage');
  assert.equal(body.task_id, 'translate_fi_en_v1');
  assert.equal(body.content.source_type, 'translation_input');
  // The key travels in the header and nowhere else.
  assert.equal(JSON.stringify(body).includes('k'.repeat(32)), false);
  assert.equal(sent.init.headers.Authorization, `Bearer ${'k'.repeat(32)}`);
  assert.equal(sent.init.redirect, 'manual');
});

test('a flag does not translate unless the deployment says so', () => {
  const verdict = parseVerdict(
    {
      request_id: 'r1',
      scan_status: 'complete',
      assessment: { label: 'suspicious', categories: [], evidence: [] },
      decision: { action: 'flag', reason_code: 'suspicious_monitoring' },
      coverage: { original_utf8_bytes: 1, scanned_utf8_bytes: 1, truncated: false },
    },
    'a',
  );
  assert.equal(permitsTranslation(verdict), false);
  assert.equal(permitsTranslation(verdict, { translateOnFlag: true }), true);
});

test('an unrecognised action is a block, and never translates', () => {
  const verdict = parseVerdict(
    {
      request_id: 'r1',
      scan_status: 'complete',
      assessment: { label: 'suspicious', categories: [], evidence: [] },
      decision: { action: 'quarantine', reason_code: 'suspicious_enforced' },
      coverage: { original_utf8_bytes: 1, scanned_utf8_bytes: 1, truncated: false },
    },
    'a',
  );
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.unrecognisedAction, 'quarantine');
  assert.equal(permitsTranslation(verdict, { translateOnFlag: true }), false);
});

test('misconfiguration is a ScanFailed, so a catch-and-refuse cannot be bypassed', () => {
  const bad = [
    { baseUrl: 'http://guard.example.com', apiKey: 'k', timeoutMs: 1000 },
    { baseUrl: 'https://u:p@guard.example.com', apiKey: 'k', timeoutMs: 1000 },
    { baseUrl: 'ftp://guard.example.com', apiKey: 'k', timeoutMs: 1000 },
    { baseUrl: 'not-a-url', apiKey: 'k', timeoutMs: 1000 },
    { baseUrl: 'https://guard.example.com', apiKey: '', timeoutMs: 1000 },
    { baseUrl: 'https://guard.example.com', apiKey: 'k', timeoutMs: 0 },
  ];
  for (const options of bad) {
    assert.throws(() => new ScanClient({ ...options, fetch: async () => new Response('{}') }), ScanFailed);
  }
  // Localhost over http is the one exception, and it is deliberate: the key
  // never leaves the machine.
  assert.doesNotThrow(
    () =>
      new ScanClient({
        baseUrl: 'http://localhost:8099',
        apiKey: 'k',
        timeoutMs: 1000,
        fetch: async () => new Response('{}'),
      }),
  );
});

test('plaintext to a named private host is allowed, and only to that host', () => {
  const build = (baseUrl, allowPlaintextHosts) =>
    new ScanClient({
      baseUrl,
      apiKey: 'k',
      timeoutMs: 1000,
      allowPlaintextHosts,
      fetch: async () => new Response('{}'),
    });

  // The case this exists for: a private, encrypted network where the
  // alternative to allowing this is publishing the gateway to the internet.
  assert.doesNotThrow(() => build('http://guard.internal:8080', ['guard.internal']));

  // Naming one host does not widen the rule to any other.
  assert.throws(() => build('http://other.internal:8080', ['guard.internal']), ScanFailed);
  // And it is a list of hosts, not a boolean that can be set to true once.
  assert.throws(() => build('http://guard.internal:8080', true), ScanFailed);
  assert.throws(() => build('http://guard.internal:8080', []), ScanFailed);
  // https is unaffected either way.
  assert.doesNotThrow(() => build('https://guard.example.com', []));
});

test('a transport failure reports a type, never a message', async () => {
  const client = new ScanClient({
    baseUrl: 'https://gateway.test',
    apiKey: 'k',
    timeoutMs: 1000,
    fetch: async () => {
      const exc = new Error('connect ECONNREFUSED https://u:secret@gateway.test/v1/scans');
      exc.name = 'TypeError';
      throw exc;
    },
  });
  const failure = await client.scan('passage', { contentId: 'c' }).then(null, (exc) => exc);
  assert.equal(failure.causeType, 'TypeError');
  assert.equal(failure.message.includes('secret'), false);
  assert.equal(failure.retryable, false);
});

test('a scan is retried only when the server said it did not happen', async () => {
  let calls = 0;
  const client = new ScanClient({
    baseUrl: 'https://gateway.test',
    apiKey: 'k',
    timeoutMs: 1000,
    retry: { maxAttempts: 3, maxDelayMs: 5, fallbackDelayMs: 1 },
    fetch: async () => {
      calls += 1;
      if (calls < 3) {
        return new Response(JSON.stringify({ request_id: 'r', error: { code: 'rate_limited' } }), {
          status: 429,
        });
      }
      return new Response(
        JSON.stringify({
          request_id: 'r',
          scan_status: 'complete',
          assessment: { label: 'no_injection_detected', categories: [], evidence: [] },
          decision: { action: 'allow', reason_code: 'clean_complete_scan' },
          coverage: { original_utf8_bytes: 1, scanned_utf8_bytes: 1, truncated: false },
        }),
        { status: 200 },
      );
    },
  });
  const verdict = await client.scan('a', { contentId: 'c' });
  assert.equal(verdict.action, 'allow');
  assert.equal(calls, 3);

  // And a non-retryable failure is attempted exactly once, because a scan is
  // a paid provider call.
  let once = 0;
  const strict = new ScanClient({
    baseUrl: 'https://gateway.test',
    apiKey: 'k',
    timeoutMs: 1000,
    retry: { maxAttempts: 3, maxDelayMs: 5, fallbackDelayMs: 1 },
    fetch: async () => {
      once += 1;
      return new Response(JSON.stringify({ request_id: 'r', error: { code: 'detector_unavailable' } }), {
        status: 503,
      });
    },
  });
  await strict.scan('a', { contentId: 'c' }).catch(() => {});
  assert.equal(once, 1);
});

test('an advised retry delay is capped, and a nonsense one falls back', () => {
  const retry = { maxAttempts: 2, maxDelayMs: 5000, fallbackDelayMs: 500 };
  assert.equal(retryDelayMs({ retryAfterSeconds: 2 }, retry), 2000);
  assert.equal(retryDelayMs({ retryAfterSeconds: 30 }, retry), 5000);
  assert.equal(retryDelayMs({ retryAfterSeconds: -1 }, retry), 500);
  assert.equal(retryDelayMs({ retryAfterSeconds: null }, retry), 500);
  assert.equal(retryDelayMs({}, retry), 500);
});

test('the digest is over exact UTF-8 bytes, with no normalisation', () => {
  // Composed vs decomposed a-umlaut: visually identical, different bytes.
  assert.notEqual(digestOf('ä'), digestOf('ä'));
  assert.notEqual(digestOf('a'), digestOf('a '));
  assert.equal(digestOf('Hei'), digestOf('Hei'));
});

test('every error code the contract defines is one this client names', () => {
  const schema = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, 'contracts', 'schemas', 'error.schema.json'), 'utf8'),
  );
  const defined = schema.properties.error.properties.code.enum;
  for (const code of defined) {
    assert.ok(ERROR_CODES.includes(code), `the client does not name error code ${code}`);
  }
  assert.equal(NO_RETRY.maxAttempts, 1, 'the default must be one attempt: a scan costs money');
});
