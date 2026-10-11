# Node client

One file, no dependencies, no build step.

```sh
make check-sdk-node     # 58 tests: the 48-case contract table plus client rules
```

```js
const { ScanClient, permitsTranslation, ScanFailed } = require('./avoidpp');

const client = new ScanClient({
  baseUrl: process.env.AVOIDPP_URL,   // https, unless localhost
  apiKey: process.env.AVOIDPP_KEY,
  timeoutMs: 20000,
  languageHint: 'fi',
});

const verdict = await client.scan(text, { contentId: 'sentence-17' });
if (permitsTranslation(verdict) && verdict.covers(text)) {
  await translate(text);
}
```

Copy `avoidpp.js` into your project. There is nothing to install: the client
uses global `fetch` and `node:crypto`, so it needs Node 18 or later and
nothing else. CommonJS, because that is what it can be `require`d from; it
imports cleanly from ESM too.

## It reads the same table as the other two clients

[`../contract-expectations.json`](../contract-expectations.json) states what a
correct client does with all 48 wire shapes. The Python, Go and Node suites
are three implementations of that one table, so a disagreement between the
clients fails a test instead of being discovered by whichever caller hits it
first. That is not hypothetical: the Python and Go clients disagreed about
wrong-typed JSON fields, and this is how it was found.

The rules it inherits are the ones the other clients document — no boolean,
no failure that reads as success, no retry you did not ask for, no tidying of
the passage, no plaintext to a remote host. Two are worth restating in
JavaScript terms, because the language makes both easy to get wrong:

- **`NotConfigured` extends `ScanFailed`.** A bad base URL or a missing key
  throws the same family as a failed scan, so `catch (e) { if (e instanceof
  ScanFailed) refuse(); }` cannot be bypassed by a misconfiguration.
  Misconfiguration is one of the likelier ways a guard ends up not guarding.
- **There is no truthy verdict.** `permitsTranslation` is a free function
  taking an explicit policy argument, not a `verdict.ok` that reads as
  permission in an `if`. An action the build does not recognise returns
  `false`.

## Plaintext on a private network

`http://` to anything but localhost is refused, because the API key is a
spending account. On a network that is private and encrypted — Fly's 6PN, a
service mesh, a VPC with no egress — name the host:

```js
new ScanClient({
  baseUrl: 'http://avoid-pp-gateway.internal:8080',
  apiKey: process.env.AVOIDPP_KEY,
  timeoutMs: 20000,
  allowPlaintextHosts: ['avoid-pp-gateway.internal'],
});
```

A list of hosts rather than a boolean, so the thing being trusted is written
down and greppable. The option exists because the alternative people actually
choose when a client refuses is worse: they publish the gateway to the
internet to get a TLS certificate in front of it.

## What is deliberately absent

No `isSafe`, no default `translateOnFlag: true`, no automatic retry, no
`verdict.toBoolean()`, and no normalisation of the passage before sending it.
Each of those would be a convenience that turns a decision into a default.
