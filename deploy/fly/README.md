# Fly deployment

Two apps with no public address, reachable only from other apps in the same
Fly organisation. Nothing here is a managed service: this is the smallest
honest way to put the guard next to a backend that already runs on Fly.

```sh
fly apps create avoid-pp-detector
fly secrets set -a avoid-pp-detector LLM_API_KEY="$LLM_API_KEY"
fly deploy -a avoid-pp-detector -c deploy/fly/detector.fly.toml

fly apps create avoid-pp-gateway
fly secrets set -a avoid-pp-gateway AVOIDPP_API_KEYS="learningapp:translate_fi_en_v1:$(openssl rand -hex 24)"
fly deploy -a avoid-pp-gateway -c deploy/fly/gateway.fly.toml
```

The detector first: the gateway starts without it, but a gateway whose
detector does not answer refuses every scan, which looks like a broken
deployment rather than an ordering mistake.

Then point the caller at it:

```sh
fly secrets set -a <your-backend> \
  AVOIDPP_URL="http://avoid-pp-gateway.internal:8080" \
  AVOIDPP_KEY="<the key above>"
```

## Why no public address

Neither app has an `[http_service]` block. Fly's private network (6PN) is
WireGuard between machines inside one organisation, so the bearer token and
the passages never touch the public internet, and there is no address for
anyone else to find.

The cost is that **the Node client has to be told** — plaintext to a remote
host is refused by default, for the good reason that a leaked key is a
spending account:

```js
new ScanClient({
  baseUrl: 'http://avoid-pp-gateway.internal:8080',
  apiKey: process.env.AVOIDPP_KEY,
  timeoutMs: 20000,
  allowPlaintextHosts: ['avoid-pp-gateway.internal'],
});
```

A named list rather than a boolean, so what is being trusted is written down.
If you would rather not do that, give the gateway an `[http_service]` with
`force_https = true` and use the `https://` address: the client needs no
option, and you have an authenticated, rate-limited, money-spending endpoint
on a public hostname. That trade is yours; this directory takes the other
side of it.

## What this is weaker at than the Kubernetes deployment

**Fly's private network is flat within an organisation.** Any app in the org
can reach the detector, and anything that reaches the detector bypasses the
gateway's validation, authentication, rate limits and policy. The Kubernetes
manifests restrict the detector to the gateway with a NetworkPolicy and
[a drill proves it is enforced](../kubernetes/README.md) — which is how we
found that kind's default CNI accepts NetworkPolicy objects and enforces none
of them. There is no equivalent here, and pretending otherwise would be the
kind of claim this repository exists to avoid making.

So: fine for a single-tenant organisation that runs this guard and the one
backend it guards. Not fine for an organisation where other people can deploy
apps.

## Cost

Two always-on shared-CPU machines, because `auto_stop_machines` is off. A
guard that scales to zero adds a cold start to the first scan after an idle
period, and that is the request a user is waiting on.

Per scan it is the provider, not Fly: about USD 0.009. The rate limits in
`gateway.fly.toml` are the bound on that, and they are set for one backend
making a handful of requests a second. Raising them raises the ceiling on
what a runaway loop can spend.
