# Fly deployment

Two apps with no public address, reachable only from other apps in the same
Fly organisation. Nothing here is a managed service: this is the smallest
honest way to put the guard next to a backend that already runs on Fly.

```sh
fly apps create avoid-pp-detector
grep '^LLM_API_KEY=' .env | fly secrets import -a avoid-pp-detector
cd detector && fly deploy -a avoid-pp-detector -c ../deploy/fly/detector.fly.toml \
  --dockerfile Dockerfile

fly apps create avoid-pp-gateway
printf 'AVOIDPP_API_KEYS=%s\n' "caller:translate_fi_en_v1:$(openssl rand -hex 24)" \
  | fly secrets import -a avoid-pp-gateway
cd gateway && fly deploy -a avoid-pp-gateway -c ../deploy/fly/gateway.fly.toml \
  --dockerfile Dockerfile
```

**Deploy from the service directory, not the repository root.** Both
Dockerfiles expect their own directory as the build context - the detector's
`COPY src ./src` is relative to `detector/`. Run it from the root and the
build fails with `"/src": not found`.

Secrets go in by `fly secrets import` reading stdin, so a key never appears
in a shell history or a process list.

The detector first: the gateway starts without it, but a gateway whose
detector does not answer refuses every scan, which looks like a broken
deployment rather than an ordering mistake.

Then point the caller at it:

```sh
fly secrets set -a <your-backend> \
  AVOIDPP_URL="http://avoid-pp-gateway.internal:8080" \
  AVOIDPP_KEY="<the key above>"
```

## On Apple Silicon

Two things bite, and both cost an hour the first time.

**`--local-only` needs `DOCKER_HOST` if you use colima or Rancher.** flyctl
looks for the default Docker socket and reports `docker is unavailable to
build the deployment image` even though `docker version` works. Point it at
the real socket:

```sh
export DOCKER_HOST=$(docker context inspect colima --format '{{.Endpoints.docker.Host}}')
```

**The Go build crashes under amd64 emulation.** Fly machines are amd64, and
building the gateway image on an arm64 Mac panics inside the Go toolchain
itself:

    panic: runtime error: growslice: len out of range
      go/parser.ParseFile.func1()

Not a code problem - the same build is clean natively. Cross-compile on the
host and ship the binary, which is also much faster:

```sh
cd gateway
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /tmp/gateway ./cmd/server
printf 'FROM scratch\nUSER 65532:65532\nCOPY gateway /gateway\nENTRYPOINT ["/gateway"]\n' > /tmp/Dockerfile
cd /tmp && docker build --platform linux/amd64 -t registry.fly.io/avoid-pp-gateway:host .
docker push registry.fly.io/avoid-pp-gateway:host
fly deploy -a avoid-pp-gateway -c deploy/fly/gateway.fly.toml --image registry.fly.io/avoid-pp-gateway:host
```

The detector is Python and builds fine under emulation, so only the gateway
needs this.

A remote builder (`--remote-only`) avoids both and is the better answer when
it works; ours returned `401 Unauthorized` pushing to the Fly registry, twice,
with a valid login.

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

The caller needs the updated client: `allowPlaintextHosts` arrived after the
first version of this file, so a vendored copy taken before it will refuse the
`.internal` URL and report `misconfigured` on every call. That is the client
working as designed, and it is confusing for ten minutes.

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
