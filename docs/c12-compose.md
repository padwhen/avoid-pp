# C12 — run the service slice with Compose

Scope: container images for both services, a private service network, and a
one-command smoke flow.

```sh
make up          # build and start both services
make smoke       # exercise the stack and assert the responses
make logs
make down
```

## Acceptance criteria

1. A clean checkout starts both services in fake mode through one command.
2. Only the Go endpoint is exposed to the host by default; Python is addressed
   over the Compose network.
3. The smoke command demonstrates allow, flag or block, and
   detector-unavailable responses.

## Verification

### AC1 — one command, no credentials

```
$ docker compose up -d
 Container avoid-pp-detector-1 Started
 Container avoid-pp-detector-1 Healthy
 Container avoid-pp-gateway-1  Started
```

The gateway waits on `condition: service_healthy`, so it does not start
scanning before the detector can answer. The detector's healthcheck calls its
own `/readyz`, which fails until initialisation succeeds.

Both services run in fake mode. No provider credential is read and no paid API
is called; live inference arrives at C13 behind its own configuration.

| Image | Size | Base |
| --- | --- | --- |
| `avoid-pp-gateway` | 9.75 MB | `scratch` |
| `avoid-pp-detector` | 226 MB | `python:3.13.14-slim` |

The gateway is a static binary on `scratch`: no shell, no package manager, no
setuid binaries, so a container escape has nothing to work with. Both services
run as uid 65532, read-only, with all capabilities dropped and
`no-new-privileges`.

### AC2 — the detector is private, and that is tested rather than assumed

```
direct to detector:9000 -> 000   (connection refused)
gateway:8099            -> 200
detector served requests: 7      (reached over the internal network)
```

The detector declares no `ports:` at all. A detector published to the host
would let anything on the machine request an assessment directly, bypassing
the gateway's validation, limits and policy — which is the whole control.

The gateway publishes `8099` rather than `8080`, because 8080 is commonly taken
by another local service and the resulting 404 looks like a broken gateway.

### AC3 — the smoke flow, including the failure

```
health
  ok    liveness
  ok    readiness

scans
  ok    ordinary Finnish -> HTTP 200, action allow
  ok    attack passage -> action flag

rejections
  ok    caller-supplied policy -> HTTP 400
  ok    unknown task id -> HTTP 422

smoke: all checks passed
```

The attack check deliberately accepts either `flag` or `block`, since the
correct answer depends on `AVOIDPP_POLICY_MODE`. What it actually asserts is
that the action is **not** `allow`.

Stopping the detector and rescanning the same attack passage:

```
$ docker compose stop detector
$ curl -X POST localhost:8099/v1/scans -d '{...}'
HTTP 503  {"error":{"code":"detector_unavailable","message":"Detector is not available."}}
```

No allow, no assessment. The gateway recovers once the detector is restarted.

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `AVOIDPP_HOST_PORT` | `8099` | Host port for the gateway |
| `AVOIDPP_POLICY_MODE` | `monitoring` | monitoring or enforcement |
| `AVOIDPP_LOG_LEVEL` | `info` | debug, info, warn, error |

```sh
AVOIDPP_POLICY_MODE=enforcement make up   # the attack passage now blocks
```

## This is development tooling, not a deployment

Images are built locally and tagged `latest`. There is no registry, no digest
pinning, no resource limit, no TLS between the services, and no secret
management. Deployment hardening is C34, and these containers are not a
substitute for it.

## Notes for a fresh machine

macOS has no container runtime by default. This slice was verified with
colima plus the Compose and buildx CLI plugins, which is the lightest option
that works with a Homebrew-installed Docker client:

```sh
brew install colima docker-compose docker-buildx
colima start --cpu 2 --memory 4 --disk 30
```

If Docker Desktop was ever installed and removed, `~/.docker/config.json` may
still name `credsStore: desktop`. Registry calls then fail with
`docker-credential-desktop: executable file not found`; removing that key
fixes it.
