# C34 — hardened images and private service configuration

> **C34-AC1** Containers run without root, dependencies/bases are pinned and
> resource limits are defined.
> **C34-AC2** Python is not publicly exposed; service identity/auth and
> transport protection are configured for the chosen network.
> **C34-AC3** Readiness, termination, secret rotation and rollback
> configuration are documented and smoke-tested in staging.

```sh
deploy/kubernetes/smoke.sh all      # cluster, deploy, four drills, teardown
```

**8 passed, 0 failed** on a local `kind` cluster with Calico, from cluster
creation to teardown. Every claim below was executed, and three of them
failed first — including one that was a real defect in the gateway.

---

## "Smoke-tested in staging", without a staging environment

This is a personal project with no deployed environment, so AC3's verification
looked unsatisfiable: readiness, termination, secret rotation and rollback are
behaviours, and a manifest that has never been applied is a guess about them.

The resolution is that **staging is a deployment with no users**, which is
exactly what `kind` — Kubernetes in Docker — provides on a laptop. Nothing in
AC3 needs traffic. It needs a cluster.

So the deliverable is not a set of manifests. It is a script that builds the
images, creates a cluster, deploys, and then runs four drills that can fail.

---

## What C12 had already done

Most of AC1 and AC2 arrived at C12 and needed nothing:

| | |
|---|---|
| non-root | `USER 65532:65532` in both Dockerfiles |
| pinned bases | `python:3.13.14-slim`, `golang:1.27.2-alpine`, gateway on `scratch` |
| no shell in the gateway image | `scratch` has no shell, package manager or setuid binary |
| detector unexposed | no `ports:` in Compose; ClusterIP only in Kubernetes |
| `read_only`, `cap_drop: ALL`, `no-new-privileges` | both services |

The one real AC1 gap was **resource limits**, which Compose had none of.
Added, and sized from measurement rather than habit: the C32 profile measured
the gateway's peak heap at 4.4 MiB with the largest passage the service
accepts, and in-flight work is bounded by admission to `MaxActive + MaxQueued`
= 8 passages. 128 MiB is an order of magnitude over a measured number.

`GOMEMLIMIT` goes with it. Go does not read the cgroup limit on its own, so a
container limit without it means the runtime grows until the kernel kills the
process — an OOMKill rather than a collection.

---

## The drills, and what failed first

### 1. The detector accepts only the gateway

The headline finding, and the reason the cluster config disables kind's
default CNI.

**NetworkPolicy is implemented by the CNI, not by Kubernetes.** kindnet
accepts policy objects and enforces none of them. With it, the first run of
this drill reported:

```
three NetworkPolicies present
detector reachable: 200
```

`kubectl get networkpolicy` looked reassuring and the detector was reachable
from any pod in the namespace — which means from anything that can run a pod,
bypassing the gateway's validation, rate limits, admission control and policy.
That is worse than having no policy, because the manifests pass inspection.

`kind-cluster.yaml` therefore sets `disableDefaultCNI: true` and the script
installs Calico, pinned to v3.26.4. With enforcement:

```
PASS a pod that is not the gateway cannot reach the detector (got 000)
PASS the gateway still reaches the detector
```

Both halves matter. A policy that blocked everything would pass the first
check and break the service.

### 2. A rollout drops no request

```
PASS 40 requests across a rolling restart, 0 dropped (0 rate limited)
```

**This drill found a real defect in the service**, and the fix is the most
useful thing C34 produced.

On a cold cluster it reported `1 of 40 requests were dropped during the
rollout` — reproducibly, and not on a warm one, which is why only a real
deployment could surface it. C24 tested draining in-process, where there is
no endpoint to withdraw, so the race it depends on does not exist there.

The sequence was:

```
SIGTERM → fail readiness → close the listener     all in the same instant
```

Kubernetes has not noticed the readiness failure yet, let alone withdrawn the
endpoint and updated every node's kube-proxy rules. Requests keep arriving at
a socket that is already closed, and get connection refused. The gateway had
been draining correctly the whole time — in-flight work always finished — and
still dropped requests, because it stopped *accepting* too early.

The usual remedy is a `preStop` hook that sleeps, and the gateway image is
`scratch` with no shell to sleep with. That constraint forced the better
answer: the wait belongs in the process, which knows it is draining, rather
than in a sidecar that guesses. `AVOIDPP_PREDRAIN` keeps the listener open
with readiness failing:

```
SIGTERM → fail readiness → serve normally for 5s → close → drain 10s
```

The default is **0**, which is right for a single process: there is no load
balancer to tell, and a delay would make every local Ctrl-C slower.
`30-gateway.yaml` sets 5 s, derived from its own readiness probe period (2 s,
`failureThreshold: 1`) with margin. `PreDrain + SHUTDOWN_TIMEOUT = 15 s` has
to stay inside `terminationGracePeriodSeconds: 30`, or the kubelet kills the
process mid-drain — the configuration rejects anything over 15 s for that
reason.

`maxUnavailable: 0` does the other half: the replacement is ready before the
old pod is told to stop.

**The drill also failed twice for its own reasons before it meant anything.**

The first version reported `124 of 150 requests failed` and was measuring the
rate limiter. The shipped per-caller limit is 1 request per second with a
burst of 5 — a spend bound sized at C32 against what a scan costs — and the
hammer fired ten times a second. The 26 that succeeded are almost exactly the
seconds of budget the run consumed. It now paces at 1/s and counts 429
separately, because a rate-limited request is the service working.

The second version failed for a harness reason worth recording: **`kubectl
port-forward svc/…` does not survive pod replacement.** It binds to a pod, not
to the Service. Measured directly: 200 before a rolling restart, 000 after.
Three of the four drills restart something, so a port-forwarded harness
reports failures that are entirely its own. Every request in the script is now
made from inside the cluster, which also exercises the Service, endpoints and
kube-proxy — the path a real caller takes.

### 3. Secret rotation

```
PASS a changed Secret alone does nothing: old key 200, new key 401
PASS after the roll the new key works and the old one is refused
```

The first assertion is the one worth having. Changing a Secret does **not**
rotate a credential: the process read the value at startup and nothing tells
it to read again. Rotation is a Secret change *and* a roll, and a procedure
that stops at the first step leaves the old key working indefinitely while
appearing to have rotated it.

Env vars rather than a mounted Secret, deliberately. A mounted Secret updates
in place, which looks like free rotation and is not — the process still has to
re-read it, and both services validate credentials at startup (C19) and refuse
to start on a bad one. Env vars make the restart requirement visible instead
of implied.

### 4. Rollback

```
PASS a configuration change rolled out (mode=enforcement)
PASS rollout undo restored mode=monitoring (revision 16 -> 18)
PASS the rolled-back revision serves
```

The drill changes policy mode to `enforcement` — a change that is visibly
wrong for this service, since C30 records enforcement as a no-go — rolls it
out, then undoes it and confirms the service still serves.

---

## The gateway refuses to start without a credential

Visible in the deployment, and correct. The first `kubectl apply` leaves the
gateway in `CreateContainerConfigError`:

```
Error: secret "avoidpp-gateway" not found
```

That is C19 behaving as designed — a service configured with no keys refuses
to start rather than silently opening — surfacing as a Kubernetes failure
state. The detector starts, because its Secret is `optional: true`: fake mode
needs no provider key, and a missing Secret must not block a deployment that
will never call a provider.

---

## Other deliberate choices

**`restricted` Pod Security is enforced on the namespace**, not audited. The
pod specs already satisfy it, so turning it on costs nothing today and refuses
a future pod that quietly drops one of the controls. It also applies to the
drill pods, which is why `smoke.sh` builds hardened overrides for them.

**`automountServiceAccountToken: false` on both.** Neither service calls the
Kubernetes API, and a mounted token is a credential sitting in a container
that processes attacker-chosen text.

**A writable `/tmp` for the detector**, as a size-limited `emptyDir`.
`readOnlyRootFilesystem: true` is the point and Python still wants somewhere
to write; an `emptyDir` is writable and disappears with the pod, which is what
a temp directory should have been all along.

**One gateway replica.** C21's rate limits and C22's admission control are
per-process, so two replicas would double both without saying so. That is
C40's problem, and C40's trigger has not fired.

**Liveness never depends on the provider.** `/healthz` answers whenever the
process runs and makes no external call, so a provider outage degrades the
service rather than restarting it into a crash loop. Readiness is the probe
that depends on the detector.

---

## What this does not establish

1. **No TLS.** AC2 says "transport protection … for the chosen network", and
   the chosen network here is a local cluster where traffic never leaves the
   host. A real deployment terminates TLS at an ingress controller or uses a
   mesh; neither exists to configure. The C41 SDK already refuses plain
   `http` to a non-loopback host, so the client half is enforced.
2. **No ingress.** The gateway is a ClusterIP Service. Reaching it from
   outside needs an Ingress or a LoadBalancer, which is the deployment
   decision this project does not have to make.
3. **One node.** Nothing here says anything about scheduling, anti-affinity
   or a node failure.
4. **Images are built locally and loaded**, with `imagePullPolicy: Never`.
   A registry deployment replaces the tags with digests — a tag is a moving
   target, and the pinning AC1 asks for ends at the base image until there is
   a registry.
5. **No secret manager.** Rotation is exercised against a Kubernetes Secret.
   An external store changes where the value comes from, not the fact that a
   roll is required.
6. **Calico is a test-harness choice, not a recommendation.** It is installed
   because kindnet cannot enforce the policies. Any CNI that does will serve;
   the point of the drill is that *inspecting manifests cannot tell you which
   one you have*.
