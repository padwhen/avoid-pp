# Deploying avoid-pp

Manifests for a local Kubernetes cluster, and a script that proves four
operational behaviours rather than describing them.

```sh
deploy/kubernetes/smoke.sh all
```

Needs `docker`, [`kind`](https://kind.sigs.k8s.io/) and `kubectl`. Builds both
images, creates a cluster, installs Calico, deploys, runs the drills and
deletes the cluster. The detector runs in **fake mode**: no provider is
contacted and nothing is spent.

Roughly five minutes, most of it Calico starting.

## Step by step, if you want to watch

```sh
deploy/kubernetes/smoke.sh up       # cluster + deploy, leaves it running
kubectl -n avoid-pp get pods
kubectl -n avoid-pp get networkpolicy

deploy/kubernetes/smoke.sh drills   # the four drills, repeatable

# Talk to it yourself. Note this breaks on the next rollout - port-forward
# binds to a pod, not to the Service, which is why the drills do not use it.
kubectl -n avoid-pp port-forward svc/gateway 18080:8080 &
KEY="$(cat deploy/kubernetes/.key-current)"

curl -s localhost:18080/readyz

curl -s -X POST localhost:18080/v1/scans \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $KEY" \
  -d '{"task_id":"translate_fi_en_v1","content":{"id":"p1",
       "source_type":"translation_input","language_hint":"fi",
       "text":"Sää on tänään aurinkoinen."}}'

# C33's metrics, which need the same credential: the block counter is an
# oracle, so this route is not open.
curl -s -H "Authorization: Bearer $KEY" localhost:18080/metrics | head -20
curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/metrics   # 401

deploy/kubernetes/smoke.sh down
```

## What is here

| | |
|---|---|
| `kind-cluster.yaml` | disables kind's default CNI — see below |
| `00-namespace.yaml` | namespace with `restricted` Pod Security enforced |
| `10-secrets.example.yaml` | a template; the real Secret is created out of band |
| `20-detector.yaml` | Deployment + ClusterIP Service, no external exposure |
| `30-gateway.yaml` | Deployment + Service, `maxUnavailable: 0` |
| `40-networkpolicy.yaml` | default deny, then two exceptions |
| `smoke.sh` | the four drills |

## The thing worth knowing

**kind's default CNI does not enforce NetworkPolicy.** kindnet accepts the
objects, `kubectl get networkpolicy` lists all three, and any pod in the
namespace can reach the detector. That is worse than having no policy,
because the manifests pass inspection.

So the cluster config disables it and `smoke.sh` installs Calico. The
isolation drill is what tells the two apart:

```
PASS a pod that is not the gateway cannot reach the detector (got 000)
```

With kindnet that line reads `FAIL … reached the detector (HTTP 200)`.

Reasoning and the drills that failed first: [docs/c34-deploy.md](../../docs/c34-deploy.md).
