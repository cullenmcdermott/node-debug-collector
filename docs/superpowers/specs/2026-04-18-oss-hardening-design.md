# OSS Hardening Design

**Date:** 2026-04-18
**Status:** Approved

## Overview

Harden `node-debug-collector` for open-source publication. Changes fall into five areas: remove dead HA-forwarding code, add Kubernetes SA-based webhook authentication, fix security and quality issues found in pre-OSS review, update deployment manifests for HA operation, and add targeted tests for the highest-risk untested paths.

## Section 1: Removals

Remove all Home Assistant forwarding code from `node-debug-collector`:

- Delete `forwardToHA` method (`main.go`)
- Remove `HAURL`, `HAWebhookID`, `ForwardHA` from `Config` and `loadConfig`
- Remove the `bytes` import (only used by `forwardToHA`)

In the homelab repo, rename the `home-assistant-node-remediation` AlertmanagerConfig receiver to `node-debug-collector`. No functional change.

## Section 2: Webhook Authentication (TokenReview)

Alertmanager already runs with a ServiceAccount (`prometheus-alertmanager`). We project a short-lived token from that SA into the Alertmanager pod via a projected volume, configure the webhook to send it as a Bearer header, and validate it on the collector side via the Kubernetes TokenReview API.

### Homelab changes

Add to `kube-prometheus-stack` values under `alertmanager.alertmanagerSpec`:

```yaml
replicas: 2
volumes:
- name: webhook-token
  projected:
    sources:
    - serviceAccountToken:
        path: token
        expirationSeconds: 3600
volumeMounts:
- name: webhook-token
  mountPath: /var/run/secrets/alertmanager-webhook
  readOnly: true
```

Update the AlertmanagerConfig webhook receiver:

```yaml
- name: node-debug-collector
  webhookConfigs:
  - url: 'http://node-debug-collector.node-debug.svc.cluster.local:8080/webhook'
    sendResolved: true
    maxAlerts: 0
    httpConfig:
      authorization:
        type: Bearer
        credentialsFile: /var/run/secrets/alertmanager-webhook/token
```

Kubelet automatically rotates the projected token before expiry. No static Secrets are created.

### Collector changes

**New config field:**

```go
AllowedSA: envOr("ALLOWED_SA", "system:serviceaccount:prometheus:alertmanager"),
```

**Auth middleware** wraps `handleWebhook`:

1. Extract Bearer token from `Authorization` header; return 401 if absent.
2. Call `k8s.client.AuthenticationV1().TokenReviews().Create(...)` with the token.
3. Return 401 if the call fails or `status.authenticated` is false.
4. Return 403 if `status.user.username` does not equal `cfg.AllowedSA`.
5. Call the next handler.

**RBAC:** Add `create` on `tokenreviews.authentication.k8s.io` to the collector's existing ClusterRole in `deploy/rbac.yaml`.

**NetworkPolicy:** Add `deploy/networkpolicy.yaml` allowing ingress to port 8080 only from pods with `app.kubernetes.io/name: alertmanager` in the `prometheus` namespace. Egress is unrestricted.

## Section 3: Security & Quality Fixes

### Input validation

Add `validateNodeName(s string) error` using `^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$`. Call it immediately after extracting `node` from alert labels in `handleWebhook`. Log and skip any alert with a non-conforming node name. This closes path traversal (filesystem + S3 key), PromQL label injection, and k8s API name injection in one place.

### HTTP hardening

- Wrap request body with `http.MaxBytesReader(w, r.Body, 1<<20)` (1 MiB) before `io.ReadAll`.
- Replace `http.ListenAndServe` with:

```go
srv := &http.Server{
    Addr:         cfg.ListenAddr,
    Handler:      mux,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 15 * time.Second,
    IdleTimeout:  60 * time.Second,
}
```

### Goroutine lifecycle

- Add a buffered channel semaphore (capacity 10) to cap concurrent collections. If the semaphore is full when a webhook arrives, log and drop (lease already prevents duplicate work).
- Track in-flight goroutines with a `sync.WaitGroup`.
- On `SIGTERM`/`SIGINT`: call `srv.Shutdown(ctx)` to stop accepting new requests, then wait on the WaitGroup before exiting. This ensures in-flight 10-minute collections are not killed mid-stream during rolling deploys.

### Config cleanup

- Add `TalosPeers []string` to `Config`, parsed from `TALOS_PEERS` (comma-split) in `loadConfig`. Remove the direct `os.Getenv` call in `collect_talos.go`.
- Log at info level in `collectPeerDmesg` when `TalosPeers` is empty: `"TALOS_PEERS not set, skipping peer dmesg"`.
- Replace the default Prometheus URL (`http://prometheus-kube-prometheus-prometheus.prometheus.svc:9090`) with a generic placeholder (`http://prometheus.monitoring.svc:9090`).
- Replace default `HA_URL` value (personal domain) — removed entirely with the HA code.

### Omni/credential cleanup

- Construct a single `*omniCollector` in `main()` and share it between `server.omni` and `server.talos.omni`. Fixes the duplicate struct with identical config.
- Read the Omni SA key once at `omniCollector` construction time and store it as a `saKey string` field. `newClient` uses the cached field instead of calling `os.ReadFile`. Removes 7–10 redundant file reads per collection and eliminates mid-collection key rotation inconsistency.

### Bug fixes

- **`tarGzUpload` goroutine leak:** Add `defer pr.Close()` immediately after the `go func()` launch. If `Upload` returns early (context cancelled), closing `pr` unblocks the write goroutine's next pipe write, allowing it to exit.
- **`dumpResource` error precedence:** Restructure so write errors are always returned; use `errors.Join` to surface `listErr` alongside a write error when both occur.
- **Raw body in logs:** Replace `"body", string(body)` in the unmarshal error log with `"body_len", len(body)`.

### Naming

Rename `collectMachineLogs` → `collectMachineStatusResources` in `collect_omni.go`. Update the comment to clarify this captures COSI status resources, not actual machine logs.

## Section 4: Deployment Changes (homelab repo)

**Alertmanager HA:**

```yaml
alertmanager:
  alertmanagerSpec:
    replicas: 2
    podAntiAffinity: soft  # kube-prometheus-stack string: "soft" = preferredDuringSchedulingIgnoredDuringExecution
```

Both replicas fire the webhook on each alert. The collector's existing lease mechanism deduplicates.

**Collector HA:**

Set `replicas: 2` in `deploy/deployment.yaml` with a `preferredDuringSchedulingIgnoredDuringExecution` pod anti-affinity rule to spread replicas across nodes.

## Section 5: Testing

Three additions targeting the highest-risk untested paths:

**`handleWebhook` tests**

Define a `leaseAcquirer` interface:

```go
type leaseAcquirer interface {
    Acquire(ctx context.Context, name string) (bool, error)
}
```

Replace `*IncidentLocker` on `server` with this interface. Use `net/http/httptest` + a fake acquirer to test:

1. Malformed JSON body → 400
2. Missing `node` label → 202, no collection triggered
3. Unknown `alertname` → 202, no collection triggered
4. Firing `NodeDown` with valid node → 202, goroutine dispatched with "pre" phase
5. Resolved `NodeDown` with valid node → 202, goroutine dispatched with "post" phase

Auth middleware gets its own test using a fake TokenReview response (stubbed k8s client).

**`IncidentLocker.Acquire` tests**

Use `k8s.io/client-go/kubernetes/fake` to cover:

1. Successful create → `(true, nil)`
2. AlreadyExists, lease still live → `(false, nil)`
3. AlreadyExists, lease expired, steal succeeds → `(true, nil)`
4. AlreadyExists, lease expired, conflict on update (race lost) → `(false, nil)`

**`tarGzUpload` test**

Write known files to `os.MkdirTemp`, call `tarGzUpload` against a local `httptest.NewServer` acting as an S3-compatible endpoint, decompress and read back the archive, assert file names and contents match.

## Files Changed

### `node-debug-collector` repo

| File | Change |
|------|--------|
| `main.go` | Remove HA code; add auth middleware; add node validation; add body size limit; add HTTP server timeouts; add semaphore + WaitGroup + SIGTERM handler; share single omniCollector; update Config |
| `collect_omni.go` | Cache SA key on struct; rename `collectMachineLogs`; fix `dumpResource` error precedence |
| `archive.go` | Add `defer pr.Close()` |
| `collect_talos.go` | Use `cfg.TalosPeers` instead of `os.Getenv`; log when empty |
| `collect_prometheus.go` | Update default URL |
| `lease.go` | No changes (logic is correct) |
| `collector_test.go` | Add `handleWebhook`, `Acquire`, and `tarGzUpload` tests |
| `deploy/rbac.yaml` | Add TokenReview create permission |
| `deploy/networkpolicy.yaml` | New file — ingress from Alertmanager only |
| `deploy/deployment.yaml` | replicas: 2, podAntiAffinity |

### homelab repo

| File | Change |
|------|--------|
| `k8s/monitoring/values.yaml` | Alertmanager replicas: 2, podAntiAffinity, projected token volume |
| `k8s/monitoring/telegram-alertmanager.yaml` | Rename receiver; add `httpConfig.authorization.credentialsFile` |
