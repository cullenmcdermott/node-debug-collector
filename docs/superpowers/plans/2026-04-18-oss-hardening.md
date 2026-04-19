# OSS Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden node-debug-collector for open-source publication by removing dead HA code, adding Kubernetes SA-based webhook auth (TokenReview), fixing security/quality issues from the pre-OSS review, and updating deployment manifests + homelab config for HA operation.

**Architecture:** Two-repo change set: `node-debug-collector` receives all code and manifest changes; `~/git/homelab` receives Alertmanager HA config and webhook auth wiring. Auth uses projected ServiceAccountToken (auto-rotated by kubelet) sent as a Bearer header; collector validates via the k8s TokenReview API and asserts the caller is `system:serviceaccount:prometheus:alertmanager`. Goroutine lifecycle is bounded by a semaphore and drained on SIGTERM via WaitGroup.

**Tech Stack:** Go 1.26, `k8s.io/client-go v0.35.2` (includes `authentication/v1` TokenReview, `kubernetes/fake`), `net/http/httptest`, `archive/tar`, `compress/gzip`, AWS SDK v2.

---

## File Map

### node-debug-collector

| File | What changes |
|------|-------------|
| `main.go` | Remove HA; add `validateNodeName`, auth middleware, `leaseAcquirer` interface, body limit, HTTP server struct with timeouts, semaphore + WaitGroup + SIGTERM, shared `*omniCollector`, updated Config |
| `collect_omni.go` | `saKeyFile` → `saKey` field (cached key content); rename `collectMachineLogs` → `collectMachineStatusResources`; fix `dumpResource` error precedence |
| `collect_talos.go` | Add `peers []string` to `talosCollector`; replace `os.Getenv("TALOS_PEERS")` with `t.peers`; log when empty |
| `collect_k8s.go` | Extract `peerTarget` type + `collectOnePeerTarget` helper so file handle is properly deferred |
| `archive.go` | Add `defer pr.Close()` after goroutine launch |
| `collector_test.go` | Add `TestAuthMiddleware`, `TestHandleWebhook`, `TestAcquire_*`, `TestTarGzUpload` |
| `deploy/rbac.yaml` | Add `create` on `tokenreviews.authentication.k8s.io` to ClusterRole |
| `deploy/networkpolicy.yaml` | New — ingress from Alertmanager pods only |
| `deploy/deployment.yaml` | Remove HA env vars; update Prometheus URL comment; remove HA secret ref |
| `deploy/kustomization.yaml` | Add `networkpolicy.yaml` to resources |

### homelab (`~/git/homelab`)

| File | What changes |
|------|-------------|
| `k8s/monitoring/values.yaml` | Alertmanager `replicas: 2`, `podAntiAffinity: soft`, projected token volume + mount |
| `k8s/monitoring/telegram-alertmanager.yaml` | Rename receiver; add `httpConfig.authorization.credentialsFile` |

---

## Task 1: Remove HA Code

**Files:**
- Modify: `main.go`

- [ ] **Remove `forwardToHA`, HA config fields, and the `bytes` import from `main.go`**

  Delete the entire `forwardToHA` method. Remove from `Config`:
  ```go
  // DELETE these three fields:
  HAURL         string
  HAWebhookID   string
  ForwardHA     bool
  ```

  Remove from `loadConfig()`:
  ```go
  // DELETE these three lines:
  HAURL:         envOr("HA_URL", "https://ha.cullen.rocks"),
  HAWebhookID:   os.Getenv("HA_WEBHOOK_ID"),
  ForwardHA:     envOr("FORWARD_HA", "true") == "true",
  ```

  Remove from `handleWebhook` (lines ~187–191):
  ```go
  // DELETE this block:
  if s.cfg.ForwardHA {
      if err := s.forwardToHA(ackCtx, body); err != nil {
          s.log.Error("forward to HA failed", "err", err)
      }
  }
  ```

  Remove `"bytes"` from the import block.

- [ ] **Verify it compiles**

  ```bash
  go build ./...
  ```
  Expected: no output, exit 0.

- [ ] **Commit**

  ```bash
  git add main.go
  git commit -m "chore: remove Home Assistant webhook forwarding"
  ```

---

## Task 2: Config Additions and TalosPeers Wiring

**Files:**
- Modify: `main.go`
- Modify: `collect_talos.go`

- [ ] **Add `AllowedSA` and `TalosPeers` to `Config` in `main.go`**

  In the `Config` struct add:
  ```go
  AllowedSA  string
  TalosPeers []string
  ```

  In `loadConfig()` add:
  ```go
  AllowedSA: envOr("ALLOWED_SA", "system:serviceaccount:prometheus:alertmanager"),
  TalosPeers: parsePeers(os.Getenv("TALOS_PEERS")),
  ```

  Add the helper function (package level, after `envOr`):
  ```go
  func parsePeers(v string) []string {
      if v == "" {
          return nil
      }
      var out []string
      for _, p := range strings.Split(v, ",") {
          if p = strings.TrimSpace(p); p != "" {
              out = append(out, p)
          }
      }
      return out
  }
  ```

  Add `"strings"` to the import block if not already present.

- [ ] **Add `peers []string` to `talosCollector` in `collect_talos.go`**

  Change:
  ```go
  type talosCollector struct {
      omni    *omniCollector
      cluster string
      log     *slog.Logger
  }
  ```
  To:
  ```go
  type talosCollector struct {
      omni    *omniCollector
      cluster string
      peers   []string
      log     *slog.Logger
  }
  ```

- [ ] **Replace `os.Getenv("TALOS_PEERS")` in `collectPeerDmesg`**

  Replace the entire `collectPeerDmesg` method:
  ```go
  func (t *talosCollector) collectPeerDmesg(ctx context.Context, deadNode, dir string) error {
      if len(t.peers) == 0 {
          t.log.Info("TALOS_PEERS not set, skipping peer dmesg")
          return nil
      }
      var firstErr error
      for _, peer := range t.peers {
          if peer == "" || peer == deadNode {
              continue
          }
          if err := t.collectOnePeerDmesg(ctx, peer, dir); err != nil && firstErr == nil {
              firstErr = fmt.Errorf("peer %s: %w", peer, err)
          }
      }
      return firstErr
  }
  ```

  Remove `"os"` and `"strings"` from `collect_talos.go` imports if no longer used (check — `strings` is used by nothing else in that file after this change; `os` is used by `writeFile`).

- [ ] **Wire `peers` in `main()` when constructing `talosCollector`**

  In `main()`, find the `talosCollector` construction and add `peers`:
  ```go
  talos: &talosCollector{
      omni:    omni,   // will be a shared instance after Task 5
      cluster: cfg.OmniCluster,
      peers:   cfg.TalosPeers,
      log:     log,
  },
  ```

  (The `omni` variable will be introduced in Task 5. For now, leave the existing inline construction and just add `peers: cfg.TalosPeers`.)

- [ ] **Verify compilation**

  ```bash
  go build ./...
  ```

- [ ] **Commit**

  ```bash
  git add main.go collect_talos.go
  git commit -m "feat: add AllowedSA and TalosPeers to Config, wire peers into talosCollector"
  ```

---

## Task 3: Input Validation (validateNodeName)

**Files:**
- Modify: `main.go`
- Modify: `collector_test.go`

- [ ] **Write the failing test**

  Add to `collector_test.go`:
  ```go
  func TestValidateNodeName(t *testing.T) {
      tests := []struct {
          name  string
          input string
          valid bool
      }{
          {"simple hostname", "k8s-worker-1", true},
          {"with dots", "node.example.com", true},
          {"single char", "a", true},
          {"uppercase rejected", "Node-1", false},
          {"underscore rejected", "node_1", false},
          {"leading hyphen", "-node", false},
          {"trailing hyphen", "node-", false},
          {"empty string", "", false},
          {"path traversal", "../../etc", false},
          {"slash", "foo/bar", false},
          {"too long", strings.Repeat("a", 254), false},
          {"exactly 253", strings.Repeat("a", 253), true},
      }
      for _, tt := range tests {
          t.Run(tt.name, func(t *testing.T) {
              err := validateNodeName(tt.input)
              if tt.valid && err != nil {
                  t.Errorf("expected valid, got err: %v", err)
              }
              if !tt.valid && err == nil {
                  t.Error("expected invalid, got nil err")
              }
          })
      }
  }
  ```

- [ ] **Run test to verify it fails**

  ```bash
  go test -run TestValidateNodeName ./...
  ```
  Expected: `undefined: validateNodeName`

- [ ] **Implement `validateNodeName` in `main.go`**

  Add after the `envOr` function:
  ```go
  var validNode = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$`)

  func validateNodeName(name string) error {
      if len(name) > 253 || !validNode.MatchString(name) {
          return fmt.Errorf("invalid node name: %q", name)
      }
      return nil
  }
  ```

  Add `"regexp"` to the import block.

- [ ] **Call `validateNodeName` in `handleWebhook`**

  In the alert-processing loop in `handleWebhook`, after extracting `node`:
  ```go
  node := alert.Labels["node"]
  alertname := alert.Labels["alertname"]
  if node == "" {
      continue
  }
  if err := validateNodeName(node); err != nil {
      s.log.Warn("invalid node name in alert, skipping", "node", node, "err", err)
      continue
  }
  ```

- [ ] **Run tests to verify they pass**

  ```bash
  go test -run TestValidateNodeName ./...
  ```
  Expected: PASS

- [ ] **Commit**

  ```bash
  git add main.go collector_test.go
  git commit -m "feat: validate node name from alert labels before use in paths or API calls"
  ```

---

## Task 4: HTTP Hardening (Body Limit + Server Timeouts)

**Files:**
- Modify: `main.go`

- [ ] **Add `http.MaxBytesReader` to `handleWebhook`**

  Replace the body read at the top of `handleWebhook`:
  ```go
  // BEFORE:
  body, err := io.ReadAll(r.Body)

  // AFTER:
  body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
  ```

- [ ] **Replace `http.ListenAndServe` with a configured `http.Server`**

  In `main()`, replace:
  ```go
  log.Info("listening", "addr", cfg.ListenAddr, "bucket", storage.Bucket, "leaseTTL", cfg.LeaseTTL)
  if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
      log.Error("http server exited", "err", err)
      os.Exit(1)
  }
  ```

  With:
  ```go
  srv := &http.Server{
      Addr:         cfg.ListenAddr,
      Handler:      mux,
      ReadTimeout:  10 * time.Second,
      WriteTimeout: 15 * time.Second,
      IdleTimeout:  60 * time.Second,
  }
  log.Info("listening", "addr", cfg.ListenAddr, "bucket", storage.Bucket, "leaseTTL", cfg.LeaseTTL)
  if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
      log.Error("http server exited", "err", err)
      os.Exit(1)
  }
  ```

  Add `"errors"` to the import block. The `srv` variable will be used again in Task 7 (graceful shutdown).

- [ ] **Update unmarshal error log to drop raw body**

  In `handleWebhook`, find:
  ```go
  s.log.Error("unmarshal payload", "err", err, "body", string(body))
  ```
  Replace with:
  ```go
  s.log.Error("unmarshal payload", "err", err, "body_len", len(body))
  ```

- [ ] **Verify compilation**

  ```bash
  go build ./...
  ```

- [ ] **Commit**

  ```bash
  git add main.go
  git commit -m "feat: add request body size limit, HTTP server timeouts, redact body from error log"
  ```

---

## Task 5: Omni Cleanup (Single Instance, Cached SA Key, dumpResource Fix, Rename)

**Files:**
- Modify: `collect_omni.go`
- Modify: `main.go`

- [ ] **Change `omniCollector` to store cached key content**

  In `collect_omni.go`, change the struct:
  ```go
  // BEFORE:
  type omniCollector struct {
      endpoint  string
      saKeyFile string
      log       *slog.Logger
  }

  // AFTER:
  type omniCollector struct {
      endpoint string
      saKey    string
      log      *slog.Logger
  }
  ```

  Update `newClient` to use the cached key:
  ```go
  func (o *omniCollector) newClient(ctx context.Context) (*omniclient.Client, error) {
      if o.endpoint == "" {
          return nil, fmt.Errorf("OMNI_ENDPOINT not set")
      }
      return omniclient.New(o.endpoint, omniclient.WithServiceAccount(o.saKey))
  }
  ```

  Remove the `"os"` import from `collect_omni.go` (no longer calls `os.ReadFile`). Keep `"path/filepath"`.

- [ ] **Add `newOmniCollector` constructor in `collect_omni.go`**

  ```go
  func newOmniCollector(endpoint, saKeyFile string, log *slog.Logger) (*omniCollector, error) {
      key, err := os.ReadFile(saKeyFile)
      if err != nil {
          return nil, fmt.Errorf("read omni SA key %s: %w", saKeyFile, err)
      }
      return &omniCollector{
          endpoint: endpoint,
          saKey:    string(key),
          log:      log,
      }, nil
  }
  ```

  Re-add `"os"` import for this constructor.

- [ ] **Fix `dumpResource` error precedence**

  Replace the `dumpResource` method:
  ```go
  func (o *omniCollector) dumpResource(ctx context.Context, resType resource.Type, outPath string) error {
      c, err := o.newClient(ctx)
      if err != nil {
          return err
      }
      defer c.Close()

      data, listErr := listToYAML(ctx, c.Omni().State(), resType)
      if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
          return errors.Join(err, listErr)
      }
      if werr := os.WriteFile(outPath, data, 0o644); werr != nil {
          return errors.Join(werr, listErr)
      }
      return listErr
  }
  ```

  Add `"errors"` to imports in `collect_omni.go`.

- [ ] **Rename `collectMachineLogs` → `collectMachineStatusResources`**

  In `collect_omni.go`, rename the method and update its comment:
  ```go
  // collectMachineStatusResources captures cluster-machine and machine status
  // COSI resources, which surface the recovery lifecycle state Omni attributes
  // to the node. This is NOT real machine log collection — that would require
  // the Omni Management API (machine-logs RPC).
  func (o *omniCollector) collectMachineStatusResources(ctx context.Context, node, dir string) error {
  ```

- [ ] **Update the call site in `main.go`**

  In `runCollection`, find:
  ```go
  errlog("omni.logs", s.omni.collectMachineLogs(ctx, node, workdir))
  ```
  Replace with:
  ```go
  errlog("omni.status", s.omni.collectMachineStatusResources(ctx, node, workdir))
  ```

- [ ] **Wire single shared `omniCollector` in `main()`**

  In `main()`, before constructing `server`, add:
  ```go
  omni, err := newOmniCollector(cfg.OmniEndpoint, cfg.OmniSAKeyFile, log)
  if err != nil {
      log.Error("omni client init failed", "err", err)
      os.Exit(1)
  }
  ```

  Then update the `server` construction to use the shared instance:
  ```go
  s := &server{
      cfg:     cfg,
      log:     log,
      k8s:     k8s,
      prom:    &promCollector{baseURL: cfg.PrometheusURL, log: log},
      talos:   &talosCollector{omni: omni, cluster: cfg.OmniCluster, peers: cfg.TalosPeers, log: log},
      omni:    omni,
      storage: storage,
      locker:  locker,
  }
  ```

  Remove the old inline `&omniCollector{...}` constructions.

- [ ] **Update default Prometheus URL in `deployment.yaml`**

  In `deploy/deployment.yaml`, change:
  ```yaml
  value: http://prometheus-kube-prometheus-prometheus.prometheus.svc:9090 # REPLACE
  ```
  To:
  ```yaml
  value: http://prometheus.monitoring.svc:9090 # REPLACE with your Prometheus URL
  ```

- [ ] **Verify compilation**

  ```bash
  go build ./...
  ```

- [ ] **Commit**

  ```bash
  git add main.go collect_omni.go deploy/deployment.yaml
  git commit -m "refactor: single shared omniCollector, cache SA key at startup, fix dumpResource error precedence, rename collectMachineLogs"
  ```

---

## Task 6: Bug Fixes (tarGzUpload Leak + collectPeerLogs Handle)

**Files:**
- Modify: `archive.go`
- Modify: `collect_k8s.go`

- [ ] **Add `defer pr.Close()` to `tarGzUpload`**

  In `archive.go`, after `pr, pw := io.Pipe()`, add:
  ```go
  pr, pw := io.Pipe()
  defer pr.Close() // unblocks write goroutine if Upload returns early (e.g. context cancelled)
  ```

- [ ] **Extract `peerTarget` type and `collectOnePeerTarget` helper in `collect_k8s.go`**

  Add the named type at package level (after imports):
  ```go
  type peerTarget struct {
      namespace string
      selector  string
      filename  string
  }
  ```

  Add the helper method:
  ```go
  func (c *k8sCollector) collectOnePeerTarget(ctx context.Context, deadNode string, t peerTarget, peerDir string) error {
      since := int64(15 * 60)
      pods, err := c.client.CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{
          LabelSelector: t.selector,
      })
      if err != nil {
          return fmt.Errorf("list %s pods: %w", t.namespace, err)
      }
      out, err := os.Create(filepath.Join(peerDir, t.filename))
      if err != nil {
          return err
      }
      defer out.Close()
      for _, p := range pods.Items {
          if p.Spec.NodeName == deadNode {
              continue
          }
          fmt.Fprintf(out, "===== pod %s/%s (node %s) =====\n", p.Namespace, p.Name, p.Spec.NodeName)
          opts := &corev1.PodLogOptions{SinceSeconds: &since}
          stream, lerr := c.client.CoreV1().Pods(p.Namespace).GetLogs(p.Name, opts).Stream(ctx)
          if lerr != nil {
              fmt.Fprintf(out, "(stream error: %v)\n", lerr)
              continue
          }
          _, _ = streamFilter(stream, out, deadNode)
          stream.Close()
      }
      return nil
  }
  ```

  Replace the `collectPeerLogs` method body:
  ```go
  func (c *k8sCollector) collectPeerLogs(ctx context.Context, node, dir string) error {
      peerDir := filepath.Join(dir, "peer-logs")
      if err := os.MkdirAll(peerDir, 0o755); err != nil {
          return err
      }
      targets := []peerTarget{
          {"kube-system", "k8s-app=cilium", "cilium.txt"},
          {"rook-ceph", "app=csi-rbdplugin", "ceph-csi.txt"},
      }
      var firstErr error
      for _, t := range targets {
          if err := c.collectOnePeerTarget(ctx, node, t, peerDir); err != nil && firstErr == nil {
              firstErr = err
          }
      }
      return firstErr
  }
  ```

  Remove the old `since` variable and inline struct from the original `collectPeerLogs`.

- [ ] **Verify compilation and existing tests pass**

  ```bash
  go test ./...
  ```
  Expected: all existing tests PASS.

- [ ] **Commit**

  ```bash
  git add archive.go collect_k8s.go
  git commit -m "fix: unblock tarGzUpload goroutine on context cancel; defer peer log file close"
  ```

---

## Task 7: Auth Middleware (TokenReview)

**Files:**
- Modify: `main.go`
- Modify: `deploy/rbac.yaml`
- Modify: `collector_test.go`

- [ ] **Write failing tests for auth middleware**

  Add to `collector_test.go`:
  ```go
  import (
      "io"
      "log/slog"
      "net/http"
      "net/http/httptest"

      authv1 "k8s.io/api/authentication/v1"
      "k8s.io/apimachinery/pkg/runtime"
      "k8s.io/client-go/kubernetes/fake"
      k8stesting "k8s.io/client-go/testing"
  )

  func newTestServer(allowedSA string, authenticated bool, username string) *server {
      client := fake.NewClientset()
      client.AddReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
          return true, &authv1.TokenReview{
              Status: authv1.TokenReviewStatus{
                  Authenticated: authenticated,
                  User:          authv1.UserInfo{Username: username},
              },
          }, nil
      })
      k8sc := &k8sCollector{client: client}
      return &server{
          cfg: Config{AllowedSA: allowedSA},
          log: slog.New(slog.NewTextHandler(io.Discard, nil)),
          k8s: k8sc,
      }
  }

  func TestAuthMiddleware_MissingToken(t *testing.T) {
      s := newTestServer("system:serviceaccount:prometheus:alertmanager", true, "system:serviceaccount:prometheus:alertmanager")
      handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
          w.WriteHeader(http.StatusOK)
      })
      req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
      rec := httptest.NewRecorder()
      handler(rec, req)
      if rec.Code != http.StatusUnauthorized {
          t.Errorf("want 401, got %d", rec.Code)
      }
  }

  func TestAuthMiddleware_ValidToken(t *testing.T) {
      sa := "system:serviceaccount:prometheus:alertmanager"
      s := newTestServer(sa, true, sa)
      called := false
      handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
          called = true
          w.WriteHeader(http.StatusOK)
      })
      req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
      req.Header.Set("Authorization", "Bearer valid-token")
      rec := httptest.NewRecorder()
      handler(rec, req)
      if rec.Code != http.StatusOK {
          t.Errorf("want 200, got %d", rec.Code)
      }
      if !called {
          t.Error("next handler not called")
      }
  }

  func TestAuthMiddleware_WrongSA(t *testing.T) {
      s := newTestServer("system:serviceaccount:prometheus:alertmanager", true, "system:serviceaccount:other:pod")
      handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
          w.WriteHeader(http.StatusOK)
      })
      req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
      req.Header.Set("Authorization", "Bearer wrong-sa-token")
      rec := httptest.NewRecorder()
      handler(rec, req)
      if rec.Code != http.StatusForbidden {
          t.Errorf("want 403, got %d", rec.Code)
      }
  }

  func TestAuthMiddleware_NotAuthenticated(t *testing.T) {
      s := newTestServer("system:serviceaccount:prometheus:alertmanager", false, "")
      handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
          w.WriteHeader(http.StatusOK)
      })
      req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
      req.Header.Set("Authorization", "Bearer bad-token")
      rec := httptest.NewRecorder()
      handler(rec, req)
      if rec.Code != http.StatusUnauthorized {
          t.Errorf("want 401, got %d", rec.Code)
      }
  }
  ```

- [ ] **Run tests to verify they fail**

  ```bash
  go test -run TestAuthMiddleware ./...
  ```
  Expected: `s.authMiddleware undefined`

- [ ] **Implement `authMiddleware` in `main.go`**

  Add after the `server` struct definition:
  ```go
  func (s *server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
      return func(w http.ResponseWriter, r *http.Request) {
          authHeader := r.Header.Get("Authorization")
          if !strings.HasPrefix(authHeader, "Bearer ") {
              http.Error(w, "unauthorized", http.StatusUnauthorized)
              return
          }
          token := strings.TrimPrefix(authHeader, "Bearer ")
          tr, err := s.k8s.client.AuthenticationV1().TokenReviews().Create(
              r.Context(),
              &authv1.TokenReview{
                  Spec: authv1.TokenReviewSpec{Token: token},
              },
              metav1.CreateOptions{},
          )
          if err != nil {
              s.log.Error("token review failed", "err", err)
              http.Error(w, "unauthorized", http.StatusUnauthorized)
              return
          }
          if !tr.Status.Authenticated {
              http.Error(w, "unauthorized", http.StatusUnauthorized)
              return
          }
          if tr.Status.User.Username != s.cfg.AllowedSA {
              s.log.Warn("unexpected service account", "got", tr.Status.User.Username, "want", s.cfg.AllowedSA)
              http.Error(w, "forbidden", http.StatusForbidden)
              return
          }
          next(w, r)
      }
  }
  ```

  Add to `main.go` imports:
  ```go
  authv1 "k8s.io/api/authentication/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  ```

  (Note: `metav1` is already imported — check for duplicates and merge.)

  Add `"strings"` if not already present.

- [ ] **Wire middleware in `main()`**

  Change the webhook handler registration:
  ```go
  // BEFORE:
  mux.HandleFunc("POST /webhook", s.handleWebhook)

  // AFTER:
  mux.HandleFunc("POST /webhook", s.authMiddleware(s.handleWebhook))
  ```

- [ ] **Change `k8sCollector.client` to `kubernetes.Interface` in `collect_k8s.go`**

  This is required so tests can inject a `*fake.Clientset`:
  ```go
  // BEFORE:
  type k8sCollector struct {
      client *kubernetes.Clientset
      log    *slog.Logger
  }

  // AFTER:
  type k8sCollector struct {
      client kubernetes.Interface
      log    *slog.Logger
  }
  ```

  `newK8sCollector` still returns `*kubernetes.Clientset` from `kubernetes.NewForConfig` — that satisfies `kubernetes.Interface`, so no other change needed there.

- [ ] **Add TokenReview RBAC to `deploy/rbac.yaml`**

  Add to the ClusterRole rules:
  ```yaml
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
  ```

- [ ] **Run tests to verify they pass**

  ```bash
  go test -run TestAuthMiddleware ./...
  ```
  Expected: PASS

- [ ] **Commit**

  ```bash
  git add main.go collector_test.go deploy/rbac.yaml
  git commit -m "feat: add TokenReview-based webhook auth, wire authMiddleware"
  ```

---

## Task 8: Goroutine Lifecycle (Semaphore + WaitGroup + Graceful Shutdown)

**Files:**
- Modify: `main.go`

- [ ] **Add `sem`, `wg`, and `collectFn` fields to `server` struct**

  ```go
  type server struct {
      cfg       Config
      log       *slog.Logger
      k8s       *k8sCollector
      prom      *promCollector
      talos     *talosCollector
      omni      *omniCollector
      storage   *S3Storage
      locker    leaseAcquirer
      sem       chan struct{}
      wg        sync.WaitGroup
      collectFn func(ctx context.Context, node, phase string, startsAt time.Time) // nil in production
  }
  ```

  `collectFn` is a test seam: when non-nil it replaces `runCollection`, allowing `handleWebhook` tests to avoid spawning real collection goroutines that would nil-panic on unset fields. In production it is always nil.

  Add `"sync"` to imports.

- [ ] **Define the `leaseAcquirer` interface**

  Add before the `server` struct:
  ```go
  type leaseAcquirer interface {
      Acquire(ctx context.Context, name string) (bool, error)
  }
  ```

  Change the `locker` field type from `*IncidentLocker` to `leaseAcquirer` (done above).

- [ ] **Initialize semaphore and wire SIGTERM in `main()`**

  Replace the tail of `main()` from the `srv` creation onward:
  ```go
  s := &server{
      cfg:     cfg,
      log:     log,
      k8s:     k8s,
      prom:    &promCollector{baseURL: cfg.PrometheusURL, log: log},
      talos:   &talosCollector{omni: omni, cluster: cfg.OmniCluster, peers: cfg.TalosPeers, log: log},
      omni:    omni,
      storage: storage,
      locker:  locker,
      sem:     make(chan struct{}, 10),
  }

  mux := http.NewServeMux()
  mux.HandleFunc("POST /webhook", s.authMiddleware(s.handleWebhook))
  mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(http.StatusOK)
      _, _ = w.Write([]byte("ok"))
  })

  srv := &http.Server{
      Addr:         cfg.ListenAddr,
      Handler:      mux,
      ReadTimeout:  10 * time.Second,
      WriteTimeout: 15 * time.Second,
      IdleTimeout:  60 * time.Second,
  }

  sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
  defer stop()

  go func() {
      <-sigCtx.Done()
      log.Info("shutdown signal received, draining")
      shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
      defer cancel()
      _ = srv.Shutdown(shutCtx)
  }()

  log.Info("listening", "addr", cfg.ListenAddr, "bucket", storage.Bucket, "leaseTTL", cfg.LeaseTTL)
  if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
      log.Error("http server exited", "err", err)
      os.Exit(1)
  }
  s.wg.Wait()
  log.Info("all collections finished, exiting")
  ```

  Add to imports:
  ```go
  "os/signal"
  "sync"
  "syscall"
  ```

- [ ] **Replace fire-and-forget goroutine in `handleWebhook` with semaphore-guarded dispatch**

  Find in `handleWebhook`:
  ```go
  go s.runCollection(context.Background(), node, phase, alert.StartsAt)
  ```

  Replace with:
  ```go
  select {
  case s.sem <- struct{}{}:
  default:
      s.log.Warn("collection semaphore full, dropping alert", "node", node, "phase", phase)
      continue
  }
  collectFn := s.collectFn
  if collectFn == nil {
      collectFn = s.runCollection
  }
  s.wg.Add(1)
  go func(n, p string, ts time.Time) {
      defer func() { <-s.sem }()
      defer s.wg.Done()
      collectFn(context.Background(), n, p, ts)
  }(node, phase, alert.StartsAt)
  ```

- [ ] **Verify compilation**

  ```bash
  go build ./...
  ```

- [ ] **Run all tests**

  ```bash
  go test ./...
  ```
  Expected: PASS

- [ ] **Commit**

  ```bash
  git add main.go
  git commit -m "feat: bound concurrent collections with semaphore, drain on SIGTERM via WaitGroup"
  ```

---

## Task 9: Tests — handleWebhook

**Files:**
- Modify: `collector_test.go`

- [ ] **Add `alertBody` helper and `handleWebhook` table-driven tests**

  Add to `collector_test.go`:
  ```go
  func alertBody(alertname, status, node string) string {
      nodeLabel := ""
      if node != "" {
          nodeLabel = fmt.Sprintf(`,"node":%q`, node)
      }
      return fmt.Sprintf(`{
          "version":"4","groupKey":"test","status":%q,
          "receiver":"test","groupLabels":{},"commonLabels":{},
          "commonAnnotations":{},"externalURL":"",
          "alerts":[{
              "status":%q,
              "labels":{"alertname":%q%s},
              "annotations":{},"startsAt":"2024-01-01T00:00:00Z",
              "endsAt":"0001-01-01T00:00:00Z","generatorURL":"","fingerprint":"abc"
          }]
      }`, status, status, alertname, nodeLabel)
  }

  type fakeLock struct {
      acquired bool
      err      error
      calls    int
  }

  func (f *fakeLock) Acquire(_ context.Context, _ string) (bool, error) {
      f.calls++
      return f.acquired, f.err
  }

  func TestHandleWebhook(t *testing.T) {
      newSrv := func(lock leaseAcquirer, dispatched *int32) *server {
          s := &server{
              cfg:    Config{AllowedSA: "system:serviceaccount:prometheus:alertmanager"},
              log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
              locker: lock,
              sem:    make(chan struct{}, 10),
          }
          s.collectFn = func(_ context.Context, _, _ string, _ time.Time) {
              atomic.AddInt32(dispatched, 1)
          }
          return s
      }

      tests := []struct {
          name           string
          body           string
          lock           *fakeLock
          wantStatus     int
          wantLocked     int // number of Acquire calls expected
          wantDispatched int32 // number of collection goroutines expected
      }{
          {
              name:           "malformed JSON",
              body:           `{invalid`,
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusBadRequest,
              wantLocked:     0,
              wantDispatched: 0,
          },
          {
              name:           "missing node label",
              body:           alertBody("NodeDown", "firing", ""),
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusAccepted,
              wantLocked:     0,
              wantDispatched: 0,
          },
          {
              name:           "unknown alertname",
              body:           alertBody("CPUHigh", "firing", "k8s-worker-1"),
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusAccepted,
              wantLocked:     0,
              wantDispatched: 0,
          },
          {
              name:           "firing NodeDown acquires pre-phase lease and dispatches",
              body:           alertBody("NodeDown", "firing", "k8s-worker-1"),
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusAccepted,
              wantLocked:     1,
              wantDispatched: 1,
          },
          {
              name:           "resolved NodeDown acquires post-phase lease and dispatches",
              body:           alertBody("NodeDown", "resolved", "k8s-worker-1"),
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusAccepted,
              wantLocked:     1,
              wantDispatched: 1,
          },
          {
              name:           "lease not acquired does not dispatch goroutine",
              body:           alertBody("NodeDown", "firing", "k8s-worker-1"),
              lock:           &fakeLock{acquired: false},
              wantStatus:     http.StatusAccepted,
              wantLocked:     1,
              wantDispatched: 0,
          },
          {
              name:           "invalid node name skipped",
              body:           alertBody("NodeDown", "firing", "../../etc"),
              lock:           &fakeLock{acquired: true},
              wantStatus:     http.StatusAccepted,
              wantLocked:     0,
              wantDispatched: 0,
          },
      }

      for _, tt := range tests {
          t.Run(tt.name, func(t *testing.T) {
              var dispatched int32
              s := newSrv(tt.lock, &dispatched)
              req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(tt.body))
              rec := httptest.NewRecorder()
              s.handleWebhook(rec, req)
              s.wg.Wait() // safe: collectFn is a no-op, goroutines complete immediately
              if rec.Code != tt.wantStatus {
                  t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
              }
              if tt.lock.calls != tt.wantLocked {
                  t.Errorf("Acquire calls: got %d, want %d", tt.lock.calls, tt.wantLocked)
              }
              if got := atomic.LoadInt32(&dispatched); got != tt.wantDispatched {
                  t.Errorf("dispatched goroutines: got %d, want %d", got, tt.wantDispatched)
              }
          })
      }
  }
  ```

  Add to `collector_test.go` imports:
  ```go
  "context"
  "fmt"
  "io"
  "log/slog"
  "net/http"
  "net/http/httptest"
  "strings"
  "sync/atomic"
  "time"
  ```

- [ ] **Run tests to verify they pass**

  ```bash
  go test -run TestHandleWebhook ./...
  ```
  Expected: PASS

- [ ] **Commit**

  ```bash
  git add collector_test.go
  git commit -m "test: add handleWebhook table-driven tests covering routing, validation, lease dispatch"
  ```

---

## Task 10: Tests — IncidentLocker.Acquire + tarGzUpload

**Files:**
- Modify: `collector_test.go`

- [ ] **Add `IncidentLocker.Acquire` tests**

  Add to `collector_test.go`:
  ```go
  import (
      coordinationv1 "k8s.io/api/coordination/v1"
      metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
      "k8s.io/apimachinery/pkg/runtime"
      "k8s.io/client-go/kubernetes/fake"
  )

  func makeLocker(objects ...runtime.Object) *IncidentLocker {
      client := fake.NewClientset(objects...)
      return newIncidentLocker(client, "test-ns", "pod-1", 30*time.Minute,
          slog.New(slog.NewTextHandler(io.Discard, nil)))
  }

  func TestAcquire_SuccessfulCreate(t *testing.T) {
      l := makeLocker()
      acquired, err := l.Acquire(context.Background(), "ndbg-node-pre-123")
      if err != nil {
          t.Fatal(err)
      }
      if !acquired {
          t.Error("expected acquired=true on fresh create")
      }
  }

  func TestAcquire_AlreadyExists_LiveLease(t *testing.T) {
      ttl := int32(60)
      renewTime := metav1.NewMicroTime(time.Now())
      existing := &coordinationv1.Lease{
          ObjectMeta: metav1.ObjectMeta{Name: "ndbg-node-pre-123", Namespace: "test-ns"},
          Spec: coordinationv1.LeaseSpec{
              HolderIdentity:       ptr("other-pod"),
              LeaseDurationSeconds: &ttl,
              RenewTime:            &renewTime,
          },
      }
      l := makeLocker(existing)
      acquired, err := l.Acquire(context.Background(), "ndbg-node-pre-123")
      if err != nil {
          t.Fatal(err)
      }
      if acquired {
          t.Error("expected acquired=false for live lease held by another pod")
      }
  }

  func TestAcquire_AlreadyExists_ExpiredLease_Stolen(t *testing.T) {
      ttl := int32(10) // 10s TTL
      renewTime := metav1.NewMicroTime(time.Now().Add(-2 * time.Minute)) // expired
      existing := &coordinationv1.Lease{
          ObjectMeta: metav1.ObjectMeta{Name: "ndbg-node-pre-123", Namespace: "test-ns",
              ResourceVersion: "1"},
          Spec: coordinationv1.LeaseSpec{
              HolderIdentity:       ptr("old-pod"),
              LeaseDurationSeconds: &ttl,
              RenewTime:            &renewTime,
          },
      }
      l := makeLocker(existing)
      acquired, err := l.Acquire(context.Background(), "ndbg-node-pre-123")
      if err != nil {
          t.Fatal(err)
      }
      if !acquired {
          t.Error("expected acquired=true after stealing expired lease")
      }
  }

  func TestAcquire_SecondCallReturnsFalse(t *testing.T) {
      l := makeLocker()
      acquired1, _ := l.Acquire(context.Background(), "ndbg-node-pre-123")
      if !acquired1 {
          t.Fatal("first acquire should succeed")
      }
      // Second locker with same client — simulates a second replica
      l2 := newIncidentLocker(l.client, "test-ns", "pod-2", 30*time.Minute,
          slog.New(slog.NewTextHandler(io.Discard, nil)))
      acquired2, err := l2.Acquire(context.Background(), "ndbg-node-pre-123")
      if err != nil {
          t.Fatal(err)
      }
      if acquired2 {
          t.Error("expected acquired=false when lease already held")
      }
  }
  ```

  Add `"context"` to imports if not present.

- [ ] **Add `tarGzUpload` test**

  Add to `collector_test.go`:
  ```go
  import (
      "archive/tar"
      "bytes"
      "compress/gzip"
      "context"
      "io"
      "net/http"
      "net/http/httptest"
      "os"
      "path/filepath"

      "github.com/aws/aws-sdk-go-v2/aws"
      awsconfig "github.com/aws/aws-sdk-go-v2/config"
      "github.com/aws/aws-sdk-go-v2/credentials"
      "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
      "github.com/aws/aws-sdk-go-v2/service/s3"
  )

  func TestTarGzUpload(t *testing.T) {
      // Build source directory with known contents.
      dir := t.TempDir()
      if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o644); err != nil {
          t.Fatal(err)
      }
      sub := filepath.Join(dir, "sub")
      if err := os.MkdirAll(sub, 0o755); err != nil {
          t.Fatal(err)
      }
      if err := os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nested content"), 0o644); err != nil {
          t.Fatal(err)
      }

      // Fake S3 server — accepts a single-part PUT and captures the body.
      var received []byte
      srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
          if r.Method != http.MethodPut {
              http.Error(w, "unexpected", http.StatusMethodNotAllowed)
              return
          }
          data, _ := io.ReadAll(r.Body)
          received = data
          w.Header().Set("ETag", `"test-etag"`)
          w.WriteHeader(http.StatusOK)
      }))
      defer srv.Close()

      // Build S3 client pointing at the fake server.
      awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
          awsconfig.WithRegion("us-east-1"),
          awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
      )
      if err != nil {
          t.Fatal(err)
      }
      client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
          o.BaseEndpoint = aws.String(srv.URL)
          o.UsePathStyle = true
      })
      uploader := manager.NewUploader(client, func(u *manager.Uploader) {
          u.PartSize = 1024 * 1024 * 1024 // 1 GiB — forces single-part upload for test files
      })

      if err := tarGzUpload(context.Background(), dir, uploader, "test-bucket", "test/key.tar.gz"); err != nil {
          t.Fatalf("tarGzUpload: %v", err)
      }

      if len(received) == 0 {
          t.Fatal("fake S3 server received no data")
      }

      // Decompress and verify contents.
      gz, err := gzip.NewReader(bytes.NewReader(received))
      if err != nil {
          t.Fatalf("gzip.NewReader: %v", err)
      }
      tr := tar.NewReader(gz)
      files := map[string]string{}
      for {
          hdr, err := tr.Next()
          if err == io.EOF {
              break
          }
          if err != nil {
              t.Fatalf("tar.Next: %v", err)
          }
          data, _ := io.ReadAll(tr)
          files[hdr.Name] = string(data)
      }

      if files["hello.txt"] != "hello world" {
          t.Errorf("hello.txt: got %q", files["hello.txt"])
      }
      if files["sub/nested.txt"] != "nested content" {
          t.Errorf("sub/nested.txt: got %q", files["sub/nested.txt"])
      }
  }
  ```

- [ ] **Update go.mod (promote credentials to direct dependency)**

  The `tarGzUpload` test imports `github.com/aws/aws-sdk-go-v2/credentials` directly. Run:
  ```bash
  go mod tidy
  ```
  Expected: `go.mod` updates the credentials line from `// indirect` to a direct dep; `go.sum` unchanged.

- [ ] **Run all tests**

  ```bash
  go test ./...
  ```
  Expected: all PASS (including new Acquire and tarGzUpload tests)

- [ ] **Commit**

  ```bash
  git add collector_test.go go.mod go.sum
  git commit -m "test: add IncidentLocker.Acquire and tarGzUpload tests"
  ```

---

## Task 11: Deploy Manifests (NetworkPolicy + Cleanup)

**Files:**
- Create: `deploy/networkpolicy.yaml`
- Modify: `deploy/deployment.yaml`
- Modify: `deploy/kustomization.yaml`

- [ ] **Create `deploy/networkpolicy.yaml`**

  ```yaml
  ---
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: node-debug-collector
    namespace: node-debug
  spec:
    podSelector:
      matchLabels:
        app.kubernetes.io/name: node-debug-collector
    policyTypes:
    - Ingress
    ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: prometheus
        podSelector:
          matchLabels:
            app.kubernetes.io/name: alertmanager
      ports:
      - protocol: TCP
        port: 8080
  ```

- [ ] **Clean up `deploy/deployment.yaml` — remove HA env vars**

  Remove these entries from the `env` section:
  ```yaml
  # DELETE:
  - name: HA_URL
    value: https://ha.example.com # REPLACE or remove if not forwarding to Home Assistant
  - name: HA_WEBHOOK_ID
    valueFrom:
      secretKeyRef:
        name: node-debug-collector-ha
        key: webhook-id
        optional: true
  ```

- [ ] **Add `networkpolicy.yaml` to `deploy/kustomization.yaml`**

  Add `- networkpolicy.yaml` to the resources list:
  ```yaml
  resources:
    - namespace.yaml
    - obc.yaml
    - rbac.yaml
    - external-secret.yaml
    - service.yaml
    - deployment.yaml
    - pdb.yaml
    - networkpolicy.yaml
  ```

- [ ] **Commit**

  ```bash
  git add deploy/networkpolicy.yaml deploy/deployment.yaml deploy/kustomization.yaml
  git commit -m "feat: add NetworkPolicy restricting webhook ingress to Alertmanager; remove HA env vars from deployment"
  ```

---

## Task 12: Homelab — Alertmanager HA + Webhook Auth

**Repo:** `~/git/homelab`

**Files:**
- Modify: `k8s/monitoring/values.yaml`
- Modify: `k8s/monitoring/telegram-alertmanager.yaml`

- [ ] **Add Alertmanager HA config to `values.yaml`**

  Under `alertmanager.alertmanagerSpec`, add:
  ```yaml
  alertmanager:
    alertmanagerSpec:
      replicas: 2
      podAntiAffinity: soft
      resources:
        requests:
          cpu: 10m
          memory: 64Mi
        limits:
          memory: 128Mi
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

- [ ] **Update `telegram-alertmanager.yaml` — rename receiver and add auth**

  Find the `home-assistant-node-remediation` receiver block:
  ```yaml
  - name: 'home-assistant-node-remediation'
    webhookConfigs:
    - url: 'http://node-debug-collector.node-debug.svc.cluster.local:8080/webhook'
      sendResolved: true
      maxAlerts: 0
  ```

  Replace with:
  ```yaml
  - name: 'node-debug-collector'
    webhookConfigs:
    - url: 'http://node-debug-collector.node-debug.svc.cluster.local:8080/webhook'
      sendResolved: true
      maxAlerts: 0
      httpConfig:
        authorization:
          type: Bearer
          credentialsFile: /var/run/secrets/alertmanager-webhook/token
  ```

  Also update the route that references this receiver:
  ```yaml
  # BEFORE:
  receiver: 'home-assistant-node-remediation'

  # AFTER:
  receiver: 'node-debug-collector'
  ```

- [ ] **Commit (homelab repo)**

  ```bash
  cd ~/git/homelab
  git add k8s/monitoring/values.yaml k8s/monitoring/telegram-alertmanager.yaml
  git commit -m "feat: Alertmanager HA (replicas=2, anti-affinity), projected SA token for webhook auth"
  ```

---

## Self-Review Checklist

After writing this plan, checking against the spec:

| Spec requirement | Task |
|-----------------|------|
| Remove HA code | Task 1 |
| `AllowedSA` + `TalosPeers` in Config | Task 2 |
| `validateNodeName` | Task 3 |
| Body size limit + HTTP server timeouts | Task 4 |
| Redact raw body from error log | Task 4 |
| Single `omniCollector`, cached SA key | Task 5 |
| Fix `dumpResource` error precedence | Task 5 |
| Rename `collectMachineLogs` | Task 5 |
| Update default Prometheus URL | Task 5 |
| `defer pr.Close()` in `tarGzUpload` | Task 6 |
| `collectPeerLogs` deferred file close | Task 6 |
| `authMiddleware` + TokenReview | Task 7 |
| RBAC: TokenReview create | Task 7 |
| Semaphore + WaitGroup + SIGTERM | Task 8 |
| `leaseAcquirer` interface | Task 8 |
| `handleWebhook` tests | Task 9 |
| `Acquire` tests | Task 10 |
| `tarGzUpload` test | Task 10 |
| NetworkPolicy | Task 11 |
| Remove HA env vars from deployment | Task 11 |
| Alertmanager replicas: 2, anti-affinity | Task 12 |
| Projected SA token volume | Task 12 |
| Rename receiver + add httpConfig | Task 12 |
