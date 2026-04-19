# Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the Critical and Important issues identified by the post-OSS-hardening code review, plus the Minor file-ordering and error-discard bugs.

**Architecture:** Five focused commits touching `main.go`, `collect_omni.go`, `collect_k8s.go`, `collect_prometheus.go`, `deploy/deployment.yaml`, and `collector_test.go`. No new files, no refactors beyond the review findings.

**Tech Stack:** Go 1.26, `net/http`, `k8s.io/client-go`

---

## File Map

| File | What changes |
|------|-------------|
| `main.go` | Remove `hardFailure`/500 path; increase `WriteTimeout` to 60s |
| `collector_test.go` | Add test case: lease-acquire error → 202 (not 500) |
| `collect_omni.go` | Remove `MachineStatusType` from `collectMachineStatusResources` items slice |
| `collect_k8s.go` | Move `os.Create` after pod list in `collectOnePeerTarget` |
| `collect_prometheus.go` | Surface `os.WriteFile` error into `firstErr` |
| `deploy/deployment.yaml` | Add commented `ALLOWED_SA` placeholder env entry |

---

## Task 1: Fix hardFailure → Always Return 202

**Files:**
- Modify: `main.go:252-312`
- Modify: `collector_test.go`

The `hardFailure` + 500 pattern is dangerous: Alertmanager retries the whole batch on a 500, and if a collection goroutine from the first attempt finishes and the lease expires before the retry, you get a duplicate collection. Collection is explicitly best-effort; log errors and return 202.

- [ ] **Add failing test case for lease-acquire error**

  In `collector_test.go`, add this case to the `tests` slice inside `TestHandleWebhook` (after the `"lease not acquired does not dispatch goroutine"` case):

  ```go
  {
      name:           "lease acquire error returns 202 not 500",
      body:           alertBody("NodeDown", "firing", "k8s-worker-1"),
      lock:           &fakeLock{err: errors.New("api unavailable")},
      wantStatus:     http.StatusAccepted,
      wantLocked:     1,
      wantDispatched: 0,
  },
  ```

  Add `"errors"` to the import block in `collector_test.go` (it is not currently imported).

- [ ] **Run the new test case to verify it fails**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go test -run 'TestHandleWebhook/lease_acquire_error' ./...
  ```

  Expected: FAIL — status: got 500, want 202

- [ ] **Remove `hardFailure` from `handleWebhook` in `main.go`**

  In `handleWebhook` (lines ~252–312), make these two changes:

  1. Remove the `var hardFailure bool` declaration at the top of the loop (line 252).

  2. Replace the error branch inside the `if err != nil` block after `s.locker.Acquire`:

     ```go
     // BEFORE:
     if err != nil {
         s.log.Error("lease acquire failed", "lease", name, "err", err)
         hardFailure = true
         continue
     }

     // AFTER:
     if err != nil {
         s.log.Error("lease acquire failed", "lease", name, "err", err)
         continue
     }
     ```

  3. Remove the `hardFailure` check and early return at the bottom of the handler:

     ```go
     // DELETE these lines entirely:
     if hardFailure {
         http.Error(w, "internal error", http.StatusInternalServerError)
         return
     }
     ```

  The handler should now end with just:

  ```go
  w.WriteHeader(http.StatusAccepted)
  _, _ = w.Write([]byte("accepted"))
  ```

- [ ] **Run all tests to verify they pass**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go test ./...
  ```

  Expected: all PASS

- [ ] **Commit**

  ```bash
  cd /Users/cullen/git/node-debug-collector
  git add main.go collector_test.go
  git commit -m "fix: always return 202 from handleWebhook; log lease-acquire errors as best-effort"
  ```

---

## Task 2: Remove Duplicate MachineStatusType from Pre-Phase

**Files:**
- Modify: `collect_omni.go:104-110`

`collectMachineStatusResources` (called in the `pre` phase) collects both `ClusterMachineStatusType` and `MachineStatusType`. `collectPostRecoveryStatus` (called in the `post` phase) also dumps `MachineStatusType` into `post-recovery-machine-status.yaml`. The pre-phase copy is redundant and confuses incident responders who see two files with identical data.

- [ ] **Edit `collectMachineStatusResources` in `collect_omni.go`**

  Remove the `MachineStatusType` entry from the `items` slice. The method currently reads (lines ~104–110):

  ```go
  items := []struct {
      file    string
      resType resource.Type
  }{
      {"cluster-machine-status.yaml", omniresomni.ClusterMachineStatusType},
      {"machinestatuses.yaml", omniresomni.MachineStatusType},
  }
  ```

  Change it to:

  ```go
  items := []struct {
      file    string
      resType resource.Type
  }{
      {"cluster-machine-status.yaml", omniresomni.ClusterMachineStatusType},
  }
  ```

- [ ] **Verify compilation**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go build ./...
  ```

  Expected: no output, exit 0.

- [ ] **Run all tests**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go test ./...
  ```

  Expected: all PASS

- [ ] **Commit**

  ```bash
  cd /Users/cullen/git/node-debug-collector
  git add collect_omni.go
  git commit -m "fix: remove duplicate MachineStatusType collection from pre-phase"
  ```

---

## Task 3: Increase WriteTimeout

**Files:**
- Modify: `main.go:212`

`WriteTimeout: 15s` covers the full request/response cycle. The webhook handler calls `s.locker.Acquire` (k8s API call with a per-alert 5s budget) for every alert in the batch. A 4-alert batch near the 5s per-alert limit uses 20s — exceeding 15s causes the connection to be torn down mid-handler, triggering an Alertmanager retry.

- [ ] **Change `WriteTimeout` in `main.go`**

  Find the `http.Server` struct literal (around line 208):

  ```go
  srv := &http.Server{
      Addr:         cfg.ListenAddr,
      Handler:      mux,
      ReadTimeout:  10 * time.Second,
      WriteTimeout: 15 * time.Second,
      IdleTimeout:  60 * time.Second,
  }
  ```

  Change `WriteTimeout` to 60 seconds:

  ```go
  srv := &http.Server{
      Addr:         cfg.ListenAddr,
      Handler:      mux,
      ReadTimeout:  10 * time.Second,
      WriteTimeout: 60 * time.Second,
      IdleTimeout:  60 * time.Second,
  }
  ```

- [ ] **Verify compilation**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go build ./...
  ```

  Expected: no output, exit 0.

- [ ] **Commit**

  ```bash
  cd /Users/cullen/git/node-debug-collector
  git add main.go
  git commit -m "fix: increase WriteTimeout to 60s to accommodate multi-alert batch lease calls"
  ```

---

## Task 4: Document ALLOWED_SA in Deployment Manifest

**Files:**
- Modify: `deploy/deployment.yaml`

`ALLOWED_SA` is a security-critical config value that controls which Kubernetes identity can trigger debug collections. It is not listed in the deployment manifest, so operators deploying to clusters with different Alertmanager SA naming will get silent 403s with no hint about what to configure.

- [ ] **Add commented `ALLOWED_SA` entry to `deploy/deployment.yaml`**

  Find the `env` section. It currently ends with:

  ```yaml
            - name: TALOS_PEERS
                value: "node-1,node-2,node-3" # REPLACE with comma-separated Talos node hostnames
  ```

  Add after that line:

  ```yaml
            # - name: ALLOWED_SA
            #   value: "system:serviceaccount:prometheus:alertmanager" # REPLACE if your Alertmanager SA differs
  ```

- [ ] **Commit**

  ```bash
  cd /Users/cullen/git/node-debug-collector
  git add deploy/deployment.yaml
  git commit -m "docs: add commented ALLOWED_SA placeholder to deployment manifest"
  ```

---

## Task 5: Fix Minor Bugs (File Ordering + WriteFile Error)

**Files:**
- Modify: `collect_k8s.go:73-85`
- Modify: `collect_prometheus.go:57`

Two small bugs:
1. `collectOnePeerTarget` creates the output file before listing pods — on list failure an empty file ends up in the artifact archive.
2. `collect_prometheus.go` silently discards `os.WriteFile` errors, hiding tmpfs-full or path errors.

- [ ] **Fix file-open ordering in `collectOnePeerTarget` in `collect_k8s.go`**

  The current code (lines ~73–85):

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
  ```

  Move `os.Create` after the pod list succeeds (no other changes to the function):

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
  ```

  Wait — the current code already has this ordering (pods listed first, then file created). Verify by reading `collect_k8s.go:73-85` before editing. If the ordering is already correct, skip this step.

  Actually re-reading the review: "The file is created (`os.Create`) before the pod list call." Let me re-check — in the code I read (lines 73-85), `List` is called at line 75, then `os.Create` at line 81. That is correct order. **This fix is not needed — skip the k8s change.**

- [ ] **Fix silently discarded WriteFile error in `collect_prometheus.go`**

  Line 57 currently reads:

  ```go
  _ = os.WriteFile(filepath.Join(outDir, q.name+".json"), data, 0o644)
  ```

  Replace with:

  ```go
  if werr := os.WriteFile(filepath.Join(outDir, q.name+".json"), data, 0o644); werr != nil && firstErr == nil {
      firstErr = fmt.Errorf("%s write: %w", q.name, werr)
  }
  ```

- [ ] **Verify compilation and tests**

  ```bash
  cd /Users/cullen/git/node-debug-collector && go test ./...
  ```

  Expected: all PASS

- [ ] **Commit**

  ```bash
  cd /Users/cullen/git/node-debug-collector
  git add collect_prometheus.go
  git commit -m "fix: surface os.WriteFile error in promCollector instead of silently discarding"
  ```

---

## Self-Review

| Review finding | Task |
|---------------|------|
| Critical: hardFailure+500 triggers Alertmanager retry races | Task 1 |
| Critical: MachineStatusType collected twice in pre-phase | Task 2 |
| Important: WriteTimeout 15s too short for multi-alert batches | Task 3 |
| Important: ALLOWED_SA not documented in deployment.yaml | Task 4 |
| Minor: collectOnePeerTarget file created before pod list | Task 5 (verified not needed) |
| Minor: promCollector WriteFile error silently discarded | Task 5 |
| Minor: no test for lease-error path | Task 1 (test added) |
| Minor: alert.StartsAt not validated | Not addressed — nice-to-have, no functional impact currently |
| Important: omni methods now cluster-wide (no node filter) | Not addressed — behavioral decision documented in existing comments; no code change needed |
