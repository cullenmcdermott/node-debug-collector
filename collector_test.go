package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	authv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestLeaseName(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	tests := []struct {
		node, phase string
		want        string
	}{
		{"k8s-worker-1", "pre", "ndbg-k8s-worker-1-pre-1700000000"},
		{"k8s-worker-1", "post", "ndbg-k8s-worker-1-post-1700000000"},
	}
	for _, tt := range tests {
		got := leaseName(tt.node, tt.phase, ts)
		if got != tt.want {
			t.Errorf("leaseName(%q, %q) = %q, want %q", tt.node, tt.phase, got, tt.want)
		}
	}
}

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
		{"233 chars - exceeds lease name limit", strings.Repeat("a", 233), false},
		{"exactly 232", strings.Repeat("a", 232), true},
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

func ptr[T any](v T) *T { return &v }

func makeLease(renewedAgo time.Duration, ttlSec int32) *coordinationv1.Lease {
	renewTime := metav1.NewMicroTime(time.Now().Add(-renewedAgo))
	return &coordinationv1.Lease{
		Spec: coordinationv1.LeaseSpec{
			RenewTime:            &renewTime,
			LeaseDurationSeconds: &ttlSec,
		},
	}
}

func TestLeaseExpired(t *testing.T) {
	tests := []struct {
		name  string
		lease *coordinationv1.Lease
		want  bool
	}{
		{
			name:  "nil renew time",
			lease: &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{LeaseDurationSeconds: ptr(int32(60))}},
			want:  true,
		},
		{
			name:  "nil duration",
			lease: &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{RenewTime: func() *metav1.MicroTime { t := metav1.NewMicroTime(time.Now()); return &t }()}},
			want:  true,
		},
		{
			name:  "fresh lease",
			lease: makeLease(10*time.Second, 60),
			want:  false,
		},
		{
			name:  "expired lease",
			lease: makeLease(2*time.Minute, 60),
			want:  true,
		},
		{
			name:  "exactly at boundary",
			lease: makeLease(60*time.Second, 60),
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := leaseExpired(tt.lease); got != tt.want {
				t.Errorf("leaseExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStreamFilter(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		needle string
		want   string
	}{
		{
			name:   "passes all lines when needle is empty",
			input:  "line one\nline two\nline three\n",
			needle: "",
			want:   "line one\nline two\nline three\n",
		},
		{
			name:   "filters to matching lines",
			input:  "node-a connected\nnode-b error\nnode-a disconnected\n",
			needle: "node-a",
			want:   "node-a connected\nnode-a disconnected\n",
		},
		{
			name:   "no matches returns empty",
			input:  "alpha\nbeta\ngamma\n",
			needle: "delta",
			want:   "",
		},
		{
			name:   "partial line at EOF is included when it matches",
			input:  "match here",
			needle: "match",
			want:   "match here",
		},
		{
			name:   "partial line at EOF is excluded when it does not match",
			input:  "no match here",
			needle: "other",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			streamFilter(strings.NewReader(tt.input), &out, tt.needle)
			if got := out.String(); got != tt.want {
				t.Errorf("streamFilter(%q) =\n%q\nwant\n%q", tt.needle, got, tt.want)
			}
		})
	}
}

func newTestServer(allowedSA string, authenticated bool, username string) *server {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
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
		wantLocked     int
		wantDispatched int32
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
			name:           "lease acquire error returns 202 not 500",
			body:           alertBody("NodeDown", "firing", "k8s-worker-1"),
			lock:           &fakeLock{err: errors.New("api unavailable")},
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
			s.wg.Wait()
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
	ttl := int32(10)
	renewTime := metav1.NewMicroTime(time.Now().Add(-2 * time.Minute))
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

func TestTarGzUpload(t *testing.T) {
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
		u.PartSize = 1024 * 1024 * 1024
	})

	if err := tarGzUpload(context.Background(), dir, uploader, "test-bucket", "test/key.tar.gz"); err != nil {
		t.Fatalf("tarGzUpload: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("fake S3 server received no data")
	}

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
