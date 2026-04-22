package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AlertmanagerPayload struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

type Config struct {
	ListenAddr    string
	Namespace     string
	PodName       string
	LeaseTTL      time.Duration
	PrometheusURL string
	OmniEndpoint  string
	OmniSAKeyFile string
	OmniCluster   string
	AllowedSA     string
	TalosPeers    []string
}

func loadConfig() Config {
	leaseTTL, err := time.ParseDuration(envOr("LEASE_TTL", "30m"))
	if err != nil {
		leaseTTL = 30 * time.Minute
	}
	return Config{
		ListenAddr:    envOr("LISTEN_ADDR", ":8080"),
		Namespace:     envOr("POD_NAMESPACE", "node-debug"),
		PodName:       envOr("POD_NAME", "node-debug-collector"),
		LeaseTTL:      leaseTTL,
		PrometheusURL: envOr("PROMETHEUS_URL", "http://prometheus-kube-prometheus-prometheus.prometheus.svc:9090"),
		OmniEndpoint:  os.Getenv("OMNI_ENDPOINT"),
		OmniSAKeyFile: envOr("OMNI_SERVICE_ACCOUNT_KEY_FILE", "/etc/omni/sa-key"),
		OmniCluster:   envOr("OMNI_CLUSTER", "prod"),
		AllowedSA:     envOr("ALLOWED_SA", "system:serviceaccount:prometheus:alertmanager"),
		TalosPeers:    parsePeers(os.Getenv("TALOS_PEERS")),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

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

var validNode = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$`)

func validateNodeName(name string) error {
	// 232 = 253 (k8s name limit) minus 21 chars of leaseName overhead (ndbg-<node>-post-<10digit_epoch>)
	if len(name) > 232 || !validNode.MatchString(name) {
		return fmt.Errorf("invalid node name: %q", name)
	}
	return nil
}

type leaseAcquirer interface {
	Acquire(ctx context.Context, name string) (bool, error)
}

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
	collectFn func(ctx context.Context, node, phase string, startsAt time.Time)
}

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

func main() {
	cfg := loadConfig()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx := context.Background()

	k8s, err := newK8sCollector(log)
	if err != nil {
		log.Error("k8s client init failed", "err", err)
		os.Exit(1)
	}

	storage, err := newS3Storage(ctx)
	if err != nil {
		log.Error("s3 client init failed", "err", err)
		os.Exit(1)
	}

	locker := newIncidentLocker(k8s.client, cfg.Namespace, cfg.PodName, cfg.LeaseTTL, log)

	if cfg.OmniEndpoint == "" {
		log.Error("OMNI_ENDPOINT not set")
		os.Exit(1)
	}
	omni, err := newOmniCollector(cfg.OmniEndpoint, cfg.OmniSAKeyFile, log)
	if err != nil {
		log.Error("omni client init failed", "err", err)
		os.Exit(1)
	}

	s := &server{
		cfg:     cfg,
		log:     log,
		k8s:     k8s,
		prom:    &promCollector{baseURL: cfg.PrometheusURL, client: &http.Client{Timeout: 2 * time.Minute}, log: log},
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
		WriteTimeout: 60 * time.Second,
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
}

func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var payload AlertmanagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		s.log.Error("unmarshal payload", "err", err, "body_len", len(body))
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	s.log.Info("webhook received", "status", payload.Status, "alerts", len(payload.Alerts), "group", payload.GroupKey)

	for _, alert := range payload.Alerts {
		node := alert.Labels["node"]
		alertname := alert.Labels["alertname"]
		if node == "" {
			continue
		}
		if err := validateNodeName(node); err != nil {
			s.log.Warn("invalid node name in alert, skipping", "node", node, "err", err)
			continue
		}

		var phase string
		switch {
		case alertname == "NodeDown" && alert.Status == "firing":
			phase = "pre"
		case alertname == "NodeDown" && alert.Status == "resolved":
			phase = "post"
		default:
			continue
		}

		// Per-alert 5s budget for the lease acquire so later alerts in a large
		// batch are not starved by a slow k8s API on earlier ones.
		alertCtx, alertCancel := context.WithTimeout(r.Context(), 5*time.Second)
		name := leaseName(node, phase, alert.StartsAt)
		acquired, err := s.locker.Acquire(alertCtx, name)
		alertCancel()
		if err != nil {
			s.log.Error("lease acquire failed", "lease", name, "err", err)
			continue
		}
		if !acquired {
			continue
		}

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
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted"))
}

func (s *server) runCollection(ctx context.Context, node, phase string, startsAt time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	start := time.Now()
	ts := startsAt.UTC().Format("20060102T150405Z")
	log := s.log.With("node", node, "ts", ts, "phase", phase)
	log.Info("collection started")

	workdir, err := os.MkdirTemp("", fmt.Sprintf("debug-%s-%s-%s-*", node, ts, phase))
	if err != nil {
		log.Error("mkdtemp", "err", err)
		return
	}
	defer func() { _ = os.RemoveAll(workdir) }()

	var errWriter = io.Discard
	if errFile, ferr := os.Create(filepath.Join(workdir, "errors.txt")); ferr == nil {
		defer func() { _ = errFile.Close() }()
		errWriter = errFile
	} else {
		log.Warn("could not create errors.txt", "err", ferr)
	}
	errlog := func(where string, err error) {
		if err == nil {
			return
		}
		_, _ = fmt.Fprintf(errWriter, "%s: %v\n", where, err)
		log.Warn("collector error", "source", where, "err", err)
	}

	switch phase {
	case "pre":
		errlog("k8s.node", s.k8s.collectNode(ctx, node, workdir))
		errlog("k8s.events", s.k8s.collectEvents(ctx, node, workdir))
		errlog("k8s.pods", s.k8s.collectPods(ctx, node, workdir))
		errlog("k8s.peerlogs", s.k8s.collectPeerLogs(ctx, node, workdir))
		errlog("prometheus", s.prom.collectNodeMetrics(ctx, node, workdir))
		errlog("omni.machine", s.omni.collectMachineState(ctx, workdir))
		errlog("omni.status", s.omni.collectMachineStatusResources(ctx, workdir))
		errlog("talos.peerdmesg", s.talos.collectPeerDmesg(ctx, node, workdir))
	case "post":
		errlog("talos.dmesg", s.talos.collectDmesg(ctx, node, workdir))
		errlog("talos.kmsg", s.talos.collectKmsg(ctx, node, workdir))
		errlog("talos.journal", s.talos.collectJournals(ctx, node, workdir))
		errlog("talos.machineinfo", s.talos.collectMachineInfo(ctx, node, workdir))
		errlog("omni.postmachine", s.omni.collectPostRecoveryStatus(ctx, workdir))
	}

	key := fmt.Sprintf("%s/%s/%s.tar.gz", node, startsAt.UTC().Format(time.RFC3339), phase)
	if err := tarGzUpload(ctx, workdir, s.storage.Uploader, s.storage.Bucket, key); err != nil {
		log.Error("s3 upload failed", "err", err, "key", key)
		return
	}
	log.Info("collection complete", "bucket", s.storage.Bucket, "key", key, "elapsed", time.Since(start))
}

