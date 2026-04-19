package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type promCollector struct {
	baseURL string
	client  *http.Client
	log     *slog.Logger
}

// queries lists the Prometheus range queries we snapshot on pre-pass. Each query
// uses {node="<node>"} or {instance=~"<node>.*"} as appropriate; Prometheus
// returns an empty result set if there's no data (harmless).
var nodeQueries = []struct {
	name string
	expr string
}{
	{"kube_node_status_condition", `kube_node_status_condition{node="%s"}`},
	{"node_cpu_seconds_total", `rate(node_cpu_seconds_total{instance=~"%s.*"}[1m])`},
	{"node_memory_MemAvailable_bytes", `node_memory_MemAvailable_bytes{instance=~"%s.*"}`},
	{"node_load1", `node_load1{instance=~"%s.*"}`},
	{"node_filesystem_avail_bytes", `node_filesystem_avail_bytes{instance=~"%s.*",fstype!="tmpfs"}`},
	{"node_network_receive_errs_total", `rate(node_network_receive_errs_total{instance=~"%s.*",device!~"lo|veth.*"}[1m])`},
	{"node_network_transmit_errs_total", `rate(node_network_transmit_errs_total{instance=~"%s.*",device!~"lo|veth.*"}[1m])`},
	{"container_oom_events_total", `sum by (pod,namespace) (rate(container_oom_events_total[1m])) * on(pod,namespace) group_left(node) kube_pod_info{node="%s"}`},
}

func (p *promCollector) collectNodeMetrics(ctx context.Context, node, dir string) error {
	outDir := filepath.Join(dir, "prometheus")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	end := time.Now()
	start := end.Add(-1 * time.Hour)

	var firstErr error
	for _, q := range nodeQueries {
		expr := fmt.Sprintf(q.expr, node)
		data, err := p.queryRange(ctx, expr, start, end, 15*time.Second)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", q.name, err)
			}
			continue
		}
		if werr := os.WriteFile(filepath.Join(outDir, q.name+".json"), data, 0o644); werr != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s write: %w", q.name, werr)
		}
	}
	return firstErr
}

func (p *promCollector) queryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) ([]byte, error) {
	u, err := url.Parse(p.baseURL + "/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("query", expr)
	q.Set("start", fmt.Sprintf("%d", start.Unix()))
	q.Set("end", fmt.Sprintf("%d", end.Unix()))
	q.Set("step", fmt.Sprintf("%.0fs", step.Seconds()))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	// Pretty-print for diffability.
	var out map[string]any
	if err := json.Unmarshal(body, &out); err == nil {
		if b, err := json.MarshalIndent(out, "", "  "); err == nil {
			return b, nil
		}
	}
	return body, nil
}
