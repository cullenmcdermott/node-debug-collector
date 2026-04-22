package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type peerTarget struct {
	namespace string
	selector  string
	filename  string
}

type k8sCollector struct {
	client kubernetes.Interface
	log    *slog.Logger
}

func newK8sCollector(log *slog.Logger) (*k8sCollector, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("new clientset: %w", err)
	}
	return &k8sCollector{client: cs, log: log}, nil
}

func (c *k8sCollector) collectNode(ctx context.Context, node, dir string) error {
	n, err := c.client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "node.json"), n)
}

func (c *k8sCollector) collectEvents(ctx context.Context, node, dir string) error {
	selector := fields.OneTermEqualSelector("involvedObject.name", node).String()
	list, err := c.client.CoreV1().Events("").List(ctx, metav1.ListOptions{
		FieldSelector: selector,
		Limit:         2000,
	})
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "events.json"), list)
}

func (c *k8sCollector) collectPods(ctx context.Context, node, dir string) error {
	list, err := c.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "pods.json"), list)
}

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
	defer func() { _ = out.Close() }()
	for _, p := range pods.Items {
		if p.Spec.NodeName == deadNode {
			continue
		}
		_, _ = fmt.Fprintf(out, "===== pod %s/%s (node %s) =====\n", p.Namespace, p.Name, p.Spec.NodeName)
		opts := &corev1.PodLogOptions{SinceSeconds: &since}
		stream, lerr := c.client.CoreV1().Pods(p.Namespace).GetLogs(p.Name, opts).Stream(ctx)
		if lerr != nil {
			_, _ = fmt.Fprintf(out, "(stream error: %v)\n", lerr)
			continue
		}
		_, _ = streamFilter(stream, out, deadNode)
		_ = stream.Close()
	}
	return nil
}

// collectPeerLogs pulls the last 15m of logs from Cilium and Ceph CSI DaemonSet
// pods running on *healthy* peer nodes, filtered to lines mentioning the dead node.
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

// streamFilter writes only lines mentioning needle (if non-empty); otherwise passes through.
func streamFilter(r io.Reader, w io.Writer, needle string) (int64, error) {
	var total int64
	buf := make([]byte, 64*1024)
	var carry strings.Builder
	for {
		n, err := r.Read(buf)
		if n > 0 {
			carry.Write(buf[:n])
			for {
				s := carry.String()
				idx := strings.IndexByte(s, '\n')
				if idx < 0 {
					break
				}
				line := s[:idx+1]
				carry.Reset()
				carry.WriteString(s[idx+1:])
				if needle == "" || strings.Contains(line, needle) {
					nn, _ := w.Write([]byte(line))
					total += int64(nn)
				}
			}
		}
		if err == io.EOF {
			if carry.Len() > 0 && (needle == "" || strings.Contains(carry.String(), needle)) {
				nn, _ := w.Write([]byte(carry.String()))
				total += int64(nn)
			}
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
