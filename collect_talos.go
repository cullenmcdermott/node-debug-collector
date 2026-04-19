package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/siderolabs/talos/pkg/machinery/api/common"
	machinepb "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	sigyaml "sigs.k8s.io/yaml"
)

// talosCollector uses the Omni client's authenticated gRPC connection to
// access the Talos Machine API via the Omni proxy. No separate PGP key
// management is required — the Omni service account handles auth.
type talosCollector struct {
	omni    *omniCollector
	cluster string
	peers   []string
	log     *slog.Logger
}

// machineClient returns a MachineServiceClient routed to node via the Omni
// proxy using the existing service account credentials. The returned closeConn
// func must be called when the caller is done with all RPCs.
func (t *talosCollector) machineClient(ctx context.Context, node string) (machinepb.MachineServiceClient, func(), error) {
	c, err := t.omni.newClient(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	return c.Talos().WithCluster(t.cluster).WithNodes(node), func() { c.Close() }, nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func protoToYAML(m proto.Message) ([]byte, error) {
	jsonBytes, err := (protojson.MarshalOptions{Multiline: true, Indent: "  "}).Marshal(m)
	if err != nil {
		return nil, err
	}
	return sigyaml.JSONToYAML(jsonBytes)
}

// drainStream collects payload bytes from a gRPC stream that yields
// *common.Data messages (Dmesg, Logs, Read). Node errors surfaced via
// stream metadata are recorded but do not abort the drain.
func drainStream[T interface {
	Recv() (*common.Data, error)
}](stream T) ([]byte, error) {
	var buf []byte
	var firstErr error
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		if resp.Metadata != nil && resp.Metadata.Error != "" && firstErr == nil {
			firstErr = fmt.Errorf("node %s: %s", resp.Metadata.Hostname, resp.Metadata.Error)
		}
		buf = append(buf, resp.Bytes...) // partial data on non-EOF error is intentional: something is better than nothing
	}
	return buf, firstErr
}

func (t *talosCollector) collectDmesg(ctx context.Context, node, dir string) error {
	mc, closeConn, err := t.machineClient(ctx, node)
	if err != nil {
		return err
	}
	defer closeConn()

	stream, err := mc.Dmesg(ctx, &machinepb.DmesgRequest{Follow: false, Tail: true})
	if err != nil {
		return err
	}
	data, drainErr := drainStream(stream)
	if werr := writeFile(filepath.Join(dir, "talos", "dmesg.txt"), data); werr != nil {
		return werr
	}
	return drainErr
}

func (t *talosCollector) collectKmsg(ctx context.Context, node, dir string) error {
	mc, closeConn, err := t.machineClient(ctx, node)
	if err != nil {
		return err
	}
	defer closeConn()

	stream, err := mc.Read(ctx, &machinepb.ReadRequest{Path: "/dev/kmsg"})
	if err != nil {
		return err
	}
	data, readErr := drainStream(stream)
	if werr := writeFile(filepath.Join(dir, "talos", "kmsg.txt"), data); werr != nil {
		return werr
	}
	return readErr
}

func (t *talosCollector) collectJournals(ctx context.Context, node, dir string) error {
	mc, closeConn, err := t.machineClient(ctx, node)
	if err != nil {
		return err
	}
	defer closeConn()

	services := []string{"kubelet", "containerd", "machined", "apid", "trustd"}
	var firstErr error
	for _, svc := range services {
		stream, lerr := mc.Logs(ctx, &machinepb.LogsRequest{
			Namespace: "system",
			Driver:    common.ContainerDriver_CONTAINERD,
			Id:        svc,
			Follow:    false,
			TailLines: -1,
		})
		if lerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("logs %s: %w", svc, lerr)
			}
			continue
		}
		data, drainErr := drainStream(stream)
		path := filepath.Join(dir, "talos", fmt.Sprintf("journal-%s.txt", svc))
		if werr := writeFile(path, data); werr != nil && firstErr == nil {
			firstErr = werr
		}
		if drainErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("logs %s: %w", svc, drainErr)
		}
	}
	return firstErr
}

func (t *talosCollector) collectMachineInfo(ctx context.Context, node, dir string) error {
	mc, closeConn, err := t.machineClient(ctx, node)
	if err != nil {
		return err
	}
	defer closeConn()

	type item struct {
		file string
		get  func() (proto.Message, error)
	}
	items := []item{
		{"version.yaml", func() (proto.Message, error) { return mc.Version(ctx, &emptypb.Empty{}) }},
		{"diskstats.yaml", func() (proto.Message, error) { return mc.DiskStats(ctx, &emptypb.Empty{}) }},
		{"mounts.yaml", func() (proto.Message, error) { return mc.Mounts(ctx, &emptypb.Empty{}) }},
		{"processes.yaml", func() (proto.Message, error) { return mc.Processes(ctx, &emptypb.Empty{}) }},
		{"memory.yaml", func() (proto.Message, error) { return mc.Memory(ctx, &emptypb.Empty{}) }},
	}

	var firstErr error
	for _, it := range items {
		resp, cerr := it.get()
		if cerr != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", it.file, cerr)
		}
		if resp == nil {
			continue
		}
		y, merr := protoToYAML(resp)
		if merr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s marshal: %w", it.file, merr)
			}
			continue
		}
		if werr := writeFile(filepath.Join(dir, "talos", it.file), y); werr != nil && firstErr == nil {
			firstErr = werr
		}
	}
	return firstErr
}

// collectPeerDmesg fetches dmesg from each healthy peer node listed in
// t.peers. Each peer gets its own Omni client connection.
func (t *talosCollector) collectPeerDmesg(ctx context.Context, deadNode, dir string) error {
	if len(t.peers) == 0 {
		t.log.Debug("TALOS_PEERS not set, skipping peer dmesg")
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

func (t *talosCollector) collectOnePeerDmesg(ctx context.Context, peer, dir string) error {
	mc, closeConn, err := t.machineClient(ctx, peer)
	if err != nil {
		return err
	}
	defer closeConn()

	stream, err := mc.Dmesg(ctx, &machinepb.DmesgRequest{Follow: false, Tail: true})
	if err != nil {
		return err
	}
	data, drainErr := drainStream(stream)
	path := filepath.Join(dir, "talos", fmt.Sprintf("dmesg-peer-%s.txt", peer))
	if werr := writeFile(path, data); werr != nil {
		return werr
	}
	return drainErr
}
