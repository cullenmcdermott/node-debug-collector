package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/state"
	omniclient "github.com/siderolabs/omni/client/pkg/client"
	omnires "github.com/siderolabs/omni/client/pkg/omni/resources"
	omniresomni "github.com/siderolabs/omni/client/pkg/omni/resources/omni"
	"gopkg.in/yaml.v3"
)

// omniCollector uses the Omni Go client (service-account auth) to dump the
// COSI resources that correlate a k8s node name with the underlying machine
// UUID, cluster membership, and recovery status.
type omniCollector struct {
	endpoint string
	saKey    string
	log      *slog.Logger
}

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

func (o *omniCollector) newClient(ctx context.Context) (*omniclient.Client, error) {
	if o.endpoint == "" {
		return nil, fmt.Errorf("OMNI_ENDPOINT not set")
	}
	return omniclient.New(o.endpoint, omniclient.WithServiceAccount(o.saKey))
}

// listToYAML lists resources of the given type and marshals the whole list to
// a multi-document YAML stream. Returns the bytes and the first error.
func listToYAML(ctx context.Context, st state.State, resType resource.Type) ([]byte, error) {
	list, err := st.List(ctx, resource.NewMetadata(omnires.DefaultNamespace, resType, "", resource.VersionUndefined))
	if err != nil {
		return nil, err
	}
	var buf []byte
	for _, r := range list.Items {
		doc, merr := resource.MarshalYAML(r)
		if merr != nil {
			return buf, merr
		}
		out, yerr := yaml.Marshal(doc)
		if yerr != nil {
			return buf, yerr
		}
		buf = append(buf, []byte("---\n")...)
		buf = append(buf, out...)
	}
	return buf, nil
}

func (o *omniCollector) dumpResource(ctx context.Context, resType resource.Type, outPath string) error {
	c, err := o.newClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	data, listErr := listToYAML(ctx, c.Omni().State(), resType)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return errors.Join(err, listErr)
	}
	if werr := os.WriteFile(outPath, data, 0o644); werr != nil {
		return errors.Join(werr, listErr)
	}
	return listErr
}

// collectMachineState dumps all ClusterMachine resources (cluster-wide, not filtered to one node).
func (o *omniCollector) collectMachineState(ctx context.Context, dir string) error {
	return o.dumpResource(ctx, omniresomni.ClusterMachineType, filepath.Join(dir, "omni", "cluster-machines.yaml"))
}

// collectMachineStatusResources captures cluster-machine and machine status
// COSI resources (cluster-wide, not filtered to one node). This is NOT real
// machine log collection — that would require the Omni Management API (machine-logs RPC).
func (o *omniCollector) collectMachineStatusResources(ctx context.Context, dir string) error {
	c, err := o.newClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	st := c.Omni().State()

	items := []struct {
		file    string
		resType resource.Type
	}{
		{"cluster-machine-status.yaml", omniresomni.ClusterMachineStatusType},
	}

	var firstErr error
	for _, it := range items {
		data, listErr := listToYAML(ctx, st, it.resType)
		path := filepath.Join(dir, "omni", it.file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if werr := os.WriteFile(path, data, 0o644); werr != nil && firstErr == nil {
			firstErr = werr
		}
		if listErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", it.file, listErr)
		}
	}
	return firstErr
}

// collectPostRecoveryStatus dumps all MachineStatus resources (cluster-wide, not filtered to one node).
func (o *omniCollector) collectPostRecoveryStatus(ctx context.Context, dir string) error {
	return o.dumpResource(ctx, omniresomni.MachineStatusType, filepath.Join(dir, "omni", "post-recovery-machine-status.yaml"))
}
