// smoketest verifies that a service-account key can reach the Talos Machine
// API via the Omni proxy. Run it before deploying to confirm auth is working.
//
// Usage: go run ./cmd/smoketest <sa-key-file> <cluster> <node-hostname>
//
// The Omni endpoint is read from OMNI_ENDPOINT (required).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	omniclient "github.com/siderolabs/omni/client/pkg/client"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: go run ./cmd/smoketest <sa-key-file> <cluster> <node-hostname>")
	}
	endpoint := os.Getenv("OMNI_ENDPOINT")
	if endpoint == "" {
		log.Fatal("OMNI_ENDPOINT not set")
	}

	saKeyFile, cluster, node := os.Args[1], os.Args[2], os.Args[3]

	rawKey, err := os.ReadFile(saKeyFile)
	if err != nil {
		log.Fatalf("read sa key: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("==> connecting to %s...\n", endpoint)
	omni, err := omniclient.New(endpoint, omniclient.WithServiceAccount(string(rawKey)))
	if err != nil {
		log.Fatalf("omni client: %v", err)
	}
	defer omni.Close()

	fmt.Printf("==> getting Talos machine client for node %s via Omni proxy...\n", node)
	tc := omni.Talos().WithCluster(cluster).WithNodes(node)

	fmt.Println("==> calling Version()...")
	resp, err := tc.Version(ctx, &emptypb.Empty{})
	if err != nil {
		log.Fatalf("version: %v", err)
	}
	for _, m := range resp.Messages {
		fmt.Printf("    node=%s version=%s\n", m.Metadata.GetHostname(), m.Version.GetTag())
	}
	fmt.Println("==> OK")
}
