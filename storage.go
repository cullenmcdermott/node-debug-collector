package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Storage wraps an S3 client + pre-bound bucket for archive uploads.
type S3Storage struct {
	Client   *s3.Client
	Uploader *manager.Uploader
	Bucket   string
}

// newS3Storage builds an S3 client against the Ceph RGW endpoint advertised by
// the ObjectBucketClaim. It expects these env vars (set via envFrom on the OBC
// ConfigMap + Secret): BUCKET_HOST, BUCKET_PORT, BUCKET_NAME, BUCKET_REGION,
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
func newS3Storage(ctx context.Context) (*S3Storage, error) {
	host := os.Getenv("BUCKET_HOST")
	if host == "" {
		return nil, fmt.Errorf("BUCKET_HOST not set (ObjectBucketClaim ConfigMap not mounted?)")
	}
	port := envOr("BUCKET_PORT", "80")
	bucket := os.Getenv("BUCKET_NAME")
	if bucket == "" {
		return nil, fmt.Errorf("BUCKET_NAME not set")
	}
	region := envOr("BUCKET_REGION", "us-east-1")

	scheme := "http"
	if port == "443" {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s:%s", scheme, host, port)

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithHTTPClient(&http.Client{Timeout: 5 * time.Minute}),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // Ceph RGW requires path-style addressing.
	})

	return &S3Storage{
		Client:   client,
		Uploader: manager.NewUploader(client),
		Bucket:   bucket,
	}, nil
}
