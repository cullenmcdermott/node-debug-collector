package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// tarGzUpload streams a tar+gzip of srcDir directly into an S3 object.
// The archive is never materialized on disk or fully in memory — io.Pipe
// connects the tar writer goroutine to the S3 uploader's multipart reader.
func tarGzUpload(ctx context.Context, srcDir string, uploader *manager.Uploader, bucket, key string) error {
	pr, pw := io.Pipe()
	defer pr.Close() // unblocks write goroutine if Upload returns early (e.g. context cancelled)

	go func() {
		gw := gzip.NewWriter(pw)
		tw := tar.NewWriter(gw)

		err := filepath.Walk(srcDir, func(path string, info os.FileInfo, werr error) error {
			if werr != nil {
				return werr
			}
			rel, rerr := filepath.Rel(srcDir, path)
			if rerr != nil {
				return rerr
			}
			if rel == "." {
				return nil
			}
			hdr, herr := tar.FileInfoHeader(info, "")
			if herr != nil {
				return herr
			}
			hdr.Name = strings.ReplaceAll(rel, string(os.PathSeparator), "/")
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			src, oerr := os.Open(path)
			if oerr != nil {
				return oerr
			}
			defer src.Close()
			if _, err := io.Copy(tw, src); err != nil {
				return fmt.Errorf("copy %s: %w", rel, err)
			}
			return nil
		})

		// Close tar and gzip writers to flush any buffered bytes before
		// signalling EOF on the pipe. Capture close errors so the uploader
		// sees them if the walk itself succeeded.
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if cerr := gw.Close(); cerr != nil && err == nil {
			err = cerr
		}
		pw.CloseWithError(err)
	}()

	_, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        pr,
		ContentType: aws.String("application/gzip"),
	})
	return err
}
