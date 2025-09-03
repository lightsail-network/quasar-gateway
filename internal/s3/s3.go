package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Proxy struct {
	client *s3.Client
	bucket string
}

type S3Config struct {
	Endpoint    string
	Region      string
	Bucket      string
	AccessKeyID string
	SecretKey   string
}

func NewS3Proxy(config S3Config) *S3Proxy {
	// Set defaults
	if config.Region == "" {
		config.Region = "us-east-1"
	}

	// Create AWS config
	awsConfig := aws.Config{
		Region:      config.Region,
		Credentials: credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretKey, ""),
	}

	// Set custom endpoint if provided (for S3-compatible services like R2)
	if config.Endpoint != "" {
		awsConfig.BaseEndpoint = aws.String(config.Endpoint)
	}

	client := s3.NewFromConfig(awsConfig)

	return &S3Proxy{
		client: client,
		bucket: config.Bucket,
	}
}

func (sp *S3Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Only allow GET and HEAD methods
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract object key from path
	objectKey := strings.TrimPrefix(req.URL.Path, "/")

	if objectKey == "" {
		http.Error(w, "Object key is required", http.StatusBadRequest)
		return
	}

	ctx := req.Context()

	if req.Method == http.MethodHead {
		sp.handleHeadObject(w, ctx, objectKey)
	} else {
		sp.handleGetObject(w, ctx, objectKey)
	}
}

func (sp *S3Proxy) handleGetObject(w http.ResponseWriter, ctx context.Context, objectKey string) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(sp.bucket),
		Key:    aws.String(objectKey),
	}

	result, err := sp.client.GetObject(ctx, input)
	if err != nil {
		sp.handleS3Error(w, err)
		return
	}
	defer result.Body.Close()

	// Set response headers
	if result.ContentType != nil {
		w.Header().Set("Content-Type", *result.ContentType)
	}
	if result.ContentLength != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}
	if result.ETag != nil {
		w.Header().Set("ETag", *result.ETag)
	}
	if result.LastModified != nil {
		w.Header().Set("Last-Modified", result.LastModified.Format(http.TimeFormat))
	}
	if result.CacheControl != nil {
		w.Header().Set("Cache-Control", *result.CacheControl)
	}
	if result.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *result.ContentEncoding)
	}
	if result.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *result.ContentDisposition)
	}

	// Copy object data to response
	_, err = io.Copy(w, result.Body)
	if err != nil {
		// Log error but don't send response as headers are already written
		fmt.Printf("Error copying object data: %v\n", err)
	}
}

func (sp *S3Proxy) handleHeadObject(w http.ResponseWriter, ctx context.Context, objectKey string) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(sp.bucket),
		Key:    aws.String(objectKey),
	}

	result, err := sp.client.HeadObject(ctx, input)
	if err != nil {
		sp.handleS3Error(w, err)
		return
	}

	// Set response headers
	if result.ContentType != nil {
		w.Header().Set("Content-Type", *result.ContentType)
	}
	if result.ContentLength != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}
	if result.ETag != nil {
		w.Header().Set("ETag", *result.ETag)
	}
	if result.LastModified != nil {
		w.Header().Set("Last-Modified", result.LastModified.Format(http.TimeFormat))
	}
	if result.CacheControl != nil {
		w.Header().Set("Cache-Control", *result.CacheControl)
	}
	if result.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *result.ContentEncoding)
	}
	if result.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *result.ContentDisposition)
	}

	w.WriteHeader(http.StatusOK)
}

func (sp *S3Proxy) handleS3Error(w http.ResponseWriter, err error) {
	// Handle different S3 error types
	var noSuchKey *types.NoSuchKey
	var noSuchBucket *types.NoSuchBucket

	if errors.As(err, &noSuchKey) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if errors.As(err, &noSuchBucket) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Generic error
	fmt.Printf("S3 error: %v\n", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

// CheckHealth performs a health check by listing objects in the bucket (with limit 1)
func (sp *S3Proxy) CheckHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(sp.bucket),
		MaxKeys: aws.Int32(1),
	}

	_, err := sp.client.ListObjectsV2(ctx, input)
	return err
}
