package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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

	writeObjectHeaders(w.Header(), objectHeaders{
		contentType:        result.ContentType,
		contentLength:      result.ContentLength,
		etag:               result.ETag,
		lastModified:       result.LastModified,
		cacheControl:       result.CacheControl,
		contentEncoding:    result.ContentEncoding,
		contentDisposition: result.ContentDisposition,
	})

	// Copy object data to response
	if _, err := io.Copy(w, result.Body); err != nil {
		// Log error but don't send response as headers are already written
		log.Printf("Error copying object data: %v", err)
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

	writeObjectHeaders(w.Header(), objectHeaders{
		contentType:        result.ContentType,
		contentLength:      result.ContentLength,
		etag:               result.ETag,
		lastModified:       result.LastModified,
		cacheControl:       result.CacheControl,
		contentEncoding:    result.ContentEncoding,
		contentDisposition: result.ContentDisposition,
	})

	w.WriteHeader(http.StatusOK)
}

// objectHeaders carries the object metadata shared by GetObject and
// HeadObject responses.
type objectHeaders struct {
	contentType        *string
	contentLength      *int64
	etag               *string
	lastModified       *time.Time
	cacheControl       *string
	contentEncoding    *string
	contentDisposition *string
}

func writeObjectHeaders(h http.Header, o objectHeaders) {
	if o.contentType != nil {
		h.Set("Content-Type", *o.contentType)
	}
	if o.contentLength != nil {
		h.Set("Content-Length", fmt.Sprintf("%d", *o.contentLength))
	}
	if o.etag != nil {
		h.Set("ETag", *o.etag)
	}
	if o.lastModified != nil {
		h.Set("Last-Modified", o.lastModified.Format(http.TimeFormat))
	}
	if o.cacheControl != nil {
		h.Set("Cache-Control", *o.cacheControl)
	}
	if o.contentEncoding != nil {
		h.Set("Content-Encoding", *o.contentEncoding)
	}
	if o.contentDisposition != nil {
		h.Set("Content-Disposition", *o.contentDisposition)
	}
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
	log.Printf("S3 error: %v", err)
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
