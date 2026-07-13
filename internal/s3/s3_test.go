package s3

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewS3Proxy(t *testing.T) {
	config := S3Config{
		Endpoint:    "https://s3.amazonaws.com",
		Region:      "us-west-2",
		Bucket:      "test-bucket",
		AccessKeyID: "test-key",
		SecretKey:   "test-secret",
	}

	proxy := NewS3Proxy(config)

	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.client)
	assert.Equal(t, "test-bucket", proxy.bucket)
}

func TestNewS3Proxy_DefaultRegion(t *testing.T) {
	config := S3Config{
		Endpoint:    "https://s3.amazonaws.com",
		Bucket:      "test-bucket",
		AccessKeyID: "test-key",
		SecretKey:   "test-secret",
	}

	proxy := NewS3Proxy(config)

	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.client)
}

func TestS3Proxy_ServeHTTP_InvalidMethods(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}

	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test-object", nil)
			rr := httptest.NewRecorder()

			proxy.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Contains(t, rr.Body.String(), "Method not allowed")
		})
	}
}

func TestS3Proxy_ServeHTTP_EmptyObjectKey(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Object key is required")
}

func TestConditionalHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/file.bin", nil)
	req.Header.Set("Range", "bytes=100-199")
	req.Header.Set("If-None-Match", `"abc123"`)
	req.Header.Set("If-Modified-Since", "Mon, 02 Jan 2006 15:04:05 GMT")

	rng, ifNoneMatch, ifModifiedSince := conditionalHeaders(req)

	require.NotNil(t, rng)
	assert.Equal(t, "bytes=100-199", *rng)
	require.NotNil(t, ifNoneMatch)
	assert.Equal(t, `"abc123"`, *ifNoneMatch)
	require.NotNil(t, ifModifiedSince)
	assert.Equal(t, time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC), ifModifiedSince.UTC())
}

func TestConditionalHeaders_Absent(t *testing.T) {
	req := httptest.NewRequest("GET", "/file.bin", nil)

	rng, ifNoneMatch, ifModifiedSince := conditionalHeaders(req)

	assert.Nil(t, rng)
	assert.Nil(t, ifNoneMatch)
	assert.Nil(t, ifModifiedSince)
}

func TestConditionalHeaders_InvalidIfModifiedSince(t *testing.T) {
	req := httptest.NewRequest("GET", "/file.bin", nil)
	req.Header.Set("If-Modified-Since", "not-a-date")

	_, _, ifModifiedSince := conditionalHeaders(req)

	assert.Nil(t, ifModifiedSince)
}

func s3ResponseError(statusCode int) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: statusCode}},
			Err:      errors.New("s3 response error"),
		},
	}
}

func TestHandleS3Error_NotModified(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}
	rr := httptest.NewRecorder()

	proxy.handleS3Error(rr, s3ResponseError(http.StatusNotModified))

	assert.Equal(t, http.StatusNotModified, rr.Code)
	assert.Empty(t, rr.Body.String())
}

func TestHandleS3Error_RangeNotSatisfiable(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}
	rr := httptest.NewRecorder()

	proxy.handleS3Error(rr, s3ResponseError(http.StatusRequestedRangeNotSatisfiable))

	assert.Equal(t, http.StatusRequestedRangeNotSatisfiable, rr.Code)
}

func TestHandleS3Error_GenericServerError(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}
	rr := httptest.NewRecorder()

	proxy.handleS3Error(rr, s3ResponseError(http.StatusForbidden))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestNewS3HealthChecker(t *testing.T) {
	proxy := &S3Proxy{bucket: "test"}
	checker := NewS3HealthChecker(proxy)

	assert.NotNil(t, checker)
	assert.Equal(t, proxy, checker.s3Proxy)
}

func TestS3HealthChecker_CheckHealth_WithoutRealS3(t *testing.T) {
	config := S3Config{
		Endpoint:    "https://nonexistent-bucket.s3.amazonaws.com",
		Region:      "us-east-1",
		Bucket:      "nonexistent-bucket",
		AccessKeyID: "fake-key",
		SecretKey:   "fake-secret",
	}
	proxy := NewS3Proxy(config)
	checker := NewS3HealthChecker(proxy)

	statusCode, body, err := checker.CheckHealth()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "S3 health check failed")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "unhealthy")
	assert.Contains(t, string(body), "S3 bucket access failed")
}
