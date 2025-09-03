package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
