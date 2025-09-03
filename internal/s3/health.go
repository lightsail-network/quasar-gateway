package s3

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// S3HealthChecker implements health checking for S3 backend
type S3HealthChecker struct {
	s3Proxy *S3Proxy
}

func NewS3HealthChecker(s3Proxy *S3Proxy) *S3HealthChecker {
	return &S3HealthChecker{
		s3Proxy: s3Proxy,
	}
}

func (h *S3HealthChecker) CheckHealth() (int, []byte, error) {
	err := h.s3Proxy.CheckHealth()

	if err != nil {
		response := map[string]string{
			"status": "unhealthy",
			"reason": "S3 bucket access failed",
		}
		body, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			return http.StatusServiceUnavailable, []byte(`{"status":"unhealthy","reason":"failed to marshal response"}`), fmt.Errorf("S3 health check failed: %v", err)
		}
		return http.StatusServiceUnavailable, body, fmt.Errorf("S3 health check failed: %v", err)
	}

	// S3 is healthy
	response := map[string]string{"status": "healthy"}
	body, err := json.Marshal(response)
	if err != nil {
		return http.StatusServiceUnavailable, []byte(`{"status":"unhealthy","reason":"failed to marshal response"}`), fmt.Errorf("failed to marshal healthy response: %v", err)
	}

	return http.StatusOK, body, nil
}
