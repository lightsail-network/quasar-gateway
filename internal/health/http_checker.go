package health

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPStatusChecker probes a plain-HTTP backend by GETting a health path and
// treating any 2xx response as healthy. Backends following the common health
// endpoint convention (e.g. wallet-backend) encode deep health — including
// data freshness — in the status code, so the body is never parsed.
type HTTPStatusChecker struct {
	healthURL  string
	httpClient *http.Client
}

func NewHTTPStatusChecker(baseURL, path string) *HTTPStatusChecker {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &HTTPStatusChecker{
		healthURL: strings.TrimSuffix(baseURL, "/") + path,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (h *HTTPStatusChecker) CheckHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("backend unreachable: %v", err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the underlying connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("backend health endpoint returned status: %d", resp.StatusCode)
	}
	return nil
}
