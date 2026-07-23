package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPStatusChecker_Healthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("Expected path /health, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	checker := NewHTTPStatusChecker(server.URL, "/health")
	if err := checker.CheckHealth(context.Background()); err != nil {
		t.Errorf("Expected healthy, got error: %v", err)
	}
}

func TestHTTPStatusChecker_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error": "not in sync"}`))
	}))
	defer server.Close()

	checker := NewHTTPStatusChecker(server.URL, "/health")
	err := checker.CheckHealth(context.Background())
	if err == nil {
		t.Fatalf("Expected error for 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("Expected error to mention status 503, got: %v", err)
	}
}

func TestHTTPStatusChecker_Unreachable(t *testing.T) {
	// A closed server guarantees a connection error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	checker := NewHTTPStatusChecker(server.URL, "/health")
	err := checker.CheckHealth(context.Background())
	if err == nil {
		t.Fatalf("Expected error for unreachable backend")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("Expected unreachable error, got: %v", err)
	}
}

// Sloppy configuration must not produce broken URLs: trailing slash on the
// base and a missing leading slash on the path are both normalized.
func TestHTTPStatusChecker_URLNormalization(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewHTTPStatusChecker(server.URL+"/", "health")
	if err := checker.CheckHealth(context.Background()); err != nil {
		t.Errorf("Expected healthy, got error: %v", err)
	}
	if gotPath != "/health" {
		t.Errorf("Expected normalized path /health, got %s", gotPath)
	}
}
