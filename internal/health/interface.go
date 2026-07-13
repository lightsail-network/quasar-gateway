package health

import "context"

// HealthChecker reports whether the backend behind the gateway is healthy.
// Implementations return nil when healthy; the HTTP status code and response
// body are the gateway's responsibility.
type HealthChecker interface {
	CheckHealth(ctx context.Context) error
}
