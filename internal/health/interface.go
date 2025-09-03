package health

// HealthChecker interface defines the contract for health checking
type HealthChecker interface {
	CheckHealth() (int, []byte, error)
}
