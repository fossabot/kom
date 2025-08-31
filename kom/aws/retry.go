package aws

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"k8s.io/klog/v2"
)

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries"`
	InitialInterval time.Duration `json:"initial_interval"`
	MaxInterval     time.Duration `json:"max_interval"`
	Multiplier      float64       `json:"multiplier"`
	Jitter          bool          `json:"jitter"`
}

// DefaultRetryConfig 默认重试配置
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:      3,
		InitialInterval: time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
	}
}

// ExponentialBackoff 指数退避重试器
type ExponentialBackoff struct {
	config  *RetryConfig
	attempt int
}

// NewExponentialBackoff 创建指数退避重试器
func NewExponentialBackoff(config *RetryConfig) *ExponentialBackoff {
	if config == nil {
		config = DefaultRetryConfig()
	}
	return &ExponentialBackoff{
		config:  config,
		attempt: 0,
	}
}

// NextBackoff 计算下一次重试的等待时间
func (eb *ExponentialBackoff) NextBackoff() time.Duration {
	if eb.attempt >= eb.config.MaxRetries {
		return 0
	}

	// 计算基础间隔
	interval := time.Duration(float64(eb.config.InitialInterval) * math.Pow(eb.config.Multiplier, float64(eb.attempt)))
	
	// 限制最大间隔
	if interval > eb.config.MaxInterval {
		interval = eb.config.MaxInterval
	}

	// 添加抖动
	if eb.config.Jitter {
		jitter := time.Duration(rand.Float64() * float64(interval) * 0.1)
		interval += jitter
	}

	eb.attempt++
	return interval
}

// Reset 重置重试计数器
func (eb *ExponentialBackoff) Reset() {
	eb.attempt = 0
}

// ShouldRetry 检查是否应该重试
func (eb *ExponentialBackoff) ShouldRetry() bool {
	return eb.attempt < eb.config.MaxRetries
}

// RetryableOperation 可重试的操作函数类型
type RetryableOperation func(ctx context.Context, attempt int) error

// RetryWithBackoff 使用指数退避执行重试操作
func RetryWithBackoff(ctx context.Context, config *RetryConfig, operation RetryableOperation) error {
	backoff := NewExponentialBackoff(config)
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// 计算等待时间
			waitTime := backoff.NextBackoff()
			if waitTime == 0 {
				break
			}

			klog.V(3).Infof("Retrying operation, attempt %d/%d, waiting %v", 
				attempt+1, config.MaxRetries+1, waitTime)

			// 等待或检查上下文取消
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
			}
		}

		// 执行操作
		err := operation(ctx, attempt)
		if err == nil {
			if attempt > 0 {
				klog.V(2).Infof("Operation succeeded after %d retries", attempt)
			}
			return nil
		}

		lastErr = err

		// 检查是否应该重试
		if !ShouldRetryError(err) {
			klog.V(3).Infof("Error is not retryable, stopping: %v", err)
			break
		}

		klog.V(3).Infof("Operation failed (attempt %d/%d): %v", 
			attempt+1, config.MaxRetries+1, err)
	}

	return fmt.Errorf("operation failed after %d retries: %w", config.MaxRetries+1, lastErr)
}

// ShouldRetryError 判断错误是否应该重试
func ShouldRetryError(err error) bool {
	if err == nil {
		return false
	}

	// 检查EKS认证错误类型
	if eksErr, ok := err.(*EKSAuthError); ok {
		switch eksErr.Type {
		case ErrorTypeNetworkError:
			return true
		case ErrorTypeTokenGeneration:
			return true
		case ErrorTypeSDKInitialization:
			return true
		case ErrorTypeCredentialsProvider:
			return true
		// 不重试的错误类型
		case ErrorTypeInvalidCredentials:
			return false
		case ErrorTypeClusterNotFound:
			return false
		case ErrorTypePermissionDenied:
			return false
		case ErrorTypeAWSConfigMissing:
			return false
		default:
			// 默认重试未知错误
			return true
		}
	}

	// 检查常见的网络错误
	errStr := err.Error()
	networkErrors := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"service unavailable",
		"too many requests",
		"rate limit",
	}

	for _, netErr := range networkErrors {
		if contains(errStr, netErr) {
			return true
		}
	}

	// 默认不重试
	return false
}

// contains 检查字符串是否包含子字符串（忽略大小写）
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    len(s) > len(substr) && 
		    (s[:len(substr)] == substr || 
		     s[len(s)-len(substr):] == substr || 
		     containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ErrorClassifier 错误分类器
type ErrorClassifier struct{}

// ClassifyError 分类错误
func (ec *ErrorClassifier) ClassifyError(err error) (errorType string, retryable bool, severity string) {
	if err == nil {
		return "", false, ""
	}

	if eksErr, ok := err.(*EKSAuthError); ok {
		return eksErr.Type, ShouldRetryError(err), ec.getSeverity(eksErr.Type)
	}

	// 分类其他类型的错误
	errStr := err.Error()
	
	if contains(errStr, "timeout") || contains(errStr, "connection") {
		return ErrorTypeNetworkError, true, "warning"
	}
	
	if contains(errStr, "permission") || contains(errStr, "unauthorized") {
		return ErrorTypePermissionDenied, false, "error"
	}
	
	if contains(errStr, "not found") {
		return ErrorTypeClusterNotFound, false, "error"
	}

	return "unknown", true, "warning"
}

// getSeverity 获取错误严重程度
func (ec *ErrorClassifier) getSeverity(errorType string) string {
	switch errorType {
	case ErrorTypeInvalidCredentials, ErrorTypePermissionDenied, ErrorTypeClusterNotFound:
		return "error"
	case ErrorTypeAWSConfigMissing, ErrorTypeKubeconfigInvalid:
		return "error"
	case ErrorTypeNetworkError, ErrorTypeTokenGeneration:
		return "warning"
	default:
		return "info"
	}
}

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	maxFailures int
	resetTime   time.Duration
	failures    int
	lastFailure time.Time
	state       string // "closed", "open", "half-open"
}

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(maxFailures int, resetTime time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures: maxFailures,
		resetTime:   resetTime,
		state:       "closed",
	}
}

// Execute 执行操作（带熔断器保护）
func (cb *CircuitBreaker) Execute(operation func() error) error {
	// 检查熔断器状态
	if cb.state == "open" {
		if time.Since(cb.lastFailure) >= cb.resetTime {
			cb.state = "half-open"
			cb.failures = 0
		} else {
			return NewEKSAuthError(ErrorTypeNetworkError, 
				"circuit breaker is open", nil)
		}
	}

	// 执行操作
	err := operation()
	
	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		
		if cb.failures >= cb.maxFailures {
			cb.state = "open"
		}
		
		return err
	}

	// 成功执行，重置状态
	if cb.state == "half-open" {
		cb.state = "closed"
	}
	cb.failures = 0
	
	return nil
}

// Reset 重置熔断器
func (cb *CircuitBreaker) Reset() {
	cb.failures = 0
	cb.state = "closed"
}

// GetState 获取熔断器状态
func (cb *CircuitBreaker) GetState() string {
	return cb.state
}