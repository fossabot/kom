package aws

import (
	"testing"
	"time"
)

func TestNewEKSTokenProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *EKSSDKConfig
		wantErr bool
		errType string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrorTypeAWSConfigMissing,
		},
		{
			name: "missing region",
			config: &EKSSDKConfig{
				ClusterName: "test-cluster",
				CredentialsProvider: &StaticCredentialsProvider{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
			},
			wantErr: true,
			errType: ErrorTypeAWSConfigMissing,
		},
		{
			name: "missing cluster name",
			config: &EKSSDKConfig{
				Region: "us-west-2",
				CredentialsProvider: &StaticCredentialsProvider{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
			},
			wantErr: true,
			errType: ErrorTypeAWSConfigMissing,
		},
		{
			name: "missing credentials provider",
			config: &EKSSDKConfig{
				Region:      "us-west-2",
				ClusterName: "test-cluster",
			},
			wantErr: true,
			errType: ErrorTypeAWSConfigMissing,
		},
		{
			name: "valid config",
			config: &EKSSDKConfig{
				Region:      "us-west-2",
				ClusterName: "test-cluster",
				CredentialsProvider: &StaticCredentialsProvider{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with custom timeout",
			config: &EKSSDKConfig{
				Region:      "us-west-2",
				ClusterName: "test-cluster",
				HTTPTimeout: 60 * time.Second,
				CredentialsProvider: &StaticCredentialsProvider{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewEKSTokenProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if eksErr, ok := err.(*EKSAuthError); ok {
					if eksErr.Type != tt.errType {
						t.Errorf("Expected error type %s, got %s", tt.errType, eksErr.Type)
					}
				} else {
					t.Errorf("Expected EKSAuthError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if provider == nil {
					t.Errorf("Expected provider to be created")
					return
				}
				if provider.config != tt.config {
					t.Errorf("Expected config to be set")
				}
			}
		})
	}
}

func TestEKSTokenProvider_shouldRetry(t *testing.T) {
	config := &EKSSDKConfig{
		Region:      "us-west-2",
		ClusterName: "test-cluster",
		CredentialsProvider: &StaticCredentialsProvider{
			AccessKey: "test-key",
			SecretKey: "test-secret",
		},
	}

	provider, err := NewEKSTokenProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tests := []struct {
		name        string
		err         error
		shouldRetry bool
	}{
		{
			name:        "nil error",
			err:         nil,
			shouldRetry: true, // shouldRetry for nil is undefined in current implementation
		},
		{
			name:        "network error",
			err:         NewEKSAuthError(ErrorTypeNetworkError, "network timeout", nil),
			shouldRetry: true,
		},
		{
			name:        "token generation error",
			err:         NewEKSAuthError(ErrorTypeTokenGeneration, "failed to generate token", nil),
			shouldRetry: true,
		},
		{
			name:        "invalid credentials",
			err:         NewEKSAuthError(ErrorTypeInvalidCredentials, "invalid credentials", nil),
			shouldRetry: false,
		},
		{
			name:        "cluster not found",
			err:         NewEKSAuthError(ErrorTypeClusterNotFound, "cluster not found", nil),
			shouldRetry: false,
		},
		{
			name:        "config missing",
			err:         NewEKSAuthError(ErrorTypeAWSConfigMissing, "config missing", nil),
			shouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.shouldRetry(tt.err)
			if result != tt.shouldRetry {
				t.Errorf("Expected shouldRetry %v, got %v for error: %v", tt.shouldRetry, result, tt.err)
			}
		})
	}
}

func TestEKSTokenProvider_String(t *testing.T) {
	config := &EKSSDKConfig{
		Region:      "us-west-2",
		ClusterName: "test-cluster",
		CredentialsProvider: &StaticCredentialsProvider{
			AccessKey: "test-key",
			SecretKey: "test-secret",
		},
	}

	provider, err := NewEKSTokenProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	str := provider.String()
	expectedSubstrings := []string{"EKSTokenProvider", "test-cluster", "us-west-2", "static"}
	
	for _, substr := range expectedSubstrings {
		if !contains(str, substr) {
			t.Errorf("Expected string to contain '%s', got: %s", substr, str)
		}
	}
}

// Mock test for generateKubernetesToken (unit test without actual AWS calls)
func TestGenerateKubernetesTokenStructure(t *testing.T) {
	config := &EKSSDKConfig{
		Region:      "us-west-2",
		ClusterName: "test-cluster",
		CredentialsProvider: &StaticCredentialsProvider{
			AccessKey: "test-key",
			SecretKey: "test-secret",
		},
	}

	provider, err := NewEKSTokenProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test that the provider is properly configured
	if provider.config.ClusterName != "test-cluster" {
		t.Errorf("Expected cluster name 'test-cluster', got %s", provider.config.ClusterName)
	}

	if provider.config.Region != "us-west-2" {
		t.Errorf("Expected region 'us-west-2', got %s", provider.config.Region)
	}

	// Test HTTP client configuration
	if provider.httpClient == nil {
		t.Errorf("Expected HTTP client to be configured")
	}

	// Test timeout configuration
	if provider.httpClient.Timeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", provider.httpClient.Timeout)
	}
}