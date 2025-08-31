package aws

import (
	"context"
	"testing"
	"time"
)

func TestNewTokenManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *EKSAuthConfig
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
			name: "config with basic AWS credentials",
			config: &EKSAuthConfig{
				AccessKey:       "test-key",
				SecretAccessKey: "test-secret",
				ClusterName:     "test-cluster",
				Region:          "us-west-2",
				TokenCache:      &TokenCache{},
			},
			wantErr: false,
		},
		{
			name: "config with existing SDK config",
			config: &EKSAuthConfig{
				ClusterName: "test-cluster",
				Region:      "us-west-2",
				TokenCache:  &TokenCache{},
				SDKConfig: &EKSSDKConfig{
					Region:      "us-west-2",
					ClusterName: "test-cluster",
					CredentialsProvider: &StaticCredentialsProvider{
						AccessKey: "test-key",
						SecretKey: "test-secret",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := NewTokenManager(tt.config)

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
				if tm == nil {
					t.Errorf("Expected TokenManager to be created")
					return
				}
			}
		})
	}
}

func TestTokenManager_IsUsingSDK(t *testing.T) {
	// Test SDK mode
	sdkConfig := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(sdkConfig)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	if !tm.IsUsingSDK() {
		t.Errorf("Expected TokenManager to be using SDK mode")
	}
}

func TestTokenManager_GetProviderInfo(t *testing.T) {
	config := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	info := tm.GetProviderInfo()
	if info == "None" {
		t.Errorf("Expected provider info to be set, got 'None'")
	}

	expectedSubstrings := []string{"SDK"}
	for _, substr := range expectedSubstrings {
		if !contains(info, substr) {
			t.Errorf("Expected provider info to contain '%s', got: %s", substr, info)
		}
	}
}

func TestTokenManager_GetTokenInfo(t *testing.T) {
	config := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	// Test with empty cache
	token, expiresAt, valid := tm.GetTokenInfo()
	if token != "" {
		t.Errorf("Expected empty token, got %s", token)
	}
	if !expiresAt.IsZero() {
		t.Errorf("Expected zero expiration time, got %v", expiresAt)
	}
	if valid {
		t.Errorf("Expected token to be invalid")
	}

	// Test with valid token in cache
	testToken := "test-token"
	testExpiry := time.Now().Add(1 * time.Hour)
	tm.eksConfig.TokenCache.SetToken(testToken, testExpiry)

	token, expiresAt, valid = tm.GetTokenInfo()
	if token != testToken {
		t.Errorf("Expected token %s, got %s", testToken, token)
	}
	if !expiresAt.Equal(testExpiry) {
		t.Errorf("Expected expiry %v, got %v", testExpiry, expiresAt)
	}
	if !valid {
		t.Errorf("Expected token to be valid")
	}
}

func TestTokenManager_ClearCache(t *testing.T) {
	config := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	// Set a token in cache
	testToken := "test-token"
	testExpiry := time.Now().Add(1 * time.Hour)
	tm.eksConfig.TokenCache.SetToken(testToken, testExpiry)

	// Verify token is set
	if !tm.eksConfig.TokenCache.IsValid() {
		t.Errorf("Expected token to be valid before clearing")
	}

	// Clear cache
	tm.ClearCache()

	// Verify token is cleared
	if tm.eksConfig.TokenCache.IsValid() {
		t.Errorf("Expected token to be invalid after clearing")
	}

	token, _ := tm.eksConfig.TokenCache.GetToken()
	if token != "" {
		t.Errorf("Expected empty token after clearing, got %s", token)
	}
}

func TestTokenManager_TriggerRefresh(t *testing.T) {
	config := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	// This should not panic
	tm.TriggerRefresh()

	// Multiple calls should not block
	tm.TriggerRefresh()
	tm.TriggerRefresh()
}

func TestTokenManager_Stop(t *testing.T) {
	config := &EKSAuthConfig{
		AccessKey:       "test-key",
		SecretAccessKey: "test-secret",
		ClusterName:     "test-cluster",
		Region:          "us-west-2",
		TokenCache:      &TokenCache{},
	}

	tm, err := NewTokenManager(config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	// Start auto refresh
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm.StartAutoRefresh(ctx)

	// This should not panic
	tm.Stop()
}