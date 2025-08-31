package aws

import (
	"context"
	"testing"
	"time"
)

func TestStaticCredentialsProvider(t *testing.T) {
	tests := []struct {
		name        string
		provider    *StaticCredentialsProvider
		wantErr     bool
		errType     string
	}{
		{
			name: "valid static credentials",
			provider: &StaticCredentialsProvider{
				AccessKey: "test-access-key",
				SecretKey: "test-secret-key",
			},
			wantErr: false,
		},
		{
			name: "valid static credentials with session token",
			provider: &StaticCredentialsProvider{
				AccessKey:    "test-access-key",
				SecretKey:    "test-secret-key",
				SessionToken: "test-session-token",
			},
			wantErr: false,
		},
		{
			name: "missing access key",
			provider: &StaticCredentialsProvider{
				SecretKey: "test-secret-key",
			},
			wantErr: true,
			errType: ErrorTypeInvalidCredentials,
		},
		{
			name: "missing secret key",
			provider: &StaticCredentialsProvider{
				AccessKey: "test-access-key",
			},
			wantErr: true,
			errType: ErrorTypeInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			creds, err := tt.provider.Retrieve(ctx)

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
				if creds.AccessKeyID != tt.provider.AccessKey {
					t.Errorf("Expected access key %s, got %s", tt.provider.AccessKey, creds.AccessKeyID)
				}
				if creds.SecretAccessKey != tt.provider.SecretKey {
					t.Errorf("Expected secret key %s, got %s", tt.provider.SecretKey, creds.SecretAccessKey)
				}
				if creds.SessionToken != tt.provider.SessionToken {
					t.Errorf("Expected session token %s, got %s", tt.provider.SessionToken, creds.SessionToken)
				}
			}
		})
	}
}

func TestProfileCredentialsProvider(t *testing.T) {
	provider := &ProfileCredentialsProvider{
		Profile: "default",
	}

	if provider.GetProviderType() != "profile" {
		t.Errorf("Expected provider type 'profile', got %s", provider.GetProviderType())
	}
}

func TestIAMRoleCredentialsProvider(t *testing.T) {
	baseProvider := &StaticCredentialsProvider{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
	}

	tests := []struct {
		name     string
		provider *IAMRoleCredentialsProvider
		wantErr  bool
		errType  string
	}{
		{
			name: "missing role ARN",
			provider: &IAMRoleCredentialsProvider{
				BaseProvider: baseProvider,
			},
			wantErr: true,
			errType: ErrorTypeInvalidCredentials,
		},
		{
			name: "missing base provider",
			provider: &IAMRoleCredentialsProvider{
				RoleARN: "arn:aws:iam::123456789012:role/test-role",
			},
			wantErr: true,
			errType: ErrorTypeInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := tt.provider.Retrieve(ctx)

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
			}
		})
	}
}

func TestNewStaticCredentialsProvider(t *testing.T) {
	accessKey := "test-access-key"
	secretKey := "test-secret-key"
	sessionToken := "test-session-token"

	provider := NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)

	if provider.AccessKey != accessKey {
		t.Errorf("Expected access key %s, got %s", accessKey, provider.AccessKey)
	}
	if provider.SecretKey != secretKey {
		t.Errorf("Expected secret key %s, got %s", secretKey, provider.SecretKey)
	}
	if provider.SessionToken != sessionToken {
		t.Errorf("Expected session token %s, got %s", sessionToken, provider.SessionToken)
	}
}

func TestNewProfileCredentialsProvider(t *testing.T) {
	profile := "test-profile"
	provider := NewProfileCredentialsProvider(profile)

	if provider.Profile != profile {
		t.Errorf("Expected profile %s, got %s", profile, provider.Profile)
	}
}

func TestNewIAMRoleCredentialsProvider(t *testing.T) {
	roleArn := "arn:aws:iam::123456789012:role/test-role"
	sessionName := "test-session"
	baseProvider := &StaticCredentialsProvider{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
	}

	provider := NewIAMRoleCredentialsProvider(roleArn, sessionName, baseProvider)

	if provider.RoleARN != roleArn {
		t.Errorf("Expected role ARN %s, got %s", roleArn, provider.RoleARN)
	}
	if provider.SessionName != sessionName {
		t.Errorf("Expected session name %s, got %s", sessionName, provider.SessionName)
	}
	if provider.BaseProvider != baseProvider {
		t.Errorf("Expected base provider to be set")
	}
	if provider.Duration != time.Hour {
		t.Errorf("Expected duration 1 hour, got %v", provider.Duration)
	}
}