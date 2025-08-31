package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CredentialsProvider 凭证提供者接口
type CredentialsProvider interface {
	// Retrieve 获取AWS凭证
	Retrieve(ctx context.Context) (aws.Credentials, error)
	// GetProviderType 获取提供者类型
	GetProviderType() string
}

// StaticCredentialsProvider 静态凭证提供者
type StaticCredentialsProvider struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token,omitempty"`
}

// Retrieve 实现 CredentialsProvider 接口
func (scp *StaticCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if scp.AccessKey == "" || scp.SecretKey == "" {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypeInvalidCredentials, 
			"access key and secret key are required for static credentials", nil)
	}

	return aws.Credentials{
		AccessKeyID:     scp.AccessKey,
		SecretAccessKey: scp.SecretKey,
		SessionToken:    scp.SessionToken,
		Source:          "StaticCredentialsProvider",
	}, nil
}

// GetProviderType 返回提供者类型
func (scp *StaticCredentialsProvider) GetProviderType() string {
	return "static"
}

// ProfileCredentialsProvider Profile凭证提供者
type ProfileCredentialsProvider struct {
	Profile string `json:"profile"`
}

// Retrieve 实现 CredentialsProvider 接口
func (pcp *ProfileCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	profile := pcp.Profile
	if profile == "" {
		profile = "default"
	}

	// 使用指定的profile加载配置
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypeInvalidCredentials,
			fmt.Sprintf("failed to load AWS profile '%s'", profile), err)
	}

	// 获取凭证
	credentials, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypeInvalidCredentials,
			fmt.Sprintf("failed to retrieve credentials from profile '%s'", profile), err)
	}

	return credentials, nil
}

// GetProviderType 返回提供者类型
func (pcp *ProfileCredentialsProvider) GetProviderType() string {
	return "profile"
}

// IAMRoleCredentialsProvider IAM角色凭证提供者
type IAMRoleCredentialsProvider struct {
	RoleARN      string                `json:"role_arn"`
	SessionName  string                `json:"session_name"`
	BaseProvider CredentialsProvider   `json:"-"` // 基础凭证提供者，不序列化
	Duration     time.Duration         `json:"duration,omitempty"`
}

// Retrieve 实现 CredentialsProvider 接口
func (ircp *IAMRoleCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if ircp.RoleARN == "" {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypeInvalidCredentials,
			"role ARN is required for IAM role credentials", nil)
	}

	if ircp.BaseProvider == nil {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypeInvalidCredentials,
			"base credentials provider is required for IAM role credentials", nil)
	}

	// 获取基础凭证
	baseCreds, err := ircp.BaseProvider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to retrieve base credentials: %w", err)
	}

	// 创建STS客户端
	cfg := aws.Config{
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return baseCreds, nil
		})),
	}
	stsClient := sts.NewFromConfig(cfg)

	// 设置会话名称
	sessionName := ircp.SessionName
	if sessionName == "" {
		sessionName = fmt.Sprintf("kom-eks-%d", time.Now().Unix())
	}

	// 设置会话持续时间（默认1小时）
	duration := ircp.Duration
	if duration == 0 {
		duration = time.Hour
	}

	// 承担角色
	result, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(ircp.RoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(int32(duration.Seconds())),
	})
	if err != nil {
		return aws.Credentials{}, NewEKSAuthError(ErrorTypePermissionDenied,
			fmt.Sprintf("failed to assume role %s", ircp.RoleARN), err)
	}

	return aws.Credentials{
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
		Expires:         *result.Credentials.Expiration,
		Source:          "IAMRoleCredentialsProvider",
	}, nil
}

// GetProviderType 返回提供者类型
func (ircp *IAMRoleCredentialsProvider) GetProviderType() string {
	return "iam_role"
}

// NewStaticCredentialsProvider 创建静态凭证提供者
func NewStaticCredentialsProvider(accessKey, secretKey, sessionToken string) *StaticCredentialsProvider {
	return &StaticCredentialsProvider{
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
	}
}

// NewProfileCredentialsProvider 创建Profile凭证提供者
func NewProfileCredentialsProvider(profile string) *ProfileCredentialsProvider {
	return &ProfileCredentialsProvider{
		Profile: profile,
	}
}

// NewIAMRoleCredentialsProvider 创建IAM角色凭证提供者
func NewIAMRoleCredentialsProvider(roleArn, sessionName string, baseProvider CredentialsProvider) *IAMRoleCredentialsProvider {
	return &IAMRoleCredentialsProvider{
		RoleARN:      roleArn,
		SessionName:  sessionName,
		BaseProvider: baseProvider,
		Duration:     time.Hour, // 默认1小时
	}
}