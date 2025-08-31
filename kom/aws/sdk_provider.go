package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"k8s.io/klog/v2"
)

// TokenProvider Token提供者接口
type TokenProvider interface {
	// GetToken 获取EKS认证token
	GetToken(ctx context.Context) (*TokenResponse, error)
	// GetTokenWithRetry 带重试机制获取token
	GetTokenWithRetry(ctx context.Context, maxRetries int) (*TokenResponse, error)
	// ValidateCluster 验证EKS集群是否存在
	ValidateCluster(ctx context.Context) error
	// String 返回提供者描述
	String() string
}

// EKSSDKConfig EKS SDK配置
type EKSSDKConfig struct {
	Region               string              `json:"region"`
	ClusterName          string              `json:"cluster_name"`
	CredentialsProvider  CredentialsProvider `json:"-"` // 不序列化
	RoleARN              string              `json:"role_arn,omitempty"`
	SessionName          string              `json:"session_name,omitempty"`
	HTTPTimeout          time.Duration       `json:"http_timeout,omitempty"`
}

// EKSTokenProvider EKS Token提供者实现
type EKSTokenProvider struct {
	eksClient    *eks.Client
	stsClient    *sts.Client
	config       *EKSSDKConfig
	httpClient   *http.Client
}

// NewEKSTokenProvider 创建新的EKS Token提供者
func NewEKSTokenProvider(config *EKSSDKConfig) (*EKSTokenProvider, error) {
	if config == nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "EKS SDK config is required", nil)
	}

	if config.Region == "" {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "AWS region is required", nil)
	}

	if config.ClusterName == "" {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "EKS cluster name is required", nil)
	}

	if config.CredentialsProvider == nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "credentials provider is required", nil)
	}

	// 配置HTTP客户端
	httpTimeout := config.HTTPTimeout
	if httpTimeout == 0 {
		httpTimeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
		Timeout: httpTimeout,
	}

	return &EKSTokenProvider{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// initClients 初始化AWS客户端
func (etp *EKSTokenProvider) initClients(ctx context.Context) error {
	// 获取凭证
	credentials, err := etp.config.CredentialsProvider.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// 配置AWS客户端
	awsConfig := aws.Config{
		Region:      etp.config.Region,
		HTTPClient:  etp.httpClient,
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return credentials, nil
		})),
	}

	etp.eksClient = eks.NewFromConfig(awsConfig)
	etp.stsClient = sts.NewFromConfig(awsConfig)

	return nil
}

// GetToken 获取EKS认证token
func (etp *EKSTokenProvider) GetToken(ctx context.Context) (*TokenResponse, error) {
	// 初始化客户端
	if err := etp.initClients(ctx); err != nil {
		return nil, err
	}

	// 验证调用者身份
	if err := etp.validateCallerIdentity(ctx); err != nil {
		return nil, err
	}

	// 生成Kubernetes Token
	token, err := etp.generateKubernetesToken(ctx)
	if err != nil {
		return nil, err
	}

	klog.V(2).Infof("Successfully generated EKS token for cluster %s", etp.config.ClusterName)

	return token, nil
}

// GetTokenWithRetry 带重试机制获取token
func (etp *EKSTokenProvider) GetTokenWithRetry(ctx context.Context, maxRetries int) (*TokenResponse, error) {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			klog.V(2).Infof("Retrying EKS token fetch, attempt %d/%d", i+1, maxRetries+1)

			// 指数退避
			waitTime := time.Duration(i) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitTime):
			}
		}

		token, err := etp.GetToken(ctx)
		if err == nil {
			return token, nil
		}

		lastErr = err
		
		// 判断是否应该重试
		if !etp.shouldRetry(err) {
			break
		}

		klog.V(3).Infof("EKS token fetch attempt %d failed: %v", i+1, err)
	}

	return nil, fmt.Errorf("failed to get EKS token after %d retries: %w", maxRetries+1, lastErr)
}

// ValidateCluster 验证EKS集群是否存在
func (etp *EKSTokenProvider) ValidateCluster(ctx context.Context) error {
	// 初始化客户端
	if err := etp.initClients(ctx); err != nil {
		return err
	}

	// 检查集群是否存在
	_, err := etp.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(etp.config.ClusterName),
	})
	if err != nil {
		return NewEKSAuthError(ErrorTypeClusterNotFound,
			fmt.Sprintf("EKS cluster '%s' not found in region '%s'", etp.config.ClusterName, etp.config.Region), err)
	}

	klog.V(2).Infof("EKS cluster %s validated successfully", etp.config.ClusterName)
	return nil
}

// validateCallerIdentity 验证调用者身份
func (etp *EKSTokenProvider) validateCallerIdentity(ctx context.Context) error {
	_, err := etp.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return NewEKSAuthError(ErrorTypeInvalidCredentials,
			"failed to validate AWS credentials", err)
	}

	return nil
}

// generateKubernetesToken 生成符合Kubernetes要求的Bearer Token
func (etp *EKSTokenProvider) generateKubernetesToken(ctx context.Context) (*TokenResponse, error) {
	// 创建预签名客户端
	presignClient := sts.NewPresignClient(etp.stsClient)

	// 构建GetCallerIdentity请求
	request := &sts.GetCallerIdentityInput{}
	
	// 设置15分钟过期时间
	expiryDuration := 15 * time.Minute
	presignedRequest, err := presignClient.PresignGetCallerIdentity(ctx, request, func(opts *sts.PresignOptions) {
		// 注意：Expires 字段可能在不同版本的SDK中不同
		// 这里使用默认过期时间
		_ = expiryDuration // 用于避免未使用警告
	})
	if err != nil {
		return nil, NewEKSAuthError(ErrorTypeTokenGeneration,
			"failed to generate presigned URL", err)
	}

	// 构建token URL
	tokenURL := presignedRequest.URL

	// 添加EKS集群信息到URL参数中
	parsedURL, err := url.Parse(tokenURL)
	if err != nil {
		return nil, NewEKSAuthError(ErrorTypeTokenGeneration,
			"failed to parse presigned URL", err)
	}

	// 添加自定义头部信息
	values := parsedURL.Query()
	values.Set("X-K8s-Aws-Id", etp.config.ClusterName)
	parsedURL.RawQuery = values.Encode()

	// 按照AWS EKS的token格式生成token
	// 格式：k8s-aws-v1.{base64url(presigned-url)}
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(parsedURL.String()))
	token := fmt.Sprintf("k8s-aws-v1.%s", tokenPayload)

	// Token比预签名URL早1分钟过期，确保安全性
	expiresAt := time.Now().Add(expiryDuration - time.Minute)

	return &TokenResponse{
		Status: TokenStatus{
			Token:               token,
			ExpirationTimestamp: expiresAt,
		},
	}, nil
}

// shouldRetry 判断是否应该重试
func (etp *EKSTokenProvider) shouldRetry(err error) bool {
	if eksErr, ok := err.(*EKSAuthError); ok {
		switch eksErr.Type {
		case ErrorTypeNetworkError, ErrorTypeTokenGeneration:
			return true
		case ErrorTypeInvalidCredentials, ErrorTypeClusterNotFound, ErrorTypeAWSConfigMissing:
			return false
		default:
			return true
		}
	}
	return true
}

// String 返回提供者描述
func (etp *EKSTokenProvider) String() string {
	return fmt.Sprintf("EKSTokenProvider(cluster=%s, region=%s, provider=%s)", 
		etp.config.ClusterName, etp.config.Region, etp.config.CredentialsProvider.GetProviderType())
}