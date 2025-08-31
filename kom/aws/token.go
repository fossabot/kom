package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"k8s.io/klog/v2"
)

// TokenManager Token管理器 - 只支持SDK模式
type TokenManager struct {
	eksConfig *EKSAuthConfig
	awsConfig aws.Config
	stsClient *sts.Client
	
	// Token提供者 (SDK模式)
	tokenProvider TokenProvider
	
	// 并发控制
	refreshMutex    sync.RWMutex
	autoRefreshCtx  context.Context
	autoRefreshStop context.CancelFunc
	refreshChan     chan struct{}
	stopChan        chan struct{}
}

// NewTokenManager 创建新的token管理器
func NewTokenManager(eksConfig *EKSAuthConfig) (*TokenManager, error) {
	if eksConfig == nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "EKS config is required", nil)
	}

	tm := &TokenManager{
		eksConfig:   eksConfig,
		refreshChan: make(chan struct{}, 1),
		stopChan:    make(chan struct{}),
	}

	// 初始化Token提供者
	if err := tm.initTokenProvider(); err != nil {
		return nil, err
	}

	// 初始化AWS配置
	if err := tm.initAWSConfig(context.Background()); err != nil {
		return nil, err
	}

	return tm, nil
}

// initTokenProvider 初始化Token提供者
func (tm *TokenManager) initTokenProvider() error {
	// 优先使用SDK配置
	if tm.eksConfig.SDKConfig != nil {
		tokenProvider, err := NewEKSTokenProvider(tm.eksConfig.SDKConfig)
		if err != nil {
			return fmt.Errorf("failed to create EKS token provider: %w", err)
		}
		tm.tokenProvider = tokenProvider
		klog.V(2).Infof("Using SDK token provider: %s", tokenProvider.String())
		return nil
	}
	
	// 如果没有SDK配置，尝试从基本配置构建
	if tm.eksConfig.AccessKey != "" && tm.eksConfig.SecretAccessKey != "" &&
		tm.eksConfig.Region != "" && tm.eksConfig.ClusterName != "" {
		
		klog.V(2).Infof("Building SDK config from basic auth config")
		
		sdkConfig, err := tm.eksConfig.BuildSDKConfig()
		if err != nil {
			return fmt.Errorf("failed to build SDK config: %w", err)
		}
		
		tokenProvider, err := NewEKSTokenProvider(sdkConfig)
		if err != nil {
			return fmt.Errorf("failed to create EKS token provider: %w", err)
		}
		
		tm.tokenProvider = tokenProvider
		klog.V(2).Infof("Using SDK token provider: %s", tokenProvider.String())
		return nil
	}

	return NewEKSAuthError(ErrorTypeAWSConfigMissing, 
		"no valid SDK configuration found, please provide either SDKConfig or basic AWS credentials", nil)
}

// GetValidToken 获取有效的token
func (tm *TokenManager) GetValidToken(ctx context.Context) (string, error) {
	// 检查缓存中的token是否有效
	if tm.eksConfig.TokenCache != nil && tm.eksConfig.TokenCache.IsValid() {
		token, _ := tm.eksConfig.TokenCache.GetToken()
		klog.V(4).Infof("Using cached AWS token")
		return token, nil
	}

	klog.V(3).Infof("Cached token expired or missing, fetching new token")
	return tm.refreshToken(ctx)
}

// refreshToken 刷新token
func (tm *TokenManager) refreshToken(ctx context.Context) (string, error) {
	tm.refreshMutex.Lock()
	defer tm.refreshMutex.Unlock()

	// 双重检查 - 在获取锁期间可能已经刷新了
	if tm.eksConfig.TokenCache != nil && tm.eksConfig.TokenCache.IsValid() {
		token, _ := tm.eksConfig.TokenCache.GetToken()
		return token, nil
	}

	// 使用SDK提供者
	if tm.tokenProvider != nil {
		tokenResponse, err := tm.tokenProvider.GetTokenWithRetry(ctx, 2)
		if err != nil {
			return "", fmt.Errorf("SDK token provider failed: %w", err)
		}
		
		// 初始化TokenCache如果不存在
		if tm.eksConfig.TokenCache == nil {
			tm.eksConfig.TokenCache = &TokenCache{}
		}

		// 更新缓存
		tm.eksConfig.TokenCache.SetToken(tokenResponse.Status.Token, tokenResponse.Status.ExpirationTimestamp)

		klog.V(2).Infof("Successfully refreshed AWS token, expires at: %v",
			tokenResponse.Status.ExpirationTimestamp)

		return tokenResponse.Status.Token, nil
	}
	
	return "", NewEKSAuthError(ErrorTypeAWSConfigMissing, "no token provider available", nil)
}

// RefreshToken 公共方法刷新token
func (tm *TokenManager) RefreshToken(ctx context.Context) error {
	_, err := tm.refreshToken(ctx)
	return err
}

// StartAutoRefresh 启动自动刷新机制
func (tm *TokenManager) StartAutoRefresh(ctx context.Context) {
	tm.autoRefreshCtx, tm.autoRefreshStop = context.WithCancel(ctx)
	go tm.autoRefreshLoop(tm.autoRefreshCtx)
}

// autoRefreshLoop 自动刷新循环
func (tm *TokenManager) autoRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // 每5分钟检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			klog.V(2).Infof("Stopping AWS token auto-refresh due to context cancellation")
			return
		case <-tm.stopChan:
			klog.V(2).Infof("Stopping AWS token auto-refresh")
			return
		case <-ticker.C:
			tm.checkAndRefreshToken(ctx)
		case <-tm.refreshChan:
			// 手动触发刷新
			tm.checkAndRefreshToken(ctx)
		}
	}
}

// checkAndRefreshToken 检查并刷新token
func (tm *TokenManager) checkAndRefreshToken(ctx context.Context) {
	if tm.eksConfig.TokenCache == nil {
		return
	}

	token, expiresAt := tm.eksConfig.TokenCache.GetToken()

	// 如果token在10分钟内过期，则刷新
	refreshThreshold := time.Now().Add(10 * time.Minute)
	if token == "" || expiresAt.Before(refreshThreshold) {
		klog.V(3).Infof("Token will expire soon, refreshing...")
		if err := tm.RefreshToken(ctx); err != nil {
			klog.Errorf("Failed to refresh AWS token: %v", err)
		}
	}
}

// TriggerRefresh 触发立即刷新
func (tm *TokenManager) TriggerRefresh() {
	select {
	case tm.refreshChan <- struct{}{}:
	default:
		// 如果通道已满，忽略
	}
}

// Stop 停止自动刷新
func (tm *TokenManager) Stop() {
	if tm.autoRefreshStop != nil {
		tm.autoRefreshStop()
	}
	close(tm.stopChan)
}

// GetTokenInfo 获取token信息
func (tm *TokenManager) GetTokenInfo() (token string, expiresAt time.Time, valid bool) {
	if tm.eksConfig.TokenCache == nil {
		return "", time.Time{}, false
	}
	token, expiresAt = tm.eksConfig.TokenCache.GetToken()
	valid = tm.eksConfig.TokenCache.IsValid()
	return
}

// ValidateAWSCredentials 验证AWS凭证
func (tm *TokenManager) ValidateAWSCredentials(ctx context.Context) error {
	if tm.tokenProvider != nil {
		// SDK模式：使用Token Provider验证
		return tm.tokenProvider.ValidateCluster(ctx)
	}

	return NewEKSAuthError(ErrorTypeAWSConfigMissing, "no token provider available for validation", nil)
}

// GetCallerIdentity 获取当前AWS身份信息
func (tm *TokenManager) GetCallerIdentity(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
	if tm.stsClient == nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "STS client not initialized", nil)
	}

	return tm.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}

// AssumeRole 承担IAM角色（如果配置了）
func (tm *TokenManager) AssumeRole(ctx context.Context) error {
	if tm.eksConfig.RoleARN == "" {
		// 没有配置角色，跳过
		return nil
	}

	if tm.stsClient == nil {
		return NewEKSAuthError(ErrorTypeAWSConfigMissing, "STS client not initialized", nil)
	}

	klog.V(2).Infof("Assuming role: %s", tm.eksConfig.RoleARN)

	sessionName := tm.eksConfig.SessionName
	if sessionName == "" {
		sessionName = fmt.Sprintf("kom-eks-%d", time.Now().Unix())
	}

	result, err := tm.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         &tm.eksConfig.RoleARN,
		RoleSessionName: &sessionName,
	})
	if err != nil {
		return NewEKSAuthError(ErrorTypePermissionDenied,
			fmt.Sprintf("failed to assume role %s", tm.eksConfig.RoleARN), err)
	}

	// 更新AWS配置使用临时凭证
	tm.awsConfig.Credentials = aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     *result.Credentials.AccessKeyId,
			SecretAccessKey: *result.Credentials.SecretAccessKey,
			SessionToken:    *result.Credentials.SessionToken,
			Expires:         *result.Credentials.Expiration,
		}, nil
	}))

	klog.V(2).Infof("Successfully assumed role: %s", tm.eksConfig.RoleARN)
	return nil
}

// ClearCache 清理token缓存
func (tm *TokenManager) ClearCache() {
	if tm.eksConfig.TokenCache != nil {
		tm.eksConfig.TokenCache.ClearToken()
	}
	klog.V(2).Infof("Cleared AWS token cache")
}

// IsUsingSDK 检查是否使用SDK模式
func (tm *TokenManager) IsUsingSDK() bool {
	return tm.tokenProvider != nil
}



// GetProviderInfo 获取提供者信息
func (tm *TokenManager) GetProviderInfo() string {
	if tm.tokenProvider != nil {
		return fmt.Sprintf("SDK: %s", tm.tokenProvider.String())
	}
	return "None"
}

// initAWSConfig 初始化AWS配置
func (tm *TokenManager) initAWSConfig(ctx context.Context) error {
	var opts []func(*config.LoadOptions) error

	// 设置区域
	if tm.eksConfig.Region != "" {
		opts = append(opts, config.WithRegion(tm.eksConfig.Region))
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return NewEKSAuthError(ErrorTypeAWSConfigMissing, "failed to load AWS config", err)
	}

	tm.awsConfig = awsConfig
	tm.stsClient = sts.NewFromConfig(awsConfig)

	// 保存到EKS配置中
	tm.eksConfig.AWSConfig = &awsConfig

	klog.V(2).Infof("Initialized AWS config with region: %s", awsConfig.Region)
	return nil
}