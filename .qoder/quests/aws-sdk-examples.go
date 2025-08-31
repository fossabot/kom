package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/weibaohui/kom/kom/aws"
)

// 示例1：使用静态凭证注册EKS集群
func ExampleStaticCredentials() {
	// 创建静态凭证提供者
	credProvider := aws.NewStaticCredentialsProvider(
		"your-access-key",
		"your-secret-key", 
		"", // session token (可选)
	)

	// 创建SDK配置
	sdkConfig := &aws.EKSSDKConfig{
		Region:              "us-west-2",
		ClusterName:         "my-eks-cluster",
		CredentialsProvider: credProvider,
	}

	// 创建EKS认证配置
	eksConfig := &aws.EKSAuthConfig{
		ClusterName: "my-eks-cluster",
		Region:      "us-west-2",
		SDKConfig:   sdkConfig,
		TokenCache:  &aws.TokenCache{},
	}

	// 创建Token管理器
	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// 验证配置
	if tokenManager.IsUsingSDK() {
		fmt.Printf("✅ Using SDK mode: %s\n", tokenManager.GetProviderInfo())
	}

	// 获取token
	ctx := context.Background()
	token, err := tokenManager.GetValidToken(ctx)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	fmt.Printf("🎫 Token obtained successfully (length: %d)\n", len(token))
}

// 示例2：使用AWS Profile
func ExampleProfileCredentials() {
	// 创建Profile凭证提供者
	credProvider := aws.NewProfileCredentialsProvider("my-profile")

	// 创建SDK配置
	sdkConfig := &aws.EKSSDKConfig{
		Region:              "us-west-2",
		ClusterName:         "my-eks-cluster",
		CredentialsProvider: credProvider,
	}

	eksConfig := &aws.EKSAuthConfig{
		ClusterName: "my-eks-cluster",
		Region:      "us-west-2",
		SDKConfig:   sdkConfig,
		TokenCache:  &aws.TokenCache{},
	}

	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	fmt.Printf("📄 Using profile credentials: %s\n", tokenManager.GetProviderInfo())
}

// 示例3：使用IAM角色
func ExampleIAMRoleCredentials() {
	// 基础凭证
	baseProvider := aws.NewStaticCredentialsProvider(
		"base-access-key",
		"base-secret-key",
		"",
	)

	// IAM角色凭证提供者
	roleProvider := aws.NewIAMRoleCredentialsProvider(
		"arn:aws:iam::123456789012:role/EKSAccessRole",
		"kom-session",
		baseProvider,
	)

	sdkConfig := &aws.EKSSDKConfig{
		Region:              "us-west-2",
		ClusterName:         "my-eks-cluster",
		CredentialsProvider: roleProvider,
	}

	eksConfig := &aws.EKSAuthConfig{
		ClusterName: "my-eks-cluster",
		Region:      "us-west-2",
		SDKConfig:   sdkConfig,
		TokenCache:  &aws.TokenCache{},
	}

	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	fmt.Printf("🎭 Using IAM role: %s\n", tokenManager.GetProviderInfo())
}

// 示例4：使用基本配置创建SDK模式
func ExampleBasicToSDK() {
	// 基本的配置格式（自动转为SDK模式）
	eksConfig := &aws.EKSAuthConfig{
		AccessKey:       "your-access-key",
		SecretAccessKey: "your-secret-key",
		ClusterName:     "my-eks-cluster",
		Region:          "us-west-2",
		TokenCache:      &aws.TokenCache{},
	}

	// 直接构建SDK配置
	sdkConfig, err := eksConfig.BuildSDKConfig()
	if err != nil {
		log.Fatalf("Failed to build SDK config: %v", err)
	}
	
	fmt.Printf("✨ SDK Config: cluster=%s, region=%s, provider=%s\n",
		sdkConfig.ClusterName, sdkConfig.Region, sdkConfig.CredentialsProvider.GetProviderType())

	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	fmt.Printf("🚀 Using SDK mode: %s\n", tokenManager.GetProviderInfo())
}

// 示例5：Token生命周期管理
func ExampleTokenLifecycle() {
	eksConfig := &aws.EKSAuthConfig{
		AccessKey:       "your-access-key",
		SecretAccessKey: "your-secret-key",
		ClusterName:     "my-eks-cluster",
		Region:          "us-west-2",
		TokenCache:      &aws.TokenCache{},
	}

	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	ctx := context.Background()

	// 启动自动刷新
	tokenManager.StartAutoRefresh(ctx)
	defer tokenManager.Stop()

	// 获取Token信息
	token, expiresAt, valid := tokenManager.GetTokenInfo()
	fmt.Printf("🔍 Token status: valid=%v, expires=%v\n", valid, expiresAt)

	if !valid {
		// 刷新Token
		fmt.Println("🔄 Refreshing token...")
		err = tokenManager.RefreshToken(ctx)
		if err != nil {
			log.Fatalf("Failed to refresh token: %v", err)
		}
		
		// 重新获取信息
		token, expiresAt, valid = tokenManager.GetTokenInfo()
		fmt.Printf("✅ Token refreshed: valid=%v, length=%d, expires=%v\n", 
			valid, len(token), expiresAt)
	}

	// 手动触发刷新
	tokenManager.TriggerRefresh()
	fmt.Println("📤 Manual refresh triggered")
}

// 示例6：错误处理和重试
func ExampleErrorHandling() {
	// 故意使用错误的凭证来演示错误处理
	credProvider := aws.NewStaticCredentialsProvider("invalid", "invalid", "")
	
	sdkConfig := &aws.EKSSDKConfig{
		Region:              "us-west-2",
		ClusterName:         "non-existent-cluster",
		CredentialsProvider: credProvider,
	}

	eksConfig := &aws.EKSAuthConfig{
		ClusterName: "non-existent-cluster",
		Region:      "us-west-2",
		SDKConfig:   sdkConfig,
		TokenCache:  &aws.TokenCache{},
	}

	tokenManager, err := aws.NewTokenManager(eksConfig)
	if err != nil {
		if eksErr, ok := err.(*aws.EKSAuthError); ok {
			fmt.Printf("❌ EKS Error Type: %s\n", eksErr.Type)
			fmt.Printf("📝 Error Message: %s\n", eksErr.Message)
			
			// 检查是否可重试
			if aws.ShouldRetryError(err) {
				fmt.Println("🔄 This error can be retried")
			} else {
				fmt.Println("🚫 This error should not be retried")
			}
		}
		return
	}

	// 尝试获取token (会失败)
	ctx := context.Background()
	_, err = tokenManager.GetValidToken(ctx)
	if err != nil {
		fmt.Printf("💥 Expected error: %v\n", err)
	}
}

// 示例7：使用重试机制
func ExampleRetryMechanism() {
	retryConfig := &aws.RetryConfig{
		MaxRetries:      3,
		InitialInterval: time.Second,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:         true,
	}

	ctx := context.Background()

	// 定义一个可能失败的操作
	operation := func(ctx context.Context, attempt int) error {
		fmt.Printf("🎯 Attempt %d: Trying operation...\n", attempt+1)
		
		// 模拟前两次失败
		if attempt < 2 {
			return aws.NewEKSAuthError(aws.ErrorTypeNetworkError, 
				"simulated network error", nil)
		}
		
		fmt.Println("✅ Operation succeeded!")
		return nil
	}

	// 使用指数退避重试
	err := aws.RetryWithBackoff(ctx, retryConfig, operation)
	if err != nil {
		fmt.Printf("❌ Operation failed after retries: %v\n", err)
	} else {
		fmt.Println("🎉 Operation completed successfully")
	}
}

// 示例8：生成Kubeconfig
func ExampleKubeconfigGeneration() {
	sdkConfig := &aws.EKSSDKConfig{
		Region:      "us-west-2",
		ClusterName: "my-eks-cluster",
		CredentialsProvider: aws.NewStaticCredentialsProvider(
			"your-access-key", "your-secret-key", ""),
	}

	// 创建SDK Kubeconfig生成器
	generator, err := aws.NewSDKKubeconfigGenerator(sdkConfig)
	if err != nil {
		log.Fatalf("Failed to create generator: %v", err)
	}

	ctx := context.Background()

	// 验证集群
	err = generator.ValidateCluster(ctx)
	if err != nil {
		fmt.Printf("❌ Cluster validation failed: %v\n", err)
		return
	}

	// 生成kubeconfig
	kubeconfig, err := generator.GenerateKubeconfig(ctx)
	if err != nil {
		log.Fatalf("Failed to generate kubeconfig: %v", err)
	}

	fmt.Printf("📄 Kubeconfig generated successfully (length: %d bytes)\n", len(kubeconfig))
	fmt.Printf("🎯 Generator info: %s\n", generator.String())
}

func main() {
	fmt.Println("🚀 AWS SDK Integration Examples")
	fmt.Println("================================")

	// 注意：这些示例需要有效的AWS凭证和EKS集群才能正常运行
	// 在实际环境中，请替换为真实的凭证和集群信息

	fmt.Println("\n1. 基本配置转换SDK示例:")
	ExampleBasicToSDK()

	fmt.Println("\n2. 错误处理示例:")
	ExampleErrorHandling()

	fmt.Println("\n3. 重试机制示例:")
	ExampleRetryMechanism()

	fmt.Println("\n✨ Examples completed!")
}