package aws

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"
)

// KubeconfigGenerator 简化的Kubeconfig生成器 - 仅支持SDK模式
type KubeconfigGenerator struct {
	timeout time.Duration
}

// NewKubeconfigGenerator 创建Kubeconfig生成器
func NewKubeconfigGenerator() *KubeconfigGenerator {
	return &KubeconfigGenerator{
		timeout: 30 * time.Second,
	}
}

// GenerateFromAWS 通过AWS SDK生成kubeconfig
func (kg *KubeconfigGenerator) GenerateFromAWS(config *EKSAuthConfig) (string, error) {
	if err := kg.validateConfig(config); err != nil {
		return "", err
	}

	// 使用SDK模式生成
	return kg.generateWithSDK(config)
}

// generateWithSDK 使用AWS SDK生成kubeconfig
func (kg *KubeconfigGenerator) generateWithSDK(config *EKSAuthConfig) (string, error) {
	// 构建或获取SDK配置
	sdkConfig, err := config.BuildSDKConfig()
	if err != nil {
		return "", NewEKSAuthError(ErrorTypeSDKInitialization, "failed to build SDK config", err)
	}

	// 创建具体的SDK生成器
	sdkGenerator, err := NewSDKKubeconfigGenerator(sdkConfig)
	if err != nil {
		return "", NewEKSAuthError(ErrorTypeSDKInitialization, "failed to create SDK generator", err)
	}

	// 生成kubeconfig
	ctx, cancel := context.WithTimeout(context.Background(), kg.timeout)
	defer cancel()

	kubeconfigContent, err := sdkGenerator.GenerateKubeconfig(ctx)
	if err != nil {
		return "", fmt.Errorf("SDK kubeconfig generation failed: %w", err)
	}

	klog.V(2).Infof("Generated kubeconfig using SDK for cluster: %s", config.ClusterName)
	return kubeconfigContent, nil
}

// validateConfig 验证配置
func (kg *KubeconfigGenerator) validateConfig(config *EKSAuthConfig) error {
	// 检查基本参数
	if config.Region == "" {
		return NewEKSAuthError(ErrorTypeInvalidCredentials, "Region is required", nil)
	}
	if config.ClusterName == "" {
		return NewEKSAuthError(ErrorTypeInvalidCredentials, "ClusterName is required", nil)
	}
	
	// 检查是否有SDK配置或可构建的凭证
	if config.SDKConfig != nil {
		return nil // SDK配置已存在
	}
	
	// 检查是否有足够的信息构建SDK配置
	if config.AccessKey == "" || config.SecretAccessKey == "" {
		return NewEKSAuthError(ErrorTypeInvalidCredentials, "AccessKey and SecretAccessKey are required", nil)
	}
	
	return nil
}

// SetTimeout 设置超时时间
func (kg *KubeconfigGenerator) SetTimeout(timeout time.Duration) {
	kg.timeout = timeout
}