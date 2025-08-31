package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// AWSAuthProvider AWS 认证提供者接口
type AWSAuthProvider interface {
	// GetToken 获取认证 token
	GetToken(ctx context.Context) (string, time.Time, error)
	// RefreshToken 刷新 token
	RefreshToken(ctx context.Context) error
	// IsEKSConfig 检测是否为 EKS 配置
	IsEKSConfig(kubeconfig []byte) bool
}

// EKSAuthConfig AWS EKS 认证配置
type EKSAuthConfig struct {
	// 保持向下兼容的字段
	AccessKey       string      `json:"access_key"`        // AWS Access Key ID
	SecretAccessKey string      `json:"secret_access_key"` // AWS Secret Access Key
	ClusterName     string      `json:"cluster_name"`      // EKS 集群名称
	Region          string      `json:"region"`            // AWS 区域
	RoleARN         string      `json:"role_arn"`          // 要承担的 IAM 角色 ARN (可选)
	SessionName     string      `json:"session_name"`      // 会话名称 (可选)
	
	// 新增字段
	SDKConfig       *EKSSDKConfig `json:"sdk_config,omitempty"`  // 新的SDK配置
	TokenCache      *TokenCache   `json:"token_cache"`           // token 缓存
	AWSConfig       *aws.Config   `json:"-"`                     // AWS 配置，不序列化
	
	// 废弃字段（保持兼容性）
	ExecConfig      *ExecConfig   `json:"exec_config,omitempty"` // exec 命令配置 (已废弃)
}

// ExecConfig 执行命令配置
type ExecConfig struct {
	Command         string            `json:"command"`           // 命令 (如 aws)
	Args            []string          `json:"args"`              // 参数列表
	Env             map[string]string `json:"env"`               // 环境变量
	AccessKey       string            `json:"access_key"`        // AWS Access Key ID
	SecretAccessKey string            `json:"secret_access_key"` // AWS Secret Access Key
	Region          string            `json:"region"`            // AWS 区域
	RoleARN         string            `json:"role_arn"`          // IAM 角色 ARN (可选)
	SessionName     string            `json:"session_name"`      // 会话名称 (可选)
}

// TokenCache token 缓存
type TokenCache struct {
	Token     string       `json:"token"`      // Bearer token
	ExpiresAt time.Time    `json:"expires_at"` // 过期时间
	mutex     sync.RWMutex // 读写锁，不序列化
}

// IsValid 检查 token 是否有效
func (tc *TokenCache) IsValid() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.Token != "" && time.Now().Before(tc.ExpiresAt)
}

// GetToken 安全获取 token
func (tc *TokenCache) GetToken() (string, time.Time) {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.Token, tc.ExpiresAt
}

// SetToken 安全设置 token
func (tc *TokenCache) SetToken(token string, expiresAt time.Time) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.Token = token
	tc.ExpiresAt = expiresAt
}

// ClearToken 清理 token
func (tc *TokenCache) ClearToken() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.Token = ""
	tc.ExpiresAt = time.Time{}
}

// EKSAuthError EKS 认证错误
type EKSAuthError struct {
	Type    string `json:"type"`    // TokenExpired, AWSConfigMissing, ExecFailed 等
	Message string `json:"message"` // 错误消息
	Cause   error  `json:"-"`       // 原始错误，不序列化
}

func (e *EKSAuthError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// NewEKSAuthError 创建 EKS 认证错误
func NewEKSAuthError(errorType, message string, cause error) *EKSAuthError {
	return &EKSAuthError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// Constants for error types
const (
	ErrorTypeTokenExpired       = "TokenExpired"
	ErrorTypeAWSConfigMissing   = "AWSConfigMissing"
	ErrorTypeExecFailed         = "ExecFailed"
	ErrorTypeInvalidKubeconfig  = "InvalidKubeconfig"
	ErrorTypeNetworkError       = "NetworkError"
	ErrorTypePermissionDenied   = "PermissionDenied"
	ErrorTypeInvalidCredentials = "InvalidCredentials"
	ErrorTypeClusterNotFound    = "ClusterNotFound"
	ErrorTypeRegionMismatch     = "RegionMismatch"
	ErrorTypeFileSystemError    = "FileSystemError"
	ErrorTypeKubeconfigInvalid  = "KubeconfigInvalid"
	// 新增错误类型
	ErrorTypeTokenGeneration    = "TokenGeneration"
	ErrorTypeCredentialsProvider = "CredentialsProvider"
	ErrorTypeSDKInitialization  = "SDKInitialization"
)

// BuildEnvVariables 构建完整的环境变量列表
func (ec *ExecConfig) BuildEnvVariables() []string {
	envVars := make([]string, 0)

	// 添加原有的环境变量
	for key, value := range ec.Env {
		envVars = append(envVars, fmt.Sprintf("%s=%s", key, value))
	}

	// 添加AWS凭证环境变量
	if ec.AccessKey != "" {
		envVars = append(envVars, fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", ec.AccessKey))
	}
	if ec.SecretAccessKey != "" {
		envVars = append(envVars, fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", ec.SecretAccessKey))
	}
	if ec.Region != "" {
		envVars = append(envVars, fmt.Sprintf("AWS_DEFAULT_REGION=%s", ec.Region))
	}
	if ec.RoleARN != "" {
		envVars = append(envVars, fmt.Sprintf("AWS_ROLE_ARN=%s", ec.RoleARN))
		if ec.SessionName != "" {
			envVars = append(envVars, fmt.Sprintf("AWS_ROLE_SESSION_NAME=%s", ec.SessionName))
		}
	}

	return envVars
}

// BuildSDKConfig 构建SDK配置
func (config *EKSAuthConfig) BuildSDKConfig() (*EKSSDKConfig, error) {
	// 如果已经有SDK配置，直接返回
	if config.SDKConfig != nil {
		return config.SDKConfig, nil
	}
	
	// 从基本配置生成SDK配置
	sdkConfig := &EKSSDKConfig{
		Region:      config.Region,
		ClusterName: config.ClusterName,
		RoleARN:     config.RoleARN,
		SessionName: config.SessionName,
	}
	
	// 创建凭证提供者
	if config.AccessKey != "" && config.SecretAccessKey != "" {
		sdkConfig.CredentialsProvider = NewStaticCredentialsProvider(
			config.AccessKey, config.SecretAccessKey, "")
	} else {
		// 使用默认profile
		sdkConfig.CredentialsProvider = NewProfileCredentialsProvider("default")
	}
	
	// 如果有IAM角色，包装成IAM角色提供者
	if config.RoleARN != "" {
		baseProvider := sdkConfig.CredentialsProvider
		sdkConfig.CredentialsProvider = NewIAMRoleCredentialsProvider(
			config.RoleARN, config.SessionName, baseProvider)
	}
	
	config.SDKConfig = sdkConfig
	return sdkConfig, nil
}

// IsUsingSDK 检查是否使用SDK模式
func (config *EKSAuthConfig) IsUsingSDK() bool {
	return config.SDKConfig != nil
}
