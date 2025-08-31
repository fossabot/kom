package aws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/weibaohui/kom/utils"
	"k8s.io/klog/v2"
)

// ExecExecutor 命令执行器
type ExecExecutor struct{}

// NewExecExecutor 创建新的命令执行器
func NewExecExecutor() *ExecExecutor {
	return &ExecExecutor{}
}

// TokenResponse AWS CLI 返回的 token 响应结构
type TokenResponse struct {
	Kind       string      `json:"kind"`
	APIVersion string      `json:"apiVersion"`
	Spec       TokenSpec   `json:"spec"`
	Status     TokenStatus `json:"status"`
}

// TokenSpec token 规格
type TokenSpec struct {
	Interactive bool `json:"interactive"`
}

// TokenStatus token 状态
type TokenStatus struct {
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
	Token               string    `json:"token"`
}

// ExecuteCommand 执行 AWS CLI 命令获取 token
func (ee *ExecExecutor) ExecuteCommand(ctx context.Context, execConfig *ExecConfig) (*TokenResponse, error) {
	if execConfig == nil {
		return nil, NewEKSAuthError(ErrorTypeExecFailed, "exec config is nil", nil)
	}

	klog.V(8).Infof("Executing AWS command: %s %v", execConfig.Command, execConfig.Args)

	// 创建命令
	cmd := exec.CommandContext(ctx, execConfig.Command, execConfig.Args...)

	// 构建完整的环境变量列表
	envVars := execConfig.BuildEnvVariables()
	cmd.Env = envVars
	klog.V(8).Infof("cmd args= %s", cmd)
	// 执行命令
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		klog.Errorf("Failed to execute AWS command: %v, stderr: %s", err, stderr.String())
		return nil, NewEKSAuthError(ErrorTypeExecFailed,
			fmt.Sprintf("failed to execute AWS command: %s", stderr.String()), err)
	}

	// 解析输出
	var tokenResponse TokenResponse
	if err := json.Unmarshal(stdout.Bytes(), &tokenResponse); err != nil {
		klog.Errorf("Failed to parse AWS command output: %v, output: %s", err, stdout.String())
		return nil, NewEKSAuthError(ErrorTypeExecFailed,
			fmt.Sprintf("failed to parse AWS command output: %v", err), err)
	}

	// 验证响应
	if tokenResponse.Status.Token == "" {
		return nil, NewEKSAuthError(ErrorTypeExecFailed, "empty token in AWS response", nil)
	}

	klog.V(4).Infof("Successfully obtained AWS token, expires at: %v",
		tokenResponse.Status.ExpirationTimestamp)

	return &tokenResponse, nil
}

func (ee *ExecExecutor) ExecuteCommandBySDK(ctx context.Context, execConfig *ExecConfig) (*TokenResponse, error) {
	if execConfig == nil {
		return nil, NewEKSAuthError(ErrorTypeExecFailed, "exec config is nil", nil)
	}

	klog.V(8).Infof("Executing AWS command: %s %v", execConfig.Command, execConfig.Args)

	// 创建命令
	cmd := exec.CommandContext(ctx, execConfig.Command, execConfig.Args...)

	// 构建完整的环境变量列表
	envVars := execConfig.BuildEnvVariables()
	cmd.Env = envVars
	klog.V(8).Infof("cmd args= %s", cmd)
	// 执行命令
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		klog.Errorf("Failed to execute AWS command: %v, stderr: %s", err, stderr.String())
		return nil, NewEKSAuthError(ErrorTypeExecFailed,
			fmt.Sprintf("failed to execute AWS command: %s", stderr.String()), err)
	}

	// 解析输出
	var tokenResponse TokenResponse
	if err := json.Unmarshal(stdout.Bytes(), &tokenResponse); err != nil {
		klog.Errorf("Failed to parse AWS command output: %v, output: %s", err, stdout.String())
		return nil, NewEKSAuthError(ErrorTypeExecFailed,
			fmt.Sprintf("failed to parse AWS command output: %v", err), err)
	}

	// 验证响应
	if tokenResponse.Status.Token == "" {
		return nil, NewEKSAuthError(ErrorTypeExecFailed, "empty token in AWS response", nil)
	}

	klog.V(4).Infof("Successfully obtained AWS token, expires at: %v",
		tokenResponse.Status.ExpirationTimestamp)

	// 构造 AWS 配置（只用传入参数，不读环境变量）
	cfg := aws.Config{
		Region: execConfig.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			execConfig.AccessKey,
			execConfig.SecretAccessKey,
			execConfig.SessionName,
		),
	}

	// STS 客户端
	stsSvc := sts.NewFromConfig(cfg)
	presignClient := sts.NewPresignClient(stsSvc)

	// 生成预签名 URL
	presigned, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	// if err != nil {
	// 	return nil, err
	// }
	// 构造 STS GetCallerIdentity 请求
	stsEndpoint := fmt.Sprintf("https://sts.%s.amazonaws.com/", execConfig.Region)
	req, _ := http.NewRequest("GET", stsEndpoint, nil)
	q := req.URL.Query()
	q.Set("Action", "GetCallerIdentity")
	q.Set("Version", "2011-06-15")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("x-k8s-aws-id", "host;x-k8s-aws-id")
	req.Header.Set("X-Amz-Expires", "60")
	now := time.Now()
	awc := aws.Credentials{
		AccessKeyID:     execConfig.AccessKey,
		SecretAccessKey: execConfig.SecretAccessKey,
		Source:          "sts",
		CanExpire:       false,
		Expires:         now,
	}
	// 用 SigV4 生成预签名 URL
	signer := v4.NewSigner()
	presignedReq, headers, err := signer.PresignHTTP(ctx, awc, req, "", "sts", execConfig.Region, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to presign request:", err)
		os.Exit(1)
	}
	klog.V(2).Infof("headers=\n%v\n", utils.ToJSON(headers))

	token := "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(presignedReq))

	// Base64 URL 编码，拼成 EKS token
	// token = "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(presigned.URL))

	tokenResponse2 := TokenResponse{
		Kind:       "ExecCredential",
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Spec: TokenSpec{
			Interactive: false,
		},
		Status: TokenStatus{
			ExpirationTimestamp: now.Add(15 * time.Minute).UTC(),
			Token:               token,
		},
	}
	klog.V(2).Infof("tokenResponse1=\n%v\n", utils.ToJSON(tokenResponse))
	klog.V(2).Infof("tokenResponse2=\n%v\n", utils.ToJSON(tokenResponse2))
	return &tokenResponse2, nil
}

// GetTokenWithRetry 带重试机制的获取 token
func (ee *ExecExecutor) GetTokenWithRetry(ctx context.Context, execConfig *ExecConfig, maxRetries int) (*TokenResponse, error) {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			klog.V(2).Infof("Retrying AWS token fetch, attempt %d/%d", i+1, maxRetries+1)

			// 指数退避
			waitTime := time.Duration(i) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitTime):
			}
		}

		tokenResponse, err := ee.ExecuteCommandBySDK(ctx, execConfig)
		if err == nil {
			return tokenResponse, nil
		}

		lastErr = err
		klog.V(3).Infof("AWS token fetch attempt %d failed: %v", i+1, err)
	}

	return nil, fmt.Errorf("failed to get AWS token after %d retries: %w", maxRetries+1, lastErr)
}

// ValidateCommand 验证命令是否可执行
func (ee *ExecExecutor) ValidateCommand(execConfig *ExecConfig) error {
	if execConfig == nil {
		return NewEKSAuthError(ErrorTypeExecFailed, "exec config is nil", nil)
	}

	if execConfig.Command == "" {
		return NewEKSAuthError(ErrorTypeExecFailed, "command is empty", nil)
	}

	// 检查命令是否存在
	_, err := exec.LookPath(execConfig.Command)
	if err != nil {
		return NewEKSAuthError(ErrorTypeExecFailed,
			fmt.Sprintf("command %s not found in PATH", execConfig.Command), err)
	}

	return nil
}
