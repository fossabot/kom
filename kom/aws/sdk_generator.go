package aws

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

// SDKKubeconfigGenerator 基于AWS SDK的Kubeconfig生成器
type SDKKubeconfigGenerator struct {
	config *EKSSDKConfig
	eksClient *eks.Client
}

// NewSDKKubeconfigGenerator 创建新的SDK Kubeconfig生成器
func NewSDKKubeconfigGenerator(config *EKSSDKConfig) (*SDKKubeconfigGenerator, error) {
	if config == nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing, "EKS SDK config is required", nil)
	}

	return &SDKKubeconfigGenerator{
		config: config,
	}, nil
}

// GenerateKubeconfig 生成kubeconfig内容
func (skg *SDKKubeconfigGenerator) GenerateKubeconfig(ctx context.Context) (string, error) {
	// 初始化EKS客户端
	if err := skg.initEKSClient(ctx); err != nil {
		return "", err
	}

	// 获取集群信息
	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return "", err
	}

	// 生成kubeconfig结构
	kubeconfig := skg.buildKubeconfigStructure(clusterInfo)

	// 序列化为YAML
	kubeconfigBytes, err := yaml.Marshal(kubeconfig)
	if err != nil {
		return "", NewEKSAuthError(ErrorTypeKubeconfigInvalid,
			"failed to marshal kubeconfig to YAML", err)
	}

	klog.V(2).Infof("Successfully generated kubeconfig for EKS cluster: %s", skg.config.ClusterName)
	return string(kubeconfigBytes), nil
}

// initEKSClient 初始化EKS客户端
func (skg *SDKKubeconfigGenerator) initEKSClient(ctx context.Context) error {
	// 获取凭证
	credentials, err := skg.config.CredentialsProvider.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// 配置AWS客户端
	awsConfig := aws.Config{
		Region: skg.config.Region,
		Credentials: aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return credentials, nil
		})),
	}

	skg.eksClient = eks.NewFromConfig(awsConfig)
	return nil
}

// getClusterInfo 获取EKS集群信息
func (skg *SDKKubeconfigGenerator) getClusterInfo(ctx context.Context) (*eks.DescribeClusterOutput, error) {
	result, err := skg.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(skg.config.ClusterName),
	})
	if err != nil {
		return nil, NewEKSAuthError(ErrorTypeClusterNotFound,
			fmt.Sprintf("failed to describe EKS cluster '%s'", skg.config.ClusterName), err)
	}

	return result, nil
}

// buildKubeconfigStructure 构建kubeconfig结构
func (skg *SDKKubeconfigGenerator) buildKubeconfigStructure(clusterInfo *eks.DescribeClusterOutput) map[string]interface{} {
	cluster := clusterInfo.Cluster
	clusterName := skg.config.ClusterName
	contextName := fmt.Sprintf("%s@%s.%s.eksctl.io", clusterName, clusterName, skg.config.Region)
	
	// 构建exec配置 - 使用SDK模式而非AWS CLI
	execConfig := map[string]interface{}{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind":       "ExecCredential",
		"command":    "kom-aws-auth", // 这将是我们的内置认证命令
		"args": []string{
			"--region", skg.config.Region,
			"--cluster-name", clusterName,
			"--provider-type", skg.config.CredentialsProvider.GetProviderType(),
		},
		"env": skg.buildExecEnv(),
	}

	// 如果有IAM角色，添加相关参数
	if skg.config.RoleARN != "" {
		execConfig["args"] = append(execConfig["args"].([]string), 
			"--role-arn", skg.config.RoleARN)
		if skg.config.SessionName != "" {
			execConfig["args"] = append(execConfig["args"].([]string), 
				"--session-name", skg.config.SessionName)
		}
	}

	kubeconfig := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []map[string]interface{}{
			{
				"cluster": map[string]interface{}{
					"certificate-authority-data": base64.StdEncoding.EncodeToString([]byte(*cluster.CertificateAuthority.Data)),
					"server":                     *cluster.Endpoint,
				},
				"name": contextName,
			},
		},
		"contexts": []map[string]interface{}{
			{
				"context": map[string]interface{}{
					"cluster": contextName,
					"user":    contextName,
				},
				"name": contextName,
			},
		},
		"current-context": contextName,
		"preferences":     map[string]interface{}{},
		"users": []map[string]interface{}{
			{
				"name": contextName,
				"user": map[string]interface{}{
					"exec": execConfig,
				},
			},
		},
	}

	return kubeconfig
}

// buildExecEnv 构建exec环境变量
func (skg *SDKKubeconfigGenerator) buildExecEnv() []map[string]string {
	var envVars []map[string]string

	// 根据凭证提供者类型设置环境变量
	switch provider := skg.config.CredentialsProvider.(type) {
	case *StaticCredentialsProvider:
		envVars = append(envVars, 
			map[string]string{"name": "AWS_ACCESS_KEY_ID", "value": provider.AccessKey},
			map[string]string{"name": "AWS_SECRET_ACCESS_KEY", "value": provider.SecretKey},
		)
		if provider.SessionToken != "" {
			envVars = append(envVars, 
				map[string]string{"name": "AWS_SESSION_TOKEN", "value": provider.SessionToken})
		}
	case *ProfileCredentialsProvider:
		if provider.Profile != "" && provider.Profile != "default" {
			envVars = append(envVars, 
				map[string]string{"name": "AWS_PROFILE", "value": provider.Profile})
		}
	}

	// 添加区域
	envVars = append(envVars, 
		map[string]string{"name": "AWS_DEFAULT_REGION", "value": skg.config.Region})

	return envVars
}

// ValidateCluster 验证集群是否可访问
func (skg *SDKKubeconfigGenerator) ValidateCluster(ctx context.Context) error {
	if err := skg.initEKSClient(ctx); err != nil {
		return err
	}

	_, err := skg.getClusterInfo(ctx)
	return err
}

// GetClusterEndpoint 获取集群端点
func (skg *SDKKubeconfigGenerator) GetClusterEndpoint(ctx context.Context) (string, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return "", err
	}

	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return "", err
	}

	return *clusterInfo.Cluster.Endpoint, nil
}

// GetClusterCertificate 获取集群CA证书
func (skg *SDKKubeconfigGenerator) GetClusterCertificate(ctx context.Context) ([]byte, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return nil, err
	}

	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return nil, err
	}

	return []byte(*clusterInfo.Cluster.CertificateAuthority.Data), nil
}

// GetClusterVersion 获取集群版本
func (skg *SDKKubeconfigGenerator) GetClusterVersion(ctx context.Context) (string, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return "", err
	}

	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return "", err
	}

	return *clusterInfo.Cluster.Version, nil
}

// GetClusterStatus 获取集群状态
func (skg *SDKKubeconfigGenerator) GetClusterStatus(ctx context.Context) (string, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return "", err
	}

	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return "", err
	}

	return string(clusterInfo.Cluster.Status), nil
}

// GetClusterTags 获取集群标签
func (skg *SDKKubeconfigGenerator) GetClusterTags(ctx context.Context) (map[string]string, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return nil, err
	}

	clusterInfo, err := skg.getClusterInfo(ctx)
	if err != nil {
		return nil, err
	}

	return clusterInfo.Cluster.Tags, nil
}

// ListClusters 列出当前区域的所有EKS集群
func (skg *SDKKubeconfigGenerator) ListClusters(ctx context.Context) ([]string, error) {
	if err := skg.initEKSClient(ctx); err != nil {
		return nil, err
	}

	result, err := skg.eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, NewEKSAuthError(ErrorTypeAWSConfigMissing,
			"failed to list EKS clusters", err)
	}

	return result.Clusters, nil
}

// String 返回生成器描述
func (skg *SDKKubeconfigGenerator) String() string {
	return fmt.Sprintf("SDKKubeconfigGenerator(cluster=%s, region=%s, provider=%s)", 
		skg.config.ClusterName, skg.config.Region, skg.config.CredentialsProvider.GetProviderType())
}