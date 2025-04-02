package dynamic

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/weibaohui/kom/kom"
	"github.com/weibaohui/kom/mcp/metadata"
	"github.com/weibaohui/kom/utils"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ListDynamicResource() mcp.Tool {
	return mcp.NewTool(
		"list_k8s_resource",
		mcp.WithDescription("List Kubernetes resources by cluster and resource type / 按集群和资源类型列出Kubernetes资源，获取列表"),
		mcp.WithString("cluster", mcp.Description("Cluster where the resources are running (use empty string for default cluster) / 运行资源的集群（使用空字符串表示默认集群）")),
		mcp.WithString("namespace", mcp.Description("Namespace of the resources (optional for cluster-scoped resources) / 资源所在的命名空间（集群范围资源可选）")),
		mcp.WithString("group", mcp.Description("API group of the resource / 资源的API组")),
		mcp.WithString("version", mcp.Description("API version of the resource / 资源的API版本")),
		mcp.WithString("kind", mcp.Description("Kind of the resource / 资源的类型")),
		mcp.WithString("label", mcp.Description("Label selector to filter resources (e.g. app=k8m) / 用于过滤资源的标签选择器（例如：app=k8m）")),
		mcp.WithString("field", mcp.Description("Field selector to filter resources (e.g. metadata.name=test-deploy) / 用于过滤资源的字段选择器（例如：metadata.name=test-deploy）")),
	)
}

func ListDynamicResourceHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	// 获取资源元数据
	ctx, meta, err := metadata.ParseFromRequest(ctx, request, config)

	if err != nil {
		return nil, err
	}

	// 获取标签选择器和字段选择器
	label, _ := request.Params.Arguments["label"].(string)
	field, _ := request.Params.Arguments["field"].(string)

	// 获取资源列表
	var list []*unstructured.Unstructured
	kubectl := kom.Cluster(meta.Cluster).WithContext(ctx).CRD(meta.Group, meta.Version, meta.Kind).Namespace(meta.Namespace).RemoveManagedFields()
	if meta.Namespace == "" {
		kubectl = kubectl.AllNamespace()
	}
	if label != "" {
		kubectl = kubectl.WithLabelSelector(label)
	}
	if field != "" {
		kubectl = kubectl.WithFieldSelector(field)
	}
	err = kubectl.List(&list).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list items type of [%s%s%s]: %v", meta.Group, meta.Version, meta.Kind, err)
	}

	// 提取name和namespace信息
	var result []map[string]string
	for _, item := range list {
		ret := map[string]string{
			"name": item.GetName(),
		}
		if item.GetNamespace() != "" {
			ret["namespace"] = item.GetNamespace()
		}

		result = append(result, ret)
	}

	return utils.TextResult(result, meta)
}
