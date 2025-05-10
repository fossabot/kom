package callbacks

import (
	"github.com/weibaohui/kom/kom"
	"k8s.io/klog/v2"
)

func RegisterInit() {
	klog.Infof("RegisterInit")
	kom.Clusters().SetRegisterCallbackFunc(RegisterDefaultCallbacks)
	klog.Infof("Register RegisterDefaultCallbacks func  to clusters")
}
func init() {
	RegisterInit()
}
// RegisterDefaultCallbacks 为指定的集群实例注册一组默认的 Kubernetes 操作回调，包括资源的查询、列表、监控、创建、更新、补丁、删除、命令执行、流式命令执行、端口转发、日志获取和资源描述等操作。
// 返回一个空的清理函数。
func RegisterDefaultCallbacks(c *kom.ClusterInst) func() {

	klog.V(4).Infof("RegisterDefaultCallbacks for cluster %s", c.ID)

	// 为每一个集群进行注册
	k := c.Kubectl

	queryCallback := k.Callback().Get()
	_ = queryCallback.Register("kom:get", Get)

	listCallback := k.Callback().List()
	_ = listCallback.Register("kom:list", List)

	watchCallback := k.Callback().Watch()
	_ = watchCallback.Register("kom:watch", Watch)

	createCallback := k.Callback().Create()
	_ = createCallback.Register("kom:create", Create)

	updateCallback := k.Callback().Update()
	_ = updateCallback.Register("kom:update", Update)

	patchCallback := k.Callback().Patch()
	_ = patchCallback.Register("kom:patch", Patch)

	deleteCallback := k.Callback().Delete()
	_ = deleteCallback.Register("kom:delete", Delete)

	execCallback := k.Callback().Exec()
	_ = execCallback.Register("kom:pod:exec", ExecuteCommand)

	streamExecCallback := k.Callback().StreamExec()
	_ = streamExecCallback.Register("kom:pod:stream:exec", StreamExecuteCommand)

	portForwardCallback := k.Callback().PortForward()
	_ = portForwardCallback.Register("kom:pod:port:forward", PortForward)

	logsCallback := k.Callback().Logs()
	_ = logsCallback.Register("kom:pod:logs", GetLogs)

	describeCallback := k.Callback().Describe()
	_ = describeCallback.Register("kom:describe", Describe)

	return nil
}
