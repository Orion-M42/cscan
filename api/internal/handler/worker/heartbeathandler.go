package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"cscan/api/internal/logic"
	"cscan/api/internal/svc"
	"cscan/pkg/response"
	"cscan/rpc/task/pb"

	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

// ==================== Heartbeat Types ====================

// WorkerHeartbeatReq 心跳请求
type WorkerHeartbeatReq struct {
	WorkerName         string  `json:"workerName"`
	IP                 string  `json:"ip"`
	CpuLoad            float64 `json:"cpuLoad"`
	MemUsed            float64 `json:"memUsed"`
	TaskStartedNumber  int32   `json:"taskStartedNumber"`
	TaskExecutedNumber int32   `json:"taskExecutedNumber"`
	Concurrency        int     `json:"concurrency"`
	IsDaemon           bool    `json:"isDaemon"`
}

// WorkerHeartbeatResp 心跳响应
type WorkerHeartbeatResp struct {
	Code               int    `json:"code"`
	Msg                string `json:"msg"`
	Status             string `json:"status"`
	ManualStopFlag     bool   `json:"manualStopFlag"`
	ManualReloadFlag   bool   `json:"manualReloadFlag"`
	ManualInitEnvFlag  bool   `json:"manualInitEnvFlag"`
	ManualSyncFlag     bool   `json:"manualSyncFlag"`
	DesiredConcurrency int    `json:"desiredConcurrency,omitempty"`
}

// ==================== Heartbeat Handler ====================

// WorkerHeartbeatHandler 心跳接口
// POST /api/v1/worker/heartbeat
func WorkerHeartbeatHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerHeartbeatReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerHeartbeatResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.WorkerName == "" {
			httpx.OkJson(w, &WorkerHeartbeatResp{Code: 400, Msg: "workerName不能为空"})
			return
		}

		// 调用RPC KeepAlive
		rpcReq := &pb.KeepAliveReq{
			WorkerName:         req.WorkerName,
			Ip:                 req.IP,
			CpuLoad:            req.CpuLoad,
			MemUsed:            req.MemUsed,
			TaskStartedNumber:  req.TaskStartedNumber,
			TaskExecutedNumber: req.TaskExecutedNumber,
			IsDaemon:           req.IsDaemon,
		}

		rpcResp, err := svcCtx.TaskRpcClient.KeepAlive(r.Context(), rpcReq)
		if err != nil {
			logx.Errorf("[WorkerHeartbeat] RPC KeepAlive error: %v", err)
			response.Error(w, err)
			return
		}

		// 额外更新 concurrency 到 Redis（因为 proto 中没有这个字段）
		if req.Concurrency > 0 {
			workerKey := "cscan:worker:" + req.WorkerName
			// 获取现有数据并更新 concurrency
			existingData, err := svcCtx.RedisClient.Get(r.Context(), workerKey).Result()
			if err == nil {
				var workerData map[string]interface{}
				if json.Unmarshal([]byte(existingData), &workerData) == nil {
					workerData["concurrency"] = req.Concurrency
					updatedJson, _ := json.Marshal(workerData)
					svcCtx.RedisClient.Set(r.Context(), workerKey, updatedJson, 60*time.Second)
				}
			}
		}

		// 读取期望并发数（由管理端设置，持久化无TTL），下发给Worker
		desiredConcurrency := 0
		desiredKey := fmt.Sprintf("cscan:worker:desired_concurrency:%s", req.WorkerName)
		if val, err := svcCtx.RedisClient.Get(r.Context(), desiredKey).Int(); err == nil && val > 0 {
			desiredConcurrency = val
		}

		httpx.OkJson(w, &WorkerHeartbeatResp{
			Code:               0,
			Msg:                "success",
			Status:             rpcResp.Status,
			ManualStopFlag:     rpcResp.ManualStopFlag,
			ManualReloadFlag:   rpcResp.ManualReloadFlag,
			ManualInitEnvFlag:  rpcResp.ManualInitEnvFlag,
			ManualSyncFlag:     rpcResp.ManualSyncFlag,
			DesiredConcurrency: desiredConcurrency,
		})
	}
}

// ==================== Offline Types ====================

// WorkerOfflineReq Worker离线通知请求
type WorkerOfflineReq struct {
	WorkerName string `json:"workerName"`
}

// WorkerOfflineResp Worker离线通知响应
type WorkerOfflineResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
}

// ==================== Offline Handler ====================

// WorkerOfflineHandler Worker离线通知接口
// POST /api/v1/worker/offline
// Worker停止时调用此接口，立即删除Redis中的状态数据
func WorkerOfflineHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req WorkerOfflineReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.OkJson(w, &WorkerOfflineResp{Code: 400, Msg: "参数解析失败"})
			return
		}

		if req.WorkerName == "" {
			httpx.OkJson(w, &WorkerOfflineResp{Code: 400, Msg: "workerName不能为空"})
			return
		}

		rdb := svcCtx.RedisClient

		// 删除Worker状态数据
		workerKey := fmt.Sprintf("cscan:worker:%s", req.WorkerName)
		rdb.Del(r.Context(), workerKey)

		// 从Worker集合中移除
		rdb.SRem(r.Context(), "cscan:workers", req.WorkerName)

		// 删除控制命令（如果有）
		controlKey := fmt.Sprintf("cscan:worker:control:%s", req.WorkerName)
		rdb.Del(r.Context(), controlKey)

		logx.Infof("[WorkerOffline] Worker %s offline, deleted from Redis", req.WorkerName)

		// 立即恢复该 Worker 处理中的任务（使用独立 context，不受 HTTP 连接断开影响）
		recoverCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		recoveredTasks, err := logic.RecoverWorkerTasks(recoverCtx, svcCtx, req.WorkerName)
		if err != nil {
			logx.Errorf("[WorkerOffline] Failed to recover tasks for worker %s: %v", req.WorkerName, err)
		} else if len(recoveredTasks) > 0 {
			logx.Infof("[WorkerOffline] Worker %s: recovered %d orphaned tasks", req.WorkerName, len(recoveredTasks))
		}

		httpx.OkJson(w, &WorkerOfflineResp{
			Code:    0,
			Msg:     "success",
			Success: true,
		})
	}
}
