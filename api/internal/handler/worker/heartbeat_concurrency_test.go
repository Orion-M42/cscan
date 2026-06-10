package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cscan/api/internal/svc"
	"cscan/rpc/task/pb"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type stubTaskRpcClient struct {
	pb.TaskServiceClient
}

func (s *stubTaskRpcClient) KeepAlive(ctx context.Context, in *pb.KeepAliveReq, opts ...grpc.CallOption) (*pb.KeepAliveResp, error) {
	return &pb.KeepAliveResp{Status: "online"}, nil
}

func newHeartbeatTestContext(t *testing.T) (*svc.ServiceContext, *miniredis.Miniredis) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &svc.ServiceContext{
		RedisClient:   rdb,
		TaskRpcClient: &stubTaskRpcClient{},
	}, mr
}

func doHeartbeat(t *testing.T, svcCtx *svc.ServiceContext, workerName string) *WorkerHeartbeatResp {
	body, err := json.Marshal(&WorkerHeartbeatReq{WorkerName: workerName, Concurrency: 5})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/worker/heartbeat", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	WorkerHeartbeatHandler(svcCtx)(rec, req)

	var resp WorkerHeartbeatResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return &resp
}

func TestHeartbeatReturnsDesiredConcurrency(t *testing.T) {
	svcCtx, mr := newHeartbeatTestContext(t)

	require.NoError(t, mr.Set("cscan:worker:desired_concurrency:w1", "20"))

	resp := doHeartbeat(t, svcCtx, "w1")
	assert.Equal(t, 0, resp.Code)
	assert.Equal(t, 20, resp.DesiredConcurrency)
}

func TestHeartbeatWithoutDesiredConcurrency(t *testing.T) {
	svcCtx, _ := newHeartbeatTestContext(t)

	resp := doHeartbeat(t, svcCtx, "w1")
	assert.Equal(t, 0, resp.Code)
	assert.Equal(t, 0, resp.DesiredConcurrency)
}

func TestHeartbeatIgnoresInvalidDesiredConcurrency(t *testing.T) {
	svcCtx, mr := newHeartbeatTestContext(t)

	require.NoError(t, mr.Set("cscan:worker:desired_concurrency:w1", "not-a-number"))

	resp := doHeartbeat(t, svcCtx, "w1")
	assert.Equal(t, 0, resp.Code)
	assert.Equal(t, 0, resp.DesiredConcurrency)
}
