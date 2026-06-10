package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cscan/model"
	"cscan/pkg/geolocation"
	"cscan/pkg/mapping"
	"cscan/pkg/utils"
	"cscan/scanner"
	"cscan/scanner/brute"
	"cscan/scheduler"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/zeromicro/go-zero/core/logx"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// WorkerConfig Worker配置
type WorkerConfig struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	ServerAddr  string `json:"serverAddr"` // API 服务地址 (e.g., http://server:8888)
	InstallKey  string `json:"installKey"` // 安装密钥
	Concurrency int    `json:"concurrency"`
	Timeout     int    `json:"timeout"`
}

// Worker 工作节点
type Worker struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     WorkerConfig
	httpClient *WorkerHTTPClient // HTTP 客户端（替代 RPC 和 Redis）
	wsClient   *WorkerWSClient   // WebSocket 客户端（用于日志推送和控制信号）
	scanners   map[string]scanner.Scanner
	taskChan   chan *scheduler.TaskInfo
	resultChan chan *scanner.ScanResult
	stopChan   chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	mu         sync.Mutex

	taskStarted   int
	taskExecuted  int
	isRunning     bool
	executorCount int // 已启动的任务处理协程数

	// 健康状态监控
	lastCPUCheck     time.Time // 上次CPU检查时间
	cpuOverloadCount int       // CPU过载计数
	isThrottled      bool      // 是否处于限流状态
	throttleUntil    time.Time // 限流结束时间

	// 任务控制信号
	taskControlSignals sync.Map // taskId -> action (STOP, PAUSE)

	// 正在执行的任务
	runningTasks sync.Map // taskId -> true

	// 日志组件
	logger Logger

	// 系统信息收集器
	sysInfoCollector *SysInfoCollector

	// 文件管理器
	fileManager *FileManager

	// 终端处理器
	terminalHandler *TerminalHandler

	// 资源管理器（旧版，保留兼容）
	resourceManager *ResourceManager

	// 自适应调度器（新版智能调度）
	adaptiveScheduler *AdaptiveScheduler

	// 任务执行器集成
	taskRunnerIntegration *TaskRunnerIntegration

	// 本地结果队列（API 不可用时持久化任务结果）
	resultQueue *ResultQueue

	// 活跃任务的日志记录器（维持 buffer 生命周期）
	taskLoggers sync.Map // mainTaskId -> *TaskLoggerWS
}

// getMainTaskId 从 taskId 中提取主任务ID
// 子任务格式: {mainTaskId}-{index}，主任务格式: {mainTaskId}
func getMainTaskId(taskId string) string {
	// 查找最后一个 "-" 后面是否是数字
	lastDash := strings.LastIndex(taskId, "-")
	if lastDash > 0 && lastDash < len(taskId)-1 {
		suffix := taskId[lastDash+1:]
		// 检查后缀是否全是数字
		isNumber := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				isNumber = false
				break
			}
		}
		if isNumber {
			return taskId[:lastDash]
		}
	}
	return taskId
}

// taskLog 发布任务级别日志
// 子任务的日志会同时写入主任务的日志流，方便统一查看
func (w *Worker) taskLog(taskId, level, format string, args ...interface{}) {
	mainTaskId := getMainTaskId(taskId)

	if mainTaskId != taskId {
		subIndex := taskId[len(mainTaskId)+1:]
		format = fmt.Sprintf("[Sub-%s] %s", subIndex, format)
	}

	// 从 map 获取持久化的 logger 实例，仅在首次时创建
	val, ok := w.taskLoggers.Load(mainTaskId)
	if !ok {
		newLogger := NewTaskLoggerWS(w.config.Name, mainTaskId, w.wsClient)
		val, _ = w.taskLoggers.LoadOrStore(mainTaskId, newLogger)
	}
	logger := val.(*TaskLoggerWS)

	switch level {
	case LevelError:
		logger.Error(format, args...)
	case LevelWarn:
		logger.Warn(format, args...)
	case LevelDebug:
		logger.Debug(format, args...)
	default:
		logger.Info(format, args...)
	}
}

// cleanupTaskLogger 清理任务日志记录器，flush 残余缓冲
func (w *Worker) cleanupTaskLogger(taskId string) {
	mainTaskId := getMainTaskId(taskId)
	if val, loaded := w.taskLoggers.LoadAndDelete(mainTaskId); loaded {
		logger := val.(*TaskLoggerWS)
		logger.flushBuffer()
	}
}

// VulnerabilityBuffer 批量缓冲保存漏洞
// AssetBuffer 批量缓冲保存资产
type AssetBuffer struct {
	assets    []*scanner.Asset
	mu        sync.Mutex
	maxSize   int
	flushChan chan struct{}
}

// NewAssetBuffer 创建资产缓冲区
func NewAssetBuffer(maxSize int) *AssetBuffer {
	return &AssetBuffer{
		assets:    make([]*scanner.Asset, 0, maxSize),
		maxSize:   maxSize,
		flushChan: make(chan struct{}, 1),
	}
}

// GetFlushChan 返回刷新信号通道，供外层 select 监听
func (b *AssetBuffer) GetFlushChan() <-chan struct{} {
	return b.flushChan
}

// Add 添加资产到缓冲区，如果达到 maxSize 则触发刷新
func (b *AssetBuffer) Add(asset *scanner.Asset) {
	b.mu.Lock()
	b.assets = append(b.assets, asset)
	shouldFlush := len(b.assets) >= b.maxSize
	b.mu.Unlock()

	if shouldFlush {
		select {
		case b.flushChan <- struct{}{}:
		default:
		}
	}
}

// Flush 刷新缓冲区，批量保存
func (b *AssetBuffer) Flush(ctx context.Context, saver func([]*scanner.Asset)) {
	b.mu.Lock()
	assets := b.assets
	b.assets = nil
	b.mu.Unlock()

	if len(assets) > 0 {
		saver(assets) // 批量保存
	}
}

type VulnerabilityBuffer struct {
	vuls      []*scanner.Vulnerability
	mu        sync.Mutex
	maxSize   int
	flushChan chan struct{}
}

// NewVulnerabilityBuffer 创建漏洞缓冲区
func NewVulnerabilityBuffer(maxSize int) *VulnerabilityBuffer {
	return &VulnerabilityBuffer{
		vuls:      make([]*scanner.Vulnerability, 0, maxSize),
		maxSize:   maxSize,
		flushChan: make(chan struct{}, 1),
	}
}

// Add 添加漏洞到缓冲区，返回是否需要刷新
func (b *VulnerabilityBuffer) Add(vul *scanner.Vulnerability) {
	b.mu.Lock()
	b.vuls = append(b.vuls, vul)
	shouldFlush := len(b.vuls) >= b.maxSize
	b.mu.Unlock()

	if shouldFlush {
		select {
		case b.flushChan <- struct{}{}:
		default:
		}
	}
}

// Flush 刷新缓冲区，批量保存
func (b *VulnerabilityBuffer) Flush(ctx context.Context, saver func([]*scanner.Vulnerability)) {
	b.mu.Lock()
	vuls := b.vuls
	b.vuls = nil
	b.mu.Unlock()

	if len(vuls) > 0 {
		saver(vuls) // 批量保存
	}
}

// NewWorker 创建Worker
func NewWorker(config WorkerConfig) (*Worker, error) {
	// 自动获取本机IP地址
	if config.IP == "" {
		config.IP = GetLocalIP()
	}

	// 创建 HTTP 客户端（替代 RPC 和 Redis）
	httpClient := NewWorkerHTTPClient(config.ServerAddr, config.InstallKey, config.Name)

	logx.Infof("[Worker] HTTP client created, API server: %s", config.ServerAddr)

	// 创建可取消的Context
	ctx, cancel := context.WithCancel(context.Background())

	// Worker版本号
	workerVersion := "1.0.0"

	w := &Worker{
		ctx:              ctx,
		cancel:           cancel,
		config:           config,
		httpClient:       httpClient,
		scanners:         make(map[string]scanner.Scanner),
		taskChan:         make(chan *scheduler.TaskInfo, config.Concurrency),
		resultChan:       make(chan *scanner.ScanResult, 100),
		stopChan:         make(chan struct{}),
		logger:           NewWorkerLoggerLocal(config.Name), // 使用本地日志
		sysInfoCollector: NewSysInfoCollector(config.Name, config.IP, workerVersion),
	}

	// 创建 WebSocket 客户端
	wsConfig := DefaultWSClientConfig(config.ServerAddr, config.Name, config.InstallKey)
	w.wsClient = NewWorkerWSClient(wsConfig)

	// 更新 logger 为 WebSocket 版本，将日志发送到服务器
	w.logger = NewWorkerLoggerWS(config.Name, w.wsClient)

	// 设置控制信号处理函数
	w.wsClient.SetControlHandler(func(taskId, action string) {
		w.handleControlSignal(taskId, action)
	})

	// 设置 Worker 级别控制处理函数
	w.wsClient.SetWorkerControlHandler(func(action, param string) {
		w.handleWorkerControl(action, param)
	})

	// 设置Worker信息请求处理函数
	w.wsClient.SetWorkerInfoHandler(func() *WorkerInfoPayload {
		return w.GetWorkerInfo()
	})

	// 创建文件管理器并设置到WebSocket客户端
	w.fileManager = NewFileManager(nil) // 使用默认配置
	w.wsClient.SetFileHandler(w.fileManager)

	// 创建终端处理器并设置到WebSocket客户端
	w.terminalHandler = NewTerminalHandler(nil) // 使用默认配置
	w.wsClient.SetTerminalHandler(w.terminalHandler)

	// 设置终端输出回调，将输出发送到WebSocket
	w.terminalHandler.SetOutputHandler(func(sessionId string, data []byte) {
		w.wsClient.SendTerminalOutput(sessionId, data)
	})

	// 创建资源管理器（旧版，保留兼容）
	w.resourceManager = NewResourceManager(config.Concurrency)

	// 创建自适应调度器（新版智能调度）
	adaptiveConfig := DefaultAdaptiveSchedulerConfig(config.Concurrency)
	w.adaptiveScheduler = NewAdaptiveScheduler(adaptiveConfig)
	w.adaptiveScheduler.SetLogger(func(level, format string, args ...interface{}) {
		w.logger.Info("[Scheduler] "+format, args...)
	})

	// 注册扫描器
	w.registerScanners()

	// 初始化 IP 地理位置服务
	w.initGeolocation()

	// 初始化自适应扫描配置（根据系统硬件自动调整扫描器参数）
	adaptiveCfg := scanner.GetGlobalAdaptiveConfig()
	logx.Infof("[Worker] Adaptive scan config initialized: profile=%s, CPU=%d cores, Mem=%d MB",
		adaptiveCfg.Profile, adaptiveCfg.CPUCores, adaptiveCfg.TotalMemoryMB)

	// 创建任务执行器集成（在扫描器注册后）
	w.taskRunnerIntegration = NewTaskRunnerIntegration(w)
	w.taskRunnerIntegration.RegisterDefaultExecutors()

	// 加载HTTP服务映射配置
	w.loadHttpServiceMappings()

	// 创建本地结果队列
	resultQueueDir := filepath.Join("data", "result_queue")
	w.resultQueue = NewResultQueue(resultQueueDir, 200, func(ctx context.Context, req *TaskResultReq) error {
		_, err := w.httpClient.SaveTaskResult(ctx, req)
		return err
	})
	w.resultQueue.SetLogger(func(level, format string, args ...interface{}) {
		w.logger.Info("[ResultQueue] "+format, args...)
	})

	return w, nil
}

// handleControlSignal 处理控制信号
func (w *Worker) handleControlSignal(taskId, action string) {
	// 检查信号是否已存在，避免重复处理（防止日志刷屏）
	if existingAction, loaded := w.taskControlSignals.Load(taskId); loaded {
		if existingAction == action {
			// 信号已存在且值相同，跳过
			return
		}
	}

	w.logger.Info("Received control signal: taskId=%s, action=%s", taskId, action)

	// 存储控制信号
	w.taskControlSignals.Store(taskId, action)
	w.logger.Info("Stored control signal for task %s: %s", taskId, action)

	// 如果是STOP或PAUSE信号，也存储到主任务ID
	mainTaskId := getMainTaskId(taskId)
	if mainTaskId != taskId {
		// 检查主任务ID的信号是否已存在
		if existingAction, loaded := w.taskControlSignals.Load(mainTaskId); loaded {
			if existingAction == action {
				// 主任务信号已存在且值相同，跳过
				return
			}
		}
		w.taskControlSignals.Store(mainTaskId, action)
		w.logger.Info("Also stored control signal for main task %s: %s", mainTaskId, action)
	}
}

// handleWorkerControl 处理 Worker 级别控制命令
func (w *Worker) handleWorkerControl(action, param string) {
	w.logger.Info("Received worker control: action=%s, param=%s", action, param)

	switch action {
	case "stop":
		w.logger.Info("Stopping worker via WebSocket command...")
		// 在新 goroutine 中执行停止，避免死锁（因为当前在 WebSocket 读取 goroutine 中）
		go func() {
			w.StopImmediate()
			os.Exit(0)
		}()
	case "restart":
		w.logger.Info("Restarting worker via WebSocket command...")
		// 在新 goroutine 中执行重启
		go func() {
			w.StopImmediate()
			w.restartSelf()
		}()
	case "rename":
		w.logger.Info("Renaming worker to: %s", param)
		w.config.Name = param
		// 更新日志前缀（使用 WebSocket 版本）
		w.logger = NewWorkerLoggerWS(param, w.wsClient)
		// 立即发送心跳，让服务端更新状态
		go w.sendHeartbeat()
	case "setConcurrency":
		newConcurrency, err := strconv.Atoi(param)
		if err != nil || newConcurrency < 1 {
			w.logger.Error("Invalid concurrency value: %s", param)
			return
		}
		w.applyConcurrency(newConcurrency)
		// 立即发送心跳，让服务端更新状态
		go w.sendHeartbeat()
	default:
		w.logger.Warn("Unknown worker control action: %s", action)
	}
}

// applyConcurrency 应用新的并发数：同步配置、资源管理器与自适应调度器，按需补启执行协程
// 调小并发时由调度器限流门自然收敛，多余协程保持空闲
func (w *Worker) applyConcurrency(newConcurrency int) {
	if newConcurrency < 1 {
		return
	}

	w.mu.Lock()
	if w.config.Concurrency == newConcurrency {
		w.mu.Unlock()
		return
	}
	w.config.Concurrency = newConcurrency
	spawn := 0
	startId := w.executorCount
	if w.isRunning && newConcurrency > w.executorCount {
		spawn = newConcurrency - w.executorCount
		w.executorCount = newConcurrency
	}
	w.mu.Unlock()

	if w.resourceManager != nil {
		w.resourceManager.SetMaxConcurrency(newConcurrency)
	}
	if w.adaptiveScheduler != nil {
		w.adaptiveScheduler.SetMaxConcurrency(newConcurrency)
	}

	for i := 0; i < spawn; i++ {
		w.wg.Add(1)
		go w.processTaskWithRecovery(startId + i)
	}

	w.logger.Info("Concurrency applied: %d (spawned %d new executors)", newConcurrency, spawn)
}

// restartSelf 重新执行自身
func (w *Worker) restartSelf() {
	// 获取当前可执行文件路径
	executable, err := os.Executable()
	if err != nil {
		w.logger.Error("Failed to get executable path: %v", err)
		os.Exit(1)
	}

	// 获取命令行参数
	args := os.Args

	w.logger.Info("Restarting worker: %s %v", executable, args[1:])

	// 等待一小段时间确保资源释放
	time.Sleep(500 * time.Millisecond)

	// 使用平台特定的重启方式
	platformRestart(executable, args, w.logger)
}

// ClearTaskControlSignal 清除任务控制信号（任务完成后调用）
func (w *Worker) ClearTaskControlSignal(taskId string) {
	w.taskControlSignals.Delete(taskId)
	mainTaskId := getMainTaskId(taskId)
	if mainTaskId != taskId {
		w.taskControlSignals.Delete(mainTaskId)
	}
}

// GetWorkerInfo 获取Worker详细信息
func (w *Worker) GetWorkerInfo() *WorkerInfoPayload {
	w.mu.Lock()
	taskStarted := w.taskStarted
	taskExecuted := w.taskExecuted
	concurrency := w.config.Concurrency
	w.mu.Unlock()

	// 计算正在运行的任务数
	taskRunning := taskStarted - taskExecuted
	if taskRunning < 0 {
		taskRunning = 0
	}

	return w.sysInfoCollector.Collect(taskStarted, taskRunning, concurrency)
}

// GetSchedulerStats 获取调度器统计信息
func (w *Worker) GetSchedulerStats() *SchedulerStats {
	if w.adaptiveScheduler != nil {
		stats := w.adaptiveScheduler.GetStats()
		return &stats
	}
	return nil
}

// GetScannerConfigRecommendation 获取扫描器配置建议
func (w *Worker) GetScannerConfigRecommendation() *ScannerConfigRecommendation {
	if w.adaptiveScheduler != nil {
		config := w.adaptiveScheduler.GetScannerConfig()
		return &config
	}
	return nil
}

// registerScanners 注册扫描器
func (w *Worker) registerScanners() {
	w.scanners["portscan"] = scanner.NewPortScanner()
	w.scanners["masscan"] = scanner.NewMasscanScanner()
	w.scanners["nmap"] = scanner.NewNmapScanner()
	w.scanners["fingerprintx"] = scanner.NewFingerprintxScanner()
	w.scanners["naabu"] = scanner.NewNaabuScanner()
	w.scanners["subfinder"] = scanner.NewSubfinderScanner()
	w.scanners["subdomain_bruteforce"] = scanner.NewSubdomainBruteforceScanner()
	w.scanners["fingerprint"] = scanner.NewFingerprintScanner()
	w.scanners["nuclei"] = scanner.NewNucleiScanner()
	w.scanners["urlfinder"] = scanner.NewURLFinderScanner()
	w.scanners["ffuf"] = scanner.NewFFufScanner()
	w.scanners["brutescan"] = scanner.NewBruteScanScanner()
	w.scanners["jsfinder"] = scanner.NewJSFinderScanner()
}

// Start 启动Worker
func (w *Worker) Start() {
	w.isRunning = true

	// 启动自适应调度器
	if w.adaptiveScheduler != nil {
		w.adaptiveScheduler.Start()
	}

	// 启动本地结果队列
	if w.resultQueue != nil {
		if err := w.resultQueue.Start(w.ctx); err != nil {
			w.logger.Warn("Result queue failed to start: %v", err)
		}
	}

	// 启动 WebSocket 客户端（用于日志推送和控制信号）
	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.logger.Error("WebSocket client goroutine panic recovered: %v", r)
			}
		}()
		if err := w.wsClient.Start(w.ctx); err != nil {
			w.logger.Warn("WebSocket client failed to start: %v, falling back to HTTP polling", err)
		} else {
			w.logger.Info("WebSocket client started")
		}
	}()

	// 等待 WebSocket 连接成功（最多等待 5 秒）
	for i := 0; i < 50; i++ {
		if w.wsClient.IsConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Worker 启动时恢复之前未完成的任务
	w.recoverOrphanedTasks()

	// 启动任务处理协程
	for i := 0; i < w.config.Concurrency; i++ {
		w.wg.Add(1)
		go w.processTaskWithRecovery(i)
	}
	w.mu.Lock()
	w.executorCount = w.config.Concurrency
	w.mu.Unlock()

	// 启动任务拉取协程
	w.wg.Add(1)
	go w.fetchTasksWithRecovery()

	// 启动结果上报协程
	w.wg.Add(1)
	go w.reportResultWithRecovery()

	// 启动心跳协程
	w.wg.Add(1)
	go w.keepAliveWithRecovery()

	// 启动 HTTP 轮询回退（当 WebSocket 不可用时）
	w.wg.Add(1)
	go w.controlPollingWithRecovery()

	w.logger.Info("Worker %s started with %d workers", w.config.Name, w.config.Concurrency)
}

// processTaskWithRecovery 带 panic 恢复的任务处理
func (w *Worker) processTaskWithRecovery(workerId int) {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopChan:
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("Task processor %d panic recovered: %v, stack: %s", workerId, r, string(getStackTrace()))
				}
			}()
			w.processTaskLoop()
		}()

		// 如果 processTaskLoop 正常返回（stopChan 关闭），退出
		select {
		case <-w.stopChan:
			return
		default:
			// panic 恢复后短暂等待再重启
			time.Sleep(time.Second)
			w.logger.Info("Task processor %d restarting after recovery", workerId)
		}
	}
}

// processTaskLoop 任务处理循环（内部方法）
func (w *Worker) processTaskLoop() {
	for {
		select {
		case <-w.stopChan:
			w.logger.Info("processTaskLoop: received stop signal, exiting")
			return
		case task := <-w.taskChan:
			w.logger.Info("processTaskLoop: received task %s from channel", task.TaskId)
			// 在执行前检查任务是否已被停止
			ctx := context.Background()
			if ctrl := w.checkTaskControl(ctx, task.TaskId); ctrl == "STOP" {
				w.taskLog(task.TaskId, LevelInfo, "Task %s skipped because it was stopped while waiting in queue", task.TaskId)
				w.cleanupTaskLogger(task.TaskId)
				// 队列内被丢弃时一次性发出本批次应有的全部增量，避免 sub_task_done 永远到不了 sub_task_count
				w.incrSubTaskDone(ctx, task, "完成", true, w.expectedTaskIncr(task.Config))
				continue
			}
			w.logger.Info("processTaskLoop: calling executeTask for task %s", task.TaskId)
			w.executeTask(task)
			w.logger.Info("processTaskLoop: executeTask completed for task %s", task.TaskId)
		}
	}
}

// fetchTasksWithRecovery 带 panic 恢复的任务拉取
func (w *Worker) fetchTasksWithRecovery() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopChan:
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("Task fetcher panic recovered: %v", r)
				}
			}()
			w.fetchTasksLoop()
		}()

		select {
		case <-w.stopChan:
			return
		default:
			time.Sleep(time.Second)
			w.logger.Info("Task fetcher restarting after recovery")
		}
	}
}

// fetchTasksLoop 任务拉取循环（内部方法）
// 使用自适应调度器动态调整拉取间隔
func (w *Worker) fetchTasksLoop() {
	for {
		select {
		case <-w.stopChan:
			return
		default:
			hasTask := w.pullTask()

			// 使用自适应调度器获取动态拉取间隔
			var interval time.Duration
			if w.adaptiveScheduler != nil {
				interval = w.adaptiveScheduler.GetPullInterval()
				if hasTask {
					// 有任务时使用较短间隔
					interval = interval / 2
					if interval < 50*time.Millisecond {
						interval = 50 * time.Millisecond
					}
				}
			} else {
				// 回退到固定间隔
				if hasTask {
					interval = 100 * time.Millisecond
				} else {
					interval = 500 * time.Millisecond
				}
			}

			time.Sleep(interval)
		}
	}
}

// reportResultWithRecovery 带 panic 恢复的结果上报
func (w *Worker) reportResultWithRecovery() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopChan:
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("Result reporter panic recovered: %v", r)
				}
			}()
			w.reportResultLoop()
		}()

		select {
		case <-w.stopChan:
			return
		default:
			time.Sleep(time.Second)
			w.logger.Info("Result reporter restarting after recovery")
		}
	}
}

// keepAliveWithRecovery 带 panic 恢复的心跳
func (w *Worker) keepAliveWithRecovery() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopChan:
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("Keepalive panic recovered: %v", r)
				}
			}()
			w.keepAliveLoop()
		}()

		select {
		case <-w.stopChan:
			return
		default:
			time.Sleep(time.Second)
			w.logger.Info("Keepalive restarting after recovery")
		}
	}
}

// controlPollingWithRecovery 带 panic 恢复的控制轮询
func (w *Worker) controlPollingWithRecovery() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopChan:
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("Control polling panic recovered: %v", r)
				}
			}()
			w.controlPollingLoop()
		}()

		select {
		case <-w.stopChan:
			return
		default:
			time.Sleep(time.Second)
			w.logger.Info("Control polling restarting after recovery")
		}
	}
}

// getStackTrace 获取堆栈跟踪
func getStackTrace() []byte {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return buf[:n]
}

// pullTask 拉取单个任务，返回是否获取到任务
func (w *Worker) pullTask() bool {
	ctx := context.Background()

	// 检查是否有空闲槽位
	if len(w.taskChan) >= w.config.Concurrency {
		return false
	}

	// 优先使用自适应调度器检查是否可以接受新任务
	if w.adaptiveScheduler != nil {
		if !w.adaptiveScheduler.CanAcceptTask() {
			return false
		}
	} else if w.resourceManager != nil {
		// 回退到旧版资源管理器
		if !w.resourceManager.CanAcceptTask() {
			return false
		}
	} else if w.isCPUOverloaded() {
		// 最后回退到简单的CPU检查
		return false
	}

	// 通过 HTTP 接口获取任务
	resp, err := w.httpClient.CheckTask(ctx)
	if err != nil {
		w.logger.Debug("pullTask: CheckTask failed: %v", err)
		return false
	}

	if resp.IsExist && !resp.IsFinished {
		// 有待执行的任务
		w.logger.Info("pullTask: got task %s (main: %s)", resp.TaskId, resp.MainTaskId)
		task := &scheduler.TaskInfo{
			TaskId:      resp.TaskId,
			MainTaskId:  resp.MainTaskId,
			WorkspaceId: resp.WorkspaceId,
			TaskName:    "scan",
			Config:      resp.Config,
		}
		w.logger.Info("pullTask: pushing task %s to taskChan (channel size: %d/%d)", task.TaskId, len(w.taskChan), cap(w.taskChan))
		w.taskChan <- task
		w.logger.Info("pullTask: task %s pushed to taskChan successfully", task.TaskId)
		return true
	}
	return false
}

// recoverOrphanedTasks Worker 启动时恢复之前未完成的任务
func (w *Worker) recoverOrphanedTasks() {
	w.logger.Info("Checking for orphaned tasks to recover...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := w.httpClient.RecoverTasks(ctx)
	if err != nil {
		w.logger.Warn("Failed to recover orphaned tasks: %v", err)
		return
	}

	if resp.RecoveredCount > 0 {
		w.logger.Info("Recovered %d orphaned tasks:", resp.RecoveredCount)
		for _, task := range resp.RecoveredTasks {
			w.logger.Info("  - Task %s (workspace: %s, status: %s)", task.TaskId, task.WorkspaceId, task.Status)
		}
	} else {
		w.logger.Info("No orphaned tasks found")
	}
}

// Stop 停止Worker
func (w *Worker) Stop() {
	w.isRunning = false

	// 停止自适应调度器
	if w.adaptiveScheduler != nil {
		w.adaptiveScheduler.Stop()
	}

	// 停止本地结果队列
	if w.resultQueue != nil {
		w.resultQueue.Stop()
	}

	// 通知服务器Worker即将离线，删除Redis状态数据
	w.notifyOffline()

	w.cancel()
	w.stopOnce.Do(func() { close(w.stopChan) })

	// 关闭 WebSocket 客户端
	if w.wsClient != nil {
		w.wsClient.Close()
	}

	w.wg.Wait()
	w.logger.Info("Worker %s stopped", w.config.Name)
}

// StopImmediate 立即停止Worker（跳过当前任务，不等待完成）
func (w *Worker) StopImmediate() {
	w.isRunning = false

	// 停止自适应调度器
	if w.adaptiveScheduler != nil {
		w.adaptiveScheduler.Stop()
	}

	// 通知服务器Worker即将离线，删除Redis状态数据
	w.notifyOffline()

	w.cancel()
	w.stopOnce.Do(func() { close(w.stopChan) })

	// 关闭 WebSocket 客户端
	if w.wsClient != nil {
		w.wsClient.Close()
	}

	// 不等待 wg.Wait()，立即返回，跳过当前正在执行的任务
	w.logger.Info("Worker %s stopped immediately (tasks skipped)", w.config.Name)
}

// notifyOffline 通知服务器Worker即将离线
func (w *Worker) notifyOffline() {
	if w.httpClient == nil {
		return
	}

	// 使用独立的context，不受w.ctx取消影响
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := w.httpClient.NotifyOffline(ctx)
	if err != nil {
		w.logger.Warn("Failed to notify server about offline: %v", err)
	} else {
		w.logger.Info("Notified server about offline")
	}
}

// SubmitTask 提交任务
func (w *Worker) SubmitTask(task *scheduler.TaskInfo) {
	w.taskChan <- task
}

// checkTaskControl 检查任务控制信号
// 返回: "PAUSE" - 暂停, "STOP" - 停止, "" - 继续执行

// handleTaskControl 统一处理任务控制信号(STOP/PAUSE)
// 返回 true 表示任务被中止或暂停，调用方应直接 return
func (w *Worker) handleTaskControl(ctx context.Context, task *scheduler.TaskInfo, completedPhases map[string]bool, assets []*scanner.Asset, phaseName string) bool {
	if ctrl := w.checkTaskControl(ctx, task.TaskId); ctrl == "STOP" {
		if phaseName != "" {
			w.taskLog(task.TaskId, LevelInfo, "Task stopped during %s", phaseName)
		} else {
			w.taskLog(task.TaskId, LevelInfo, "Task stopped")
		}
		return true
	} else if ctrl == "PAUSE" {
		if phaseName != "" {
			w.taskLog(task.TaskId, LevelInfo, "Task paused during %s, saving progress...", phaseName)
		} else {
			w.taskLog(task.TaskId, LevelInfo, "Task paused, saving progress...")
		}
		w.saveTaskProgress(ctx, task, completedPhases, assets)
		return true
	}
	return false
}

func (w *Worker) checkTaskControl(ctx context.Context, taskId string) string {
	// 从控制信号映射中检查
	if signal, ok := w.taskControlSignals.Load(taskId); ok {
		if action, ok := signal.(string); ok {
			return action
		}
	}

	// 也检查主任务ID的控制信号
	mainTaskId := getMainTaskId(taskId)
	if mainTaskId != taskId {
		if signal, ok := w.taskControlSignals.Load(mainTaskId); ok {
			if action, ok := signal.(string); ok {
				return action
			}
		}
	}

	return ""
}

// shouldStopTask 检查任务是否应该停止（包括 STOP 和 PAUSE）
func (w *Worker) shouldStopTask(ctx context.Context, taskId string) bool {
	ctrl := w.checkTaskControl(ctx, taskId)
	return ctrl == "STOP" || ctrl == "PAUSE" || ctx.Err() != nil
}

// saveTaskProgress 保存任务进度（用于暂停后继续扫描)
func (w *Worker) saveTaskProgress(ctx context.Context, task *scheduler.TaskInfo, completedPhases map[string]bool, assets []*scanner.Asset) {
	// 使用新的context，因为原context可能已被取消
	saveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 构建状态
	phases := make([]string, 0)
	for phase, completed := range completedPhases {
		if completed {
			phases = append(phases, phase)
		}
	}

	assetsJson, _ := json.Marshal(assets)
	state := map[string]interface{}{
		"completedPhases": phases,
		"assets":          string(assetsJson),
	}
	stateJson, _ := json.Marshal(state)

	// 通过 HTTP 接口保存到数据库
	w.httpClient.UpdateTask(saveCtx, &TaskUpdateReq{
		TaskId: task.TaskId,
		State:  "PAUSED",
		Result: string(stateJson),
	})
	w.taskLog(task.TaskId, LevelInfo, "Task %s progress saved: completedPhases=%v, assets=%d", task.TaskId, phases, len(assets))
}

// createTaskContext 创建带有任务控制信号检查的上下文
// 当任务被停止或暂停时，上下文会被取消
func (w *Worker) createTaskContext(parentCtx context.Context, taskId string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parentCtx)

	// 启动一个goroutine定期检查任务控制信号
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond) // 检查间隔200ms
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ctrl := w.checkTaskControl(ctx, taskId)
				if ctrl == "STOP" || ctrl == "PAUSE" {
					w.taskLog(taskId, LevelInfo, "Task %s received %s signal, canceling context", taskId, ctrl)
					cancel()
					return
				}
			}
		}
	}()

	return ctx, cancel
}

// executeTask 执行任务
func (w *Worker) executeTask(task *scheduler.TaskInfo) {
	// 添加 panic 恢复机制，防止单个任务的 panic 导致整个 Worker 挂掉
	defer func() {
		if r := recover(); r != nil {
			// 使用 Worker 级别 logger，避免在 cleanupTaskLogger 之后创建孤儿 task logger
			w.logger.Error("[Task:%s] Task execution panic recovered: %v, stack: %s", task.TaskId, r, string(getStackTrace()))
			ctx := context.Background()
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, fmt.Sprintf("Task panic: %v", r))
		}
	}()

	baseCtx := context.Background()
	startTime := time.Now()

	// 添加函数入口日志
	w.taskLog(task.TaskId, LevelInfo, "=== executeTask START === TaskId: %s, MainTaskId: %s", task.TaskId, task.MainTaskId)

	// 获取资源槽位（优先使用自适应调度器）
	if w.adaptiveScheduler != nil {
		w.adaptiveScheduler.AcquireSlot()
	} else if w.resourceManager != nil {
		w.resourceManager.AcquireSlot()
	}

	w.mu.Lock()
	w.taskStarted++
	w.mu.Unlock()

	// 注册正在执行的任务
	w.runningTasks.Store(task.TaskId, true)
	mainTaskId := getMainTaskId(task.TaskId)
	if mainTaskId != task.TaskId {
		w.runningTasks.Store(mainTaskId, true)
	}

	// 使用 defer 确保无论任务如何结束，taskExecuted 都会递增
	// 这样 runningCount (taskStarted - taskExecuted) 才能正确反映正在执行的任务数
	defer func() {
		w.mu.Lock()
		w.taskExecuted++
		w.mu.Unlock()

		// 注销正在执行的任务
		w.runningTasks.Delete(task.TaskId)
		if mainTaskId != task.TaskId {
			w.runningTasks.Delete(mainTaskId)
		}

		// 清除控制信号
		w.ClearTaskControlSignal(task.TaskId)

		// 清理任务日志记录器，flush 残余缓冲
		w.cleanupTaskLogger(task.TaskId)

		// 释放资源槽位（优先使用自适应调度器）
		if w.adaptiveScheduler != nil {
			w.adaptiveScheduler.ReleaseSlot()
		} else if w.resourceManager != nil {
			w.resourceManager.ReleaseSlot()
		}
	}()

	// 兜底递增子任务计数器：正常流程中每个模块完成时已递增，此 defer 仅在异常退出（STOP/致命错误/panic）时补递增。
	// PAUSE 信号下跳过，恢复后由新一轮执行递增。
	// 此 defer 在 cleanup state defer 之后注册，按 LIFO 先执行，可在控制信号被清除前读取。
	finalIncrSent := false
	targetCount := 0    // 仅用于日志展示
	expectedIncr := 1   // 单 sub-task 应发增量 = enabledModules + 1，配置解析后赋真值
	incrSent := 0       // 已发出的增量数
	defer func() {
		if finalIncrSent {
			return
		}
		bgCtx := context.Background()
		if ctrl := w.checkTaskControl(bgCtx, task.TaskId); ctrl == "PAUSE" {
			return
		}
		remaining := expectedIncr - incrSent
		if remaining < 1 {
			remaining = 1
		}
		w.incrSubTaskDone(bgCtx, task, "完成", true, remaining)
	}()

	// 检查是否有停止信号（任务可能在队列中被停止)
	if ctrl := w.checkTaskControl(baseCtx, task.TaskId); ctrl == "STOP" {
		w.taskLog(task.TaskId, LevelInfo, "Task %s was stopped before execution", task.TaskId)
		return
	}
	w.taskLog(task.TaskId, LevelInfo, "Step 1: Control check passed")

	// 创建带有任务控制信号检查的上下文
	ctx, cancelTask := w.createTaskContext(baseCtx, task.TaskId)
	defer cancelTask()
	w.taskLog(task.TaskId, LevelInfo, "Step 2: Context created")

	// 更新任务状态
	w.taskLog(task.TaskId, LevelInfo, "Step 3: Updating task status to STARTED")
	w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusStarted, "")
	w.taskLog(task.TaskId, LevelInfo, "Step 4: Task status updated")

	// 解析任务配置
	w.taskLog(task.TaskId, LevelInfo, "Step 5: Parsing task config, length=%d", len(task.Config))
	var taskConfig map[string]interface{}
	if err := json.Unmarshal([]byte(task.Config), &taskConfig); err != nil {
		w.taskLog(task.TaskId, LevelError, "Step 5 FAILED: Config parse error: %v", err)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "配置解析失败: "+err.Error())
		return
	}
	w.taskLog(task.TaskId, LevelInfo, "Step 6: Config parsed successfully, keys=%d", len(taskConfig))

	// 计算本 sub-task 应发出的总增量数 = 启用模块数 + 1，供早退路径与最终路径补齐使用
	expectedIncr = utils.CountEnabledModules(taskConfig) + 1

	// 检查任务类型，处理POC验证任务
	taskType, _ := taskConfig["taskType"].(string)
	if taskType == "" {
		w.taskLog(task.TaskId, LevelInfo, "Step 7: Task type: normal scan")
	} else {
		w.taskLog(task.TaskId, LevelInfo, "Step 7: Task type: '%s'", taskType)
	}
	if taskType == "poc_validate" {
		w.taskLog(task.TaskId, LevelInfo, "Step 7a: Executing POC validate task")
		w.executePocValidateTask(ctx, task, taskConfig, startTime)
		return
	}
	if taskType == "poc_batch_validate" {
		w.taskLog(task.TaskId, LevelInfo, "Step 7b: Executing POC batch validate task")
		w.executePocBatchValidateTask(ctx, task, taskConfig, startTime)
		return
	}

	// 获取目标
	target, _ := taskConfig["target"].(string)
	w.taskLog(task.TaskId, LevelInfo, "Step 8: Target extracted: '%s'", target)
	if target == "" {
		w.taskLog(task.TaskId, LevelError, "Step 8 FAILED: Target is empty")
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "Target is empty")
		return
	}

	// 获取组织ID
	orgId, _ := taskConfig["orgId"].(string)
	w.taskLog(task.TaskId, LevelInfo, "Task started")
	w.taskLog(task.TaskId, LevelDebug, "Full task config: %s", task.Config)

	var allAssets []*scanner.Asset
	var allVuls []*scanner.Vulnerability
	var skippedHosts []string // 因端口阈值超限被跳过的主机

	// 解析扫描配置
	config, err := scheduler.ParseTaskConfig(task.Config)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Failed to parse task config: %v", err)
		w.taskLog(task.TaskId, LevelDebug, "Raw config string: %s", task.Config)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "配置解析失败: "+err.Error())
		return
	}
	if config == nil {
		w.taskLog(task.TaskId, LevelError, "Task config is nil after parsing")
		w.taskLog(task.TaskId, LevelDebug, "Raw config string: %s", task.Config)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "任务配置为空")
		return
	}

	// 输出任务开始日志（包含关键配置信息）
	var enabledPhases []string
	var configDetails []string

	if config.DomainScan != nil {
		configDetails = append(configDetails, fmt.Sprintf("DomainScan.Enable=%v", config.DomainScan.Enable))
		if config.DomainScan.Enable {
			enabledPhases = append(enabledPhases, "Domain Scan")
		}
	} else {
		configDetails = append(configDetails, "DomainScan=nil")
	}

	if config.PortScan != nil {
		configDetails = append(configDetails, fmt.Sprintf("PortScan.Enable=%v", config.PortScan.Enable))
		if config.PortScan.Enable {
			enabledPhases = append(enabledPhases, "Port Scan")
		}
	} else {
		configDetails = append(configDetails, "PortScan=nil")
	}

	if config.PortIdentify != nil {
		configDetails = append(configDetails, fmt.Sprintf("PortIdentify.Enable=%v", config.PortIdentify.Enable))
		if config.PortIdentify.Enable {
			enabledPhases = append(enabledPhases, "Port Identify")
		}
	} else {
		configDetails = append(configDetails, "PortIdentify=nil")
	}

	if config.Fingerprint != nil {
		configDetails = append(configDetails, fmt.Sprintf("Fingerprint.Enable=%v", config.Fingerprint.Enable))
		if config.Fingerprint.Enable {
			enabledPhases = append(enabledPhases, "Fingerprint")
		}
	} else {
		configDetails = append(configDetails, "Fingerprint=nil")
	}

	if config.BruteScan != nil {
		configDetails = append(configDetails, fmt.Sprintf("BruteScan.Enable=%v", config.BruteScan.Enable))
		if config.BruteScan.Enable {
			enabledPhases = append(enabledPhases, "Brute Scan")
			w.taskLog(task.TaskId, LevelInfo, "BruteScan config: services=%v, threads=%d, timeout=%d, dictIds=%v",
				config.BruteScan.Services, config.BruteScan.Threads, config.BruteScan.Timeout, config.BruteScan.WeakpassDictIds)
		}
	} else {
		configDetails = append(configDetails, "BruteScan=nil")
	}

	if config.DirScan != nil {
		configDetails = append(configDetails, fmt.Sprintf("DirScan.Enable=%v", config.DirScan.Enable))
		if config.DirScan.Enable {
			enabledPhases = append(enabledPhases, "Dir Scan")
		}
	} else {
		configDetails = append(configDetails, "DirScan=nil")
	}

	if config.JSFinder != nil {
		configDetails = append(configDetails, fmt.Sprintf("JSFinder.Enable=%v", config.JSFinder.Enable))
		if config.JSFinder.Enable {
			enabledPhases = append(enabledPhases, "JSFinder")
		}
	} else {
		configDetails = append(configDetails, "JSFinder=nil")
	}

	if config.PocScan != nil {
		configDetails = append(configDetails, fmt.Sprintf("PocScan.Enable=%v", config.PocScan.Enable))
		if config.PocScan.Enable {
			enabledPhases = append(enabledPhases, "POC Scan")
		}
	} else {
		configDetails = append(configDetails, "PocScan=nil")
	}

	w.taskLog(task.TaskId, LevelInfo, "Config parsed: %s", strings.Join(configDetails, ", "))

	// 检查是否有启用的扫描阶段
	if len(enabledPhases) == 0 {
		w.taskLog(task.TaskId, LevelError, "No scan phases enabled in config")
		w.taskLog(task.TaskId, LevelError, "Config details: %s", strings.Join(configDetails, ", "))
		w.taskLog(task.TaskId, LevelDebug, "Full config JSON: %s", task.Config)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "未启用任何扫描阶段")
		return
	}

	// 解析目标列表
	targetLines := strings.Split(strings.TrimSpace(target), "\n")
	var targets []string
	for _, line := range targetLines {
		line = strings.TrimSpace(line)
		if line != "" {
			targets = append(targets, line)
		}
	}

	// 应用全局黑名单过滤
	blacklistMatcher := w.getBlacklistMatcher(ctx, task.TaskId)
	if blacklistMatcher != nil && !blacklistMatcher.IsEmpty() {
		originalCount := len(targets)
		blacklistedTargets := blacklistMatcher.GetBlacklistedTargets(targets)
		targets = blacklistMatcher.FilterTargets(targets)
		if len(blacklistedTargets) > 0 {
			w.taskLog(task.TaskId, LevelInfo, "Blacklist: filtered %d/%d targets", len(blacklistedTargets), originalCount)
			for _, t := range blacklistedTargets {
				w.taskLog(task.TaskId, LevelDebug, "Blacklist: skipped target: %s", t)
			}
		}
		if len(targets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "All targets filtered by blacklist, marking task as complete")
			blacklistRemaining := expectedIncr - incrSent
			if blacklistRemaining < 1 {
				blacklistRemaining = 1
			}
			w.incrSubTaskDone(ctx, task, "完成", true, blacklistRemaining)
			finalIncrSent = true
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusSuccess, "All targets filtered by blacklist")
			return
		}
	}

	// 输出任务开始日志
	targetCount = len(targets)
	w.taskLog(task.TaskId, LevelInfo, "Starting: %s", strings.Join(enabledPhases, " → "))
	w.taskLog(task.TaskId, LevelInfo, "Targets (%d): %s", targetCount, strings.Join(targets, ", "))

	// 解析恢复状态（如果是继续执行的任务）
	var resumeState map[string]interface{}
	if stateStr, ok := taskConfig["resumeState"].(string); ok && stateStr != "" {
		json.Unmarshal([]byte(stateStr), &resumeState)
		w.taskLog(task.TaskId, LevelInfo, "Resuming from saved state")
	}
	completedPhases := make(map[string]bool)
	if resumeState != nil {
		if phases, ok := resumeState["completedPhases"].([]interface{}); ok {
			for _, p := range phases {
				if ps, ok := p.(string); ok {
					completedPhases[ps] = true
				}
			}
		}
		// 恢复已扫描的资产
		if assetsJson, ok := resumeState["assets"].(string); ok && assetsJson != "" {
			json.Unmarshal([]byte(assetsJson), &allAssets)
			w.taskLog(task.TaskId, LevelInfo, "Restored %d assets", len(allAssets))
		}
	}

	// 当端口扫描禁用时，需要从目标生成初始资产列表
	// 支持 IP:Port 格式的目标，用于资产扫描场景
	if config.PortScan != nil && !config.PortScan.Enable && len(allAssets) == 0 {
		// 检查是否有其他阶段需要资产
		needAssets := (config.PortIdentify != nil && config.PortIdentify.Enable) ||
			(config.Fingerprint != nil && config.Fingerprint.Enable) ||
			(config.PocScan != nil && config.PocScan.Enable)

		if needAssets {
			generatedAssets := w.generateAssetsFromTarget(target, config.PortScan)
			if len(generatedAssets) > 0 {
				allAssets = generatedAssets
				w.taskLog(task.TaskId, LevelInfo, "Generated %d assets from target (port scan disabled)", len(allAssets))
			}
		}
	}

	// 执行子域名扫描（在端口扫描之前）
	if config.DomainScan != nil && config.DomainScan.Enable && !completedPhases["domainscan"] {
		// 检查控制信号
		if ctrl := w.checkTaskControl(ctx, task.TaskId); ctrl == "STOP" {
			w.taskLog(task.TaskId, LevelInfo, "Task stopped")
			return
		}

		// 更新当前阶段
		w.updateTaskProgressWithPhase(ctx, task.TaskId, 10, "子域名扫描中", "子域名扫描")
		w.taskLog(task.TaskId, LevelInfo, "Starting domain scan...")

		// 创建任务日志回调
		domainTaskLogger := func(level, format string, args ...interface{}) {
			w.taskLog(task.TaskId, level, format, args...)
		}

		// 通过 HTTP 接口获取 Subfinder 配置
		var providerConfig map[string][]string
		providerResp, err := w.httpClient.GetSubfinderProviders(ctx, task.WorkspaceId)
		if err != nil {
			w.taskLog(task.TaskId, LevelWarn, "Failed to get subfinder providers: %v", err)
		} else if providerResp != nil && len(providerResp.Providers) > 0 {
			providerConfig = make(map[string][]string)
			for _, p := range providerResp.Providers {
				if len(p.Keys) > 0 {
					providerConfig[p.Provider] = p.Keys
					w.taskLog(task.TaskId, LevelDebug, "Subfinder provider: %s, keys: %d", p.Provider, len(p.Keys))
				}
			}
			w.taskLog(task.TaskId, LevelInfo, "Loaded %d subfinder providers with keys", len(providerConfig))
		} else {
			w.taskLog(task.TaskId, LevelInfo, "No subfinder providers configured in database")
		}

		// 构建Subfinder选项，使用Worker并发数
		subfinderOpts := &scanner.SubfinderOptions{
			Timeout:            config.DomainScan.Timeout,
			MaxEnumerationTime: config.DomainScan.MaxEnumerationTime,
			Threads:            w.config.Concurrency, // 使用Worker并发数
			RateLimit:          config.DomainScan.RateLimit,
			Sources:            config.DomainScan.Sources,
			ExcludeSources:     config.DomainScan.ExcludeSources,
			All:                config.DomainScan.All,
			Recursive:          config.DomainScan.Recursive,
			RemoveWildcard:     config.DomainScan.RemoveWildcard,
			ResolveDNS:         config.DomainScan.ResolveDNS,
			Concurrent:         w.config.Concurrency * 1, // DNS解析并发数为Worker并发数的10倍
			ProviderConfig:     providerConfig,
		}

		// 设置默认值
		if subfinderOpts.Timeout <= 0 {
			subfinderOpts.Timeout = 30
		}
		if subfinderOpts.MaxEnumerationTime <= 0 {
			subfinderOpts.MaxEnumerationTime = 10
		}
		w.taskLog(task.TaskId, LevelInfo, "Subfinder using worker concurrency: threads=%d, dns_concurrent=%d", subfinderOpts.Threads, subfinderOpts.Concurrent)

		// 执行子域名扫描
		var subfinderAssets []*scanner.Asset
		// 只有启用Subfinder时才执行被动枚举
		if config.DomainScan.Subfinder {
			if s, ok := w.scanners["subfinder"]; ok {
				result, err := s.Scan(ctx, &scanner.ScanConfig{
					Target:      target,
					WorkspaceId: task.WorkspaceId,
					MainTaskId:  task.MainTaskId,
					Options:     subfinderOpts,
					TaskLogger:  domainTaskLogger,
				})

				if err != nil {
					w.taskLog(task.TaskId, LevelError, "Subfinder error: %v", err)
				} else if result != nil && len(result.Assets) > 0 {
					subfinderAssets = result.Assets
					w.taskLog(task.TaskId, LevelInfo, "Subfinder: found %d subdomains", len(subfinderAssets))
				}
			} else {
				w.taskLog(task.TaskId, LevelWarn, "Subfinder scanner not available")
			}
		} else {
			w.taskLog(task.TaskId, LevelInfo, "Subfinder disabled, skipping passive enumeration")
		}

		// Subfinder 完成后立即保存，避免后续超时导致结果丢失
		if len(subfinderAssets) > 0 {
			w.taskLog(task.TaskId, LevelInfo, "Saving %d subfinder subdomains to database immediately", len(subfinderAssets))
			w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, subfinderAssets)
		}

		// 执行子域名暴力破解（如果配置了字典）
		var bruteforceAssets []*scanner.Asset
		if len(config.DomainScan.SubdomainDictIds) > 0 {
			w.taskLog(task.TaskId, LevelInfo, "Starting subdomain bruteforce with %d dicts", len(config.DomainScan.SubdomainDictIds))

			// 获取字典内容
			dictResp, err := w.httpClient.GetSubdomainDicts(ctx, config.DomainScan.SubdomainDictIds)
			if err != nil {
				w.taskLog(task.TaskId, LevelError, "Bruteforce: get dicts failed: %v", err)
			} else if dictResp != nil && len(dictResp.Dicts) > 0 {
				// 合并所有字典内容
				var allWords []string
				wordSet := make(map[string]bool)
				for _, dict := range dictResp.Dicts {
					lines := strings.Split(dict.Content, "\n")
					for _, line := range lines {
						word := strings.TrimSpace(line)
						if word != "" && !strings.HasPrefix(word, "#") && !wordSet[word] {
							wordSet[word] = true
							allWords = append(allWords, word)
						}
					}
					w.taskLog(task.TaskId, LevelInfo, "Bruteforce: loaded dict '%s'", dict.Name)
				}

				if len(allWords) > 0 {
					w.taskLog(task.TaskId, LevelInfo, "Bruteforce: total %d unique words", len(allWords))

					// 构建暴力破解选项（包含增强功能）
					bruteforceOpts := &scanner.SubdomainBruteforceOptions{
						Wordlist:       strings.Join(allWords, "\n"),
						Threads:        w.config.Concurrency * 2,
						Timeout:        config.DomainScan.BruteforceTimeout * 60, // 转换为秒
						WildcardFilter: config.DomainScan.RemoveWildcard,
						ResolveDNS:     config.DomainScan.ResolveDNS,
						Concurrent:     w.config.Concurrency * 10,
						// 引擎配置
						Engine:       config.DomainScan.BruteforceEngine,
						Bandwidth:    config.DomainScan.Bandwidth,
						Retry:        config.DomainScan.Retry,
						WildcardMode: config.DomainScan.WildcardMode,
						// 增强功能配置
						RecursiveBrute: config.DomainScan.RecursiveBrute,
						RecursiveDepth: 2,
						WildcardDetect: config.DomainScan.WildcardDetect,
					}

					// 获取递归爆破字典（如果启用了递归爆破）
					if config.DomainScan.RecursiveBrute && len(config.DomainScan.RecursiveDictIds) > 0 {
						recursiveDictResp, err := w.httpClient.GetSubdomainDicts(ctx, config.DomainScan.RecursiveDictIds)
						if err != nil {
							w.taskLog(task.TaskId, LevelWarn, "Bruteforce: get recursive dicts failed: %v", err)
						} else if recursiveDictResp != nil && len(recursiveDictResp.Dicts) > 0 {
							var recursiveWords []string
							recursiveWordSet := make(map[string]bool)
							for _, dict := range recursiveDictResp.Dicts {
								lines := strings.Split(dict.Content, "\n")
								for _, line := range lines {
									word := strings.TrimSpace(line)
									if word != "" && !strings.HasPrefix(word, "#") && !recursiveWordSet[word] {
										recursiveWordSet[word] = true
										recursiveWords = append(recursiveWords, word)
									}
								}
								w.taskLog(task.TaskId, LevelInfo, "Bruteforce: loaded recursive dict '%s'", dict.Name)
							}
							if len(recursiveWords) > 0 {
								bruteforceOpts.RecursiveWordlist = strings.Join(recursiveWords, "\n")
								w.taskLog(task.TaskId, LevelInfo, "Bruteforce: recursive wordlist total %d unique words", len(recursiveWords))
							}
						}
					}

					// 执行暴力破解
					if bruteScanner, ok := w.scanners["subdomain_bruteforce"]; ok {
						bruteResult, err := bruteScanner.Scan(ctx, &scanner.ScanConfig{
							Target:      target,
							WorkspaceId: task.WorkspaceId,
							MainTaskId:  task.MainTaskId,
							Options:     bruteforceOpts,
							TaskLogger:  domainTaskLogger,
						})

						if err != nil {
							w.taskLog(task.TaskId, LevelError, "Bruteforce error: %v", err)
						} else if bruteResult != nil && len(bruteResult.Assets) > 0 {
							bruteforceAssets = bruteResult.Assets
							w.taskLog(task.TaskId, LevelInfo, "Bruteforce: found %d subdomains", len(bruteforceAssets))
						}
					} else {
						w.taskLog(task.TaskId, LevelWarn, "Subdomain bruteforce scanner not available")
					}
				}
			}
		}

		// 合并subfinder和bruteforce结果
		allAssetMap := make(map[string]*scanner.Asset)
		for _, asset := range subfinderAssets {
			if asset.Host != "" {
				allAssetMap[asset.Host] = asset
			}
		}
		for _, asset := range bruteforceAssets {
			if asset.Host != "" {
				if _, exists := allAssetMap[asset.Host]; !exists {
					allAssetMap[asset.Host] = asset
				}
			}
		}

		// 转换为切片
		var mergedAssets []*scanner.Asset
		for _, asset := range allAssetMap {
			mergedAssets = append(mergedAssets, asset)
		}

		// 应用黑名单过滤子域名结果
		if blacklistMatcher != nil && !blacklistMatcher.IsEmpty() {
			mergedAssets = w.filterAssetsByBlacklist(mergedAssets, blacklistMatcher, task.TaskId)
		}

		// 应用端口扫描排除目标过滤子域名解析的IP
		if config.PortScan != nil && config.PortScan.ExcludeHosts != "" {
			excludeMatcher := utils.NewExcludeHostsMatcher(config.PortScan.ExcludeHosts)
			if excludeMatcher != nil && !excludeMatcher.IsEmpty() {
				originalCount := len(mergedAssets)
				mergedAssets = w.filterAssetsByExcludeHosts(mergedAssets, excludeMatcher, task.TaskId)
				if filteredCount := originalCount - len(mergedAssets); filteredCount > 0 {
					w.taskLog(task.TaskId, LevelInfo, "ExcludeHosts: filtered %d subdomains by resolved IP", filteredCount)
				}
			}
		}

		if len(mergedAssets) > 0 {
			allAssets = append(allAssets, mergedAssets...)
		}
		if w.handleTaskControl(ctx, task, completedPhases, allAssets, "domain scan") {
			return
		}

		// 检查context是否被取消
		select {
		case <-ctx.Done():
			w.taskLog(task.TaskId, LevelInfo, "Domain scan canceled by context")
			// 资产已在各阶段完成后立即保存，此处只需保存任务进度
			w.saveTaskProgress(ctx, task, completedPhases, allAssets)
			return
		default:
		}

		// 只保存暴力破解新发现的增量资产（subfinder 的已在前面立即保存过）
		if len(bruteforceAssets) > 0 {
			subfinderHosts := make(map[string]bool)
			for _, asset := range subfinderAssets {
				if asset.Host != "" {
					subfinderHosts[asset.Host] = true
				}
			}
			var newBruteAssets []*scanner.Asset
			for _, asset := range bruteforceAssets {
				if asset.Host != "" && !subfinderHosts[asset.Host] {
					newBruteAssets = append(newBruteAssets, asset)
				}
			}
			if len(newBruteAssets) > 0 {
				w.taskLog(task.TaskId, LevelInfo, "Saving %d bruteforce subdomains to database", len(newBruteAssets))
				w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, newBruteAssets)
			}
		}

		if len(mergedAssets) > 0 {
			// 将发现的子域名添加到目标列表
			var newTargets []string
			for _, asset := range mergedAssets {
				if asset.Host != "" {
					newTargets = append(newTargets, asset.Host)
				}
			}
			if len(newTargets) > 0 {
				// 更新目标（将子域名添加到原始目标）
				target = target + "\n" + strings.Join(newTargets, "\n")
				w.taskLog(task.TaskId, LevelInfo, "Domain scan completed: found %d subdomains (subfinder: %d, bruteforce: %d)",
					len(newTargets), len(subfinderAssets), len(bruteforceAssets))
			}
		}

		completedPhases["domainscan"] = true
		// 子域名扫描模块完成，递增子任务进度
		w.incrSubTaskDone(ctx, task, "子域名扫描", false, 1)
		incrSent++
	}

	// 执行端口扫描（只有明确启用时才执行）
	if config.PortScan != nil && config.PortScan.Enable && !completedPhases["portscan"] {
		// 检查控制信号
		if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
			return
		}

		// 更新当前阶段
		w.updateTaskProgressWithPhase(ctx, task.TaskId, 20, "端口扫描中", "端口扫描")

		// 使用 Worker 并发数覆盖 Naabu Workers
		if config.PortScan.Workers <= 0 || config.PortScan.Workers > w.config.Concurrency {
			config.PortScan.Workers = w.config.Concurrency
		}

		// 端口扫描在 naabu/masscan 内部按目标串行执行（见 scanner/naabu.go runNaabuWithLogger）
		// 故总超时 = 用户单目标超时 × 目标数；并基于端口数/速率/重试估算下限，避免大端口范围低速率被截断
		singleTimeout := config.PortScan.Timeout
		if singleTimeout <= 0 {
			singleTimeout = 5
		}
		// 粗略估算目标数（按换行分割）
		portTargetCount := len(strings.Split(strings.TrimSpace(target), "\n"))
		if portTargetCount <= 0 {
			portTargetCount = 1
		}

		portScanTimeout := singleTimeout * portTargetCount

		// 估算最小耗时：每目标 ports*(1+retries)*1.5/rate 秒（1.5 为安全系数）
		portCount := scanner.EstimatePortCount(config.PortScan.Ports)
		rate := config.PortScan.Rate
		if rate <= 0 {
			rate = 1000
		}
		retries := config.PortScan.Retries
		if retries < 0 {
			retries = 0
		}
		estimatedPerTarget := portCount * (1 + retries) * 3 / (rate * 2)
		if estimatedPerTarget < 60 {
			estimatedPerTarget = 60
		}
		minTotal := estimatedPerTarget * portTargetCount
		if portScanTimeout < minTotal {
			portScanTimeout = minTotal
		}

		w.taskLog(task.TaskId, LevelInfo, "Port scan: timeout=%ds (single=%ds, targets=%d, ports=%d, rate=%d, estimatedPerTarget=%ds)",
			portScanTimeout, singleTimeout, portTargetCount, portCount, rate, estimatedPerTarget)
		portCtx, portCancel := context.WithTimeout(ctx, time.Duration(portScanTimeout)*time.Second)

		// 根据配置选择端口发现工具（默认使用Naabu)
		portDiscoveryTool := "naabu"
		if config.PortScan != nil && config.PortScan.Tool != "" {
			portDiscoveryTool = config.PortScan.Tool
		}

		var openPorts []*scanner.Asset

		// 创建任务日志回调
		taskLogger := func(level, format string, args ...interface{}) {
			w.taskLog(task.TaskId, level, format, args...)
		}

		// 创建进度回调
		onProgress := func(progress int, message string) {
			w.updateTaskProgress(ctx, task.TaskId, progress, message)
		}

		// 第一步：端口发现
		switch portDiscoveryTool {
		case "masscan":
			w.taskLog(task.TaskId, LevelInfo, "Port scan: Masscan")
			masscanScanner := w.scanners["masscan"]
			masscanResult, err := masscanScanner.Scan(portCtx, &scanner.ScanConfig{
				Target:     target,
				Options:    config.PortScan,
				TaskLogger: taskLogger,
				OnProgress: onProgress,
			})
			// 检查是否被停止或超时
			if portCtx.Err() == context.DeadlineExceeded {
				w.taskLog(task.TaskId, LevelWarn, "Port scan timeout, continuing with partial results")
			} else if ctx.Err() != nil {
				portCancel()
				w.taskLog(task.TaskId, LevelInfo, "Task stopped")
				return
			}
			if err != nil {
				w.taskLog(task.TaskId, LevelError, "Masscan error: %v", err)
			}
			if masscanResult != nil {
				if len(masscanResult.Assets) > 0 {
					openPorts = masscanResult.Assets
					w.taskLog(task.TaskId, LevelInfo, "Found %d open ports", len(openPorts))
				}
				if len(masscanResult.SkippedHosts) > 0 {
					skippedHosts = append(skippedHosts, masscanResult.SkippedHosts...)
				}
				if len(masscanResult.DNSFailedHosts) > 0 {
					skippedHosts = append(skippedHosts, masscanResult.DNSFailedHosts...)
					w.taskLog(task.TaskId, LevelInfo, "DNS resolution failed for %d hosts, will skip in subsequent phases", len(masscanResult.DNSFailedHosts))
				}
			}
		default: // naabu
			w.taskLog(task.TaskId, LevelInfo, "Port scan: Naabu")
			naabuScanner := w.scanners["naabu"]
			naabuResult, err := naabuScanner.Scan(portCtx, &scanner.ScanConfig{
				Target:     target,
				Options:    config.PortScan,
				TaskLogger: taskLogger,
				OnProgress: onProgress,
			})
			// 检查是否有目标超过端口阈值（不终止任务，只记录警告）
			if err == scanner.ErrPortThresholdExceeded {
				w.taskLog(task.TaskId, LevelWarn, "Some targets exceeded port threshold and were skipped")
			}
			// 检查是否被停止或超时
			if portCtx.Err() == context.DeadlineExceeded {
				w.taskLog(task.TaskId, LevelWarn, "Port scan timeout, continuing with partial results")
			} else if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
				portCancel()
				w.taskLog(task.TaskId, LevelInfo, "Task stopped")
				return
			}
			if err != nil && err != scanner.ErrPortThresholdExceeded {
				w.taskLog(task.TaskId, LevelError, "Naabu error: %v", err)
			}
			if naabuResult != nil {
				if len(naabuResult.Assets) > 0 {
					openPorts = naabuResult.Assets
					w.taskLog(task.TaskId, LevelInfo, "Found %d open ports", len(openPorts))
				}
				if len(naabuResult.SkippedHosts) > 0 {
					skippedHosts = append(skippedHosts, naabuResult.SkippedHosts...)
				}
				if len(naabuResult.DNSFailedHosts) > 0 {
					skippedHosts = append(skippedHosts, naabuResult.DNSFailedHosts...)
					w.taskLog(task.TaskId, LevelInfo, "DNS resolution failed for %d hosts, will skip in subsequent phases", len(naabuResult.DNSFailedHosts))
				}
			}
		}

		// 检查是否被停止
		if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
			portCancel()
			w.taskLog(task.TaskId, LevelInfo, "Task stopped")
			return
		}

		// 端口发现完成，将结果添加到 allAssets
		if len(openPorts) > 0 {
			for _, asset := range openPorts {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
			}
			allAssets = append(allAssets, openPorts...)
			w.taskLog(task.TaskId, LevelInfo, "Port scan completed: %d assets", len(allAssets))

			// 端口扫描完成后立即保存结果
			w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, allAssets)
		} else {
			w.taskLog(task.TaskId, LevelInfo, "No open ports found")
		}

		portCancel() // 释放端口扫描上下文
		if len(skippedHosts) > 0 {
			w.taskLog(task.TaskId, LevelWarn, "Port scan: %d hosts skipped due to port threshold: %v", len(skippedHosts), skippedHosts)
		}
		completedPhases["portscan"] = true
		// 端口扫描模块完成，递增子任务进度
		w.incrSubTaskDone(ctx, task, "端口扫描", false, 1)
		incrSent++
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行端口识别（Nmap服务识别）- 独立阶段
	if config.PortIdentify != nil && config.PortIdentify.Enable && !completedPhases["portidentify"] {
		// 强制扫描模式：没有资产时从用户输入目标生成资产
		// GenerateAssetsFromTargets 已过滤DNS解析失败的域名
		if len(allAssets) == 0 && target != "" && config.PortIdentify.ForceScan {
			generatedAssets := scanner.GenerateAssetsFromTargets(target)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "Port identify: generated %d assets from target (force scan)", len(generatedAssets))
			}
		}

		// 没有资产时跳过实际扫描，但仍需递增进度
		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "Port identify: skipped (no assets)")
			completedPhases["portidentify"] = true
			w.incrSubTaskDone(ctx, task, "端口识别", false, 1)
			incrSent++
		} else {
			// 检查控制信号
			if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
				return
			}

			// 更新当前阶段
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 40, "端口识别中", "端口识别")

			identifiedAssets := w.executePortIdentify(ctx, task, allAssets, config.PortIdentify)
			if len(identifiedAssets) > 0 {
				allAssets = identifiedAssets
				// 端口识别完成后保存更新结果
				w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, allAssets)
			}
			completedPhases["portidentify"] = true
			// 端口识别模块完成，递增子任务进度
			w.incrSubTaskDone(ctx, task, "端口识别", false, 1)
			incrSent++
		}
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行指纹识别
	if config.Fingerprint != nil && config.Fingerprint.Enable && !completedPhases["fingerprint"] {
		// 强制扫描模式：没有资产时从用户输入目标生成资产
		// GenerateAssetsFromTargets 已过滤DNS解析失败的域名
		if len(allAssets) == 0 && target != "" && config.Fingerprint.ForceScan {
			generatedAssets := scanner.GenerateAssetsFromTargets(target)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "Fingerprint: generated %d assets from target (force scan)", len(generatedAssets))
			}
		}

		// 没有资产时跳过实际扫描，但仍需递增进度
		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "Fingerprint: skipped (no assets)")
			completedPhases["fingerprint"] = true
			w.incrSubTaskDone(ctx, task, "指纹识别", false, 1)
			incrSent++
		} else {
			// 在指纹识别开始前检查停止信号
			if ctrl := w.checkTaskControl(ctx, task.TaskId); ctrl == "STOP" {
				w.taskLog(task.TaskId, LevelInfo, "Task stopped")
				return
			} else if ctrl == "PAUSE" {
				w.taskLog(task.TaskId, LevelInfo, "Task paused, saving progress...")
				w.saveTaskProgress(ctx, task, completedPhases, allAssets)
				return
			}

			// 更新当前阶段
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 60, "指纹识别中", "指纹识别")

			if s, ok := w.scanners["fingerprint"]; ok {
				// 根据过滤模式处理资产
				assetsToScan := allAssets
				filterMode := config.Fingerprint.FilterMode
				if filterMode == "" {
					filterMode = "http_mapping" // 默认使用HTTP映射模式
				}

				if filterMode == "service_mapping" {
					// 模式B：使用服务映射过滤非HTTP服务
					var httpAssets []*scanner.Asset
					nonHttpCount := 0

					for _, asset := range allAssets {
						// 通过全局HTTP服务检查器判断服务是否为HTTP
						// 如果服务映射中明确标识为非HTTP，则排除
						if globalHttpServiceChecker := scanner.GetHttpServiceChecker(); globalHttpServiceChecker != nil {
							serviceLower := strings.ToLower(asset.Service)
							if isHttp, found := globalHttpServiceChecker.IsHttpService(serviceLower); found {
								if !isHttp {
									// 服务映射中明确标识为非HTTP，排除
									nonHttpCount++
									continue
								}
							}
							// 未在服务映射中找到或标识为HTTP，保留
						}
						httpAssets = append(httpAssets, asset)
					}

					assetsToScan = httpAssets
					w.taskLog(task.TaskId, LevelInfo, "Fingerprint: FilterMode=service_mapping, filtered %d assets (excluded %d non-HTTP services), remaining %d assets",
						len(allAssets), nonHttpCount, len(httpAssets))
				} else {
					// 模式A：使用HTTP映射，过滤非HTTP资产
					var httpAssets []*scanner.Asset
					nonHttpCount := 0

					for _, asset := range allAssets {
						if scanner.IsHttpAsset(asset) {
							httpAssets = append(httpAssets, asset)
						} else {
							nonHttpCount++
						}
					}

					assetsToScan = httpAssets
					w.taskLog(task.TaskId, LevelInfo, "Fingerprint: FilterMode=http_mapping, filtered %d assets (excluded %d non-HTTP assets), remaining %d assets",
						len(allAssets), nonHttpCount, len(httpAssets))
				}

				// 获取单目标超时配置
				targetTimeout := config.Fingerprint.TargetTimeout
				if targetTimeout <= 0 {
					targetTimeout = 30 // 默认30秒
				}
				// 使用Worker并发数覆盖配置中的并发数
				config.Fingerprint.Concurrency = w.config.Concurrency
				w.taskLog(task.TaskId, LevelInfo, "Fingerprint: %d assets, timeout %ds/target, concurrency=%d, activeScan=%v, filterMode=%s",
					len(assetsToScan), targetTimeout, w.config.Concurrency, config.Fingerprint.ActiveScan, filterMode)

				// 每次扫描前实时加载HTTP服务映射配置
				w.loadHttpServiceMappings()

				// 如果启用自定义指纹引擎，加载自定义指纹（包括主动指纹）
				if config.Fingerprint.CustomEngine {
					w.loadCustomFingerprints(ctx, s.(*scanner.FingerprintScanner), config.Fingerprint.ActiveScan)
				}

				// 按单目标超时计算总超时：单目标超时 × 目标数 / 并发数
				fpConcurrency := config.Fingerprint.Concurrency
				if fpConcurrency <= 0 {
					fpConcurrency = 1
				}
				fingerprintTimeout := targetTimeout * len(assetsToScan) / fpConcurrency
				// runner.New() 初始化（LevelDB 清理等）可能需要较长时间，
				// 尤其是在 Windows 上，最小值设为 180 秒以确保有足够初始化时间
				if fingerprintTimeout < 180 {
					fingerprintTimeout = 180
				}
				w.taskLog(task.TaskId, LevelInfo, "Fingerprint: total timeout=%ds (single=%ds, assets=%d, concurrency=%d)",
					fingerprintTimeout, targetTimeout, len(assetsToScan), fpConcurrency)
				fpCtx, fpCancel := context.WithTimeout(ctx, time.Duration(fingerprintTimeout)*time.Second)

				// 创建任务日志回调
				fpTaskLogger := func(level, format string, args ...interface{}) {
					w.taskLog(task.TaskId, level, format, args...)
				}

				// 创建流式资产缓冲区，满10个或每3秒触发批量保存
				assetBuffer := NewAssetBuffer(10)
				go func() {
					ticker := time.NewTicker(3 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-assetBuffer.GetFlushChan():
							assetBuffer.Flush(ctx, func(assets []*scanner.Asset) {
								w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, assets)
							})
						case <-ticker.C:
							assetBuffer.Flush(ctx, func(assets []*scanner.Asset) {
								w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, assets)
							})
						case <-fpCtx.Done():
							return
						}
					}
				}()

				result, err := s.Scan(fpCtx, &scanner.ScanConfig{
					Assets:     assetsToScan,
					Options:    config.Fingerprint,
					TaskLogger: fpTaskLogger,
					OnAssetUpdated: func(asset *scanner.Asset) {
						copiedAsset := *asset
						assetBuffer.Add(&copiedAsset)
					},
				})
				fpCancel()

				// 检查是否超时
				if fpCtx.Err() == context.DeadlineExceeded {
					w.taskLog(task.TaskId, LevelWarn, "Fingerprint scan timeout after %ds, continuing with partial results", fingerprintTimeout)
				}

				// 检查是否被取消
				if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
					w.taskLog(task.TaskId, LevelInfo, "Task stopped")
					return
				}

				if err == nil && result != nil {
					// 构建 Host:Port -> Asset 的映射，用于匹配指纹结果
					assetMap := make(map[string]*scanner.Asset)
					for _, asset := range allAssets {
						key := fmt.Sprintf("%s:%d", asset.Host, asset.Port)
						assetMap[key] = asset
					}

					// 通过 Host:Port 匹配来更新资产信息，而不是按索引
					for _, fpAsset := range result.Assets {
						key := fmt.Sprintf("%s:%d", fpAsset.Host, fpAsset.Port)
						if originalAsset, ok := assetMap[key]; ok {
							originalAsset.Service = fpAsset.Service
							originalAsset.Title = fpAsset.Title
							originalAsset.App = fpAsset.App
							originalAsset.HttpStatus = fpAsset.HttpStatus
							originalAsset.HttpHeader = fpAsset.HttpHeader
							originalAsset.HttpBody = fpAsset.HttpBody
							originalAsset.Server = fpAsset.Server
							originalAsset.IconHash = fpAsset.IconHash
							originalAsset.IsHTTP = fpAsset.IsHTTP
							if len(fpAsset.IconData) > 0 {
								originalAsset.IconData = fpAsset.IconData
							}
							originalAsset.Screenshot = fpAsset.Screenshot
						}
					}

					// 刷新流式缓冲区剩余资产
					assetBuffer.Flush(ctx, func(assets []*scanner.Asset) {
						w.saveAssetResult(ctx, task.WorkspaceId, task.MainTaskId, orgId, assets)
					})
				}
			}
			completedPhases["fingerprint"] = true
			// 指纹识别模块完成，递增子任务进度
			w.incrSubTaskDone(ctx, task, "指纹识别", false, 1)
			incrSent++
		} // 结束 len(allAssets) > 0 的 else 分支
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行弱口令扫描（在指纹识别之后、目录扫描之前）
	if config.BruteScan != nil && config.BruteScan.Enable && !completedPhases["brutescan"] {
		w.taskLog(task.TaskId, LevelInfo, "Brute scan: starting, total assets=%d, forceScan=%v, services=%v", len(allAssets), config.BruteScan.ForceScan, config.BruteScan.Services)

		// 强制扫描模式：没有资产时从用户输入目标生成资产
		// 注意：如果目标携带端口（如 192.168.1.215:63791），会保留该端口进行扫描
		if len(allAssets) == 0 && target != "" && config.BruteScan.ForceScan {
			generatedAssets := w.generateBruteAssetsFromTargets(target, config.BruteScan.Services)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "Brute scan: generated %d assets from target (force scan), services=%v", len(generatedAssets), config.BruteScan.Services)
				// 打印生成的资产详情
				for _, asset := range generatedAssets {
					w.taskLog(task.TaskId, LevelInfo, "Brute scan: generated asset: %s:%d (%s)", asset.Host, asset.Port, asset.Service)
				}
			}
		}

		// 仍然没有资产时跳过
		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "Brute scan: skipped (no assets)")
			completedPhases["brutescan"] = true
			w.incrSubTaskDone(ctx, task, "弱口令扫描", false, 1)
			incrSent++
		} else {
			// 检查控制信号
			if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
				return
			}

			// 更新当前阶段
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 65, "弱口令扫描中", "弱口令扫描")

			// 执行弱口令扫描
			bruteVulns := w.executeBruteScan(ctx, task, allAssets, config.BruteScan, orgId)
			if len(bruteVulns) > 0 {
				w.taskLog(task.TaskId, LevelInfo, "Brute scan completed: found %d weak passwords", len(bruteVulns))
			}
			completedPhases["brutescan"] = true
			w.incrSubTaskDone(ctx, task, "弱口令扫描", false, 1)
			incrSent++
		}
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行目录扫描（在弱口令扫描之后、POC扫描之前）
	if config.DirScan != nil && config.DirScan.Enable && !completedPhases["dirscan"] {
		// 强制扫描模式：没有资产时从用户输入目标生成资产
		if len(allAssets) == 0 && target != "" && config.DirScan.ForceScan {
			generatedAssets := scanner.GenerateAssetsFromTargets(target)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "Dir scan: generated %d assets from target (force scan)", len(generatedAssets))
			}
		}

		// 仍然没有资产时跳过
		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "Dir scan: skipped (no assets)")
			completedPhases["dirscan"] = true
			w.incrSubTaskDone(ctx, task, "目录扫描", false, 1)
			incrSent++
		} else {
			// 检查控制信号
			if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
				return
			}

			// 更新当前阶段
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 70, "目录扫描中", "目录扫描")

			// 执行目录扫描
			dirScanAssets := w.executeDirScan(ctx, task, allAssets, config.DirScan, orgId)
			if len(dirScanAssets) > 0 {
				// 注意：目录扫描结果不添加到 allAssets，避免影响后续 POC 扫描
				// 目录扫描结果是 URL 路径，不是独立的扫描目标
				w.taskLog(task.TaskId, LevelInfo, "Dir scan completed: found %d paths", len(dirScanAssets))
				// 目录扫描结果已在 executeDirScan 中通过 saveDirScanResults 保存到数据库
			}
			completedPhases["dirscan"] = true
			w.incrSubTaskDone(ctx, task, "目录扫描", false, 1)
			incrSent++
		}
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行 JSFinder 扫描（JS 敏感信息 + 未授权检测）
	if config.JSFinder != nil && config.JSFinder.Enable && !completedPhases["jsfinder"] {
		// 强制扫描模式：没有资产时从用户输入目标生成资产
		if len(allAssets) == 0 && target != "" && config.JSFinder.ForceScan {
			generatedAssets := scanner.GenerateAssetsFromTargets(target)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "JSFinder: generated %d assets from target (force scan)", len(generatedAssets))
			}
		}

		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "JSFinder: skipped (no assets)")
			completedPhases["jsfinder"] = true
			w.incrSubTaskDone(ctx, task, "JS扫描", false, 1)
			incrSent++
		} else {
			if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
				return
			}

			w.updateTaskProgressWithPhase(ctx, task.TaskId, 80, "JS扫描中", "JS扫描")

			jsfinderResults := w.executeJSFinder(ctx, task, allAssets, config.JSFinder, orgId)
			if len(jsfinderResults) > 0 {
				var schedResults []*JSFinderResultItem
				for _, r := range jsfinderResults {
					schedResults = append(schedResults, &JSFinderResultItem{
						Authority:        r.Authority,
						Host:             r.Host,
						Port:             r.Port,
						URL:              r.URL,
						Severity:         r.Severity,
						VulName:          r.VulName,
						Result:           r.Result,
						Tags:             r.Tags,
						MatcherName:      r.MatcherName,
						ExtractedResults: r.ExtractedResults,
						CurlCommand:      r.CurlCommand,
						Request:          r.Request,
						Response:         r.Response,
					})
				}

				req := &SaveJSFinderResultReq{
					WorkspaceId: task.WorkspaceId,
					MainTaskId:  task.MainTaskId,
					Results:     schedResults,
				}

				resp, err := w.httpClient.SaveJSFinderResult(ctx, req)
				if err != nil {
					w.taskLog(task.TaskId, LevelError, "JSFinder save failed: %v", err)
				} else if resp.Code != 0 {
					w.taskLog(task.TaskId, LevelWarn, "JSFinder save response: %s", resp.Msg)
				} else {
					w.taskLog(task.TaskId, LevelInfo, "JSFinder completed: saved %d findings", len(jsfinderResults))
				}
			}
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 85, "JS扫描完成", "JS扫描")
			completedPhases["jsfinder"] = true
			w.incrSubTaskDone(ctx, task, "JS扫描", false, 1)
			incrSent++
		}
	}

	// 检查控制信号
	if w.handleTaskControl(ctx, task, completedPhases, allAssets, "") {
		return
	}

	// 执行POC扫描 (使用Nuclei引擎)
	if config.PocScan != nil && config.PocScan.Enable && !completedPhases["pocscan"] {
		// 强制扫描模式：没有资产时从用户输入目标生成资产
		if len(allAssets) == 0 && target != "" && config.PocScan.ForceScan {
			generatedAssets := scanner.GenerateAssetsFromTargets(target)
			generatedAssets = filterSkippedHostsAssets(generatedAssets, skippedHosts)
			if len(generatedAssets) > 0 {
				allAssets = append(allAssets, generatedAssets...)
				w.taskLog(task.TaskId, LevelInfo, "POC scan: generated %d assets from target (force scan)", len(generatedAssets))
			}
		}

		// 没有资产时跳过实际扫描，但仍需递增进度
		if len(allAssets) == 0 {
			w.taskLog(task.TaskId, LevelInfo, "POC scan: skipped (no assets)")
			completedPhases["pocscan"] = true
			w.incrSubTaskDone(ctx, task, "漏洞扫描", false, 1)
			incrSent++
		} else {
			// 在POC扫描开始前检查停止信号
			if ctrl := w.checkTaskControl(ctx, task.TaskId); ctrl == "STOP" {
				w.taskLog(task.TaskId, LevelInfo, "Task stopped")
				return
			} else if ctrl == "PAUSE" {
				w.taskLog(task.TaskId, LevelInfo, "Task paused, saving progress...")
				w.saveTaskProgress(ctx, task, completedPhases, allAssets)
				return
			}

			// 更新当前阶段
			w.updateTaskProgressWithPhase(ctx, task.TaskId, 80, "漏洞扫描中", "漏洞扫描")

			if s, ok := w.scanners["nuclei"]; ok {
				// 获取单目标超时配置
				pocTargetTimeout := config.PocScan.TargetTimeout
				if pocTargetTimeout <= 0 {
					pocTargetTimeout = 600 // 默认600秒
				}
				w.taskLog(task.TaskId, LevelInfo, "POC scan: %d assets, timeout %ds/target", len(allAssets), pocTargetTimeout)

				// 从数据库获取模板（所有模板都存储在数据库中）
				var templates []string

				// 检查是否有模板ID列表（任务创建时已筛选好的模板）
				if len(config.PocScan.NucleiTemplateIds) > 0 || len(config.PocScan.CustomPocIds) > 0 {
					// 通过RPC根据ID获取模板内容（包括默认模板和自定义POC)
					w.taskLog(task.TaskId, LevelInfo, "POC template request: nucleiTemplateIds=%d, customPocIds=%d", len(config.PocScan.NucleiTemplateIds), len(config.PocScan.CustomPocIds))
					templates = w.getTemplatesByIds(ctx, config.PocScan.NucleiTemplateIds, config.PocScan.CustomPocIds)
					w.taskLog(task.TaskId, LevelInfo, "Loaded %d POC templates", len(templates))
				} else if config.PocScan.CustomPocOnly {
					// 只使用自定义POC模式，但没有指定具体ID，获取所有自定义POC
					severities := []string{}
					if config.PocScan.Severity != "" {
						severities = strings.Split(config.PocScan.Severity, ",")
					}
					templates = w.getAllCustomPocs(ctx, severities)
					w.taskLog(task.TaskId, LevelInfo, "CustomPocOnly mode: loaded %d custom POC templates", len(templates))
				} else {
					// 优化：按资产分组，每组只加载相关的POC模板
					// 当AutoScan或AutomaticScan启用时，按资产的指纹标签进行分组
					var groups []*AssetGroup
					if config.PocScan.AutoScan || config.PocScan.AutomaticScan {
						groups = w.groupAssetsByTags(allAssets, config.PocScan)

						// 输出分组信息日志
						for _, group := range groups {
							w.taskLog(task.TaskId, LevelInfo, "Auto-scan group: tags=%v, assets=%d", group.Tags, len(group.Assets))
						}
					}

					if len(groups) > 0 {
						w.taskLog(task.TaskId, LevelInfo, "POC template auto selection: %d asset groups", len(groups))

						// 用于统计漏洞数量
						var vulCount int

						// 创建漏洞缓冲区，发现漏洞立即保存
						vulBuffer := NewVulnerabilityBuffer(1)

						// 获取单目标超时配置
						targetTimeout := config.PocScan.TargetTimeout
						if targetTimeout <= 0 {
							targetTimeout = 600 // 默认600秒
						}

						// 超时直接使用单目标超时，由自适应调度器管理并发和速率
						w.taskLog(task.TaskId, LevelInfo, "POC scan: target timeout=%ds, assets=%d, groups=%d (concurrency/rate managed by adaptive scheduler)",
							targetTimeout, len(allAssets), len(groups))
						pocCtx, pocCancel := context.WithTimeout(ctx, time.Duration(targetTimeout)*time.Second)

						// 启动后台刷新协程
						flushDone := make(chan struct{})
						go func() {
							defer close(flushDone)
							ticker := time.NewTicker(5 * time.Second)
							defer ticker.Stop()
							for {
								select {
								case <-pocCtx.Done():
									return
								case <-flushDone:
									return
								case <-vulBuffer.flushChan:
									vulBuffer.Flush(pocCtx, func(vuls []*scanner.Vulnerability) {
										w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
									})
								case <-ticker.C:
									vulBuffer.Flush(pocCtx, func(vuls []*scanner.Vulnerability) {
										w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
									})
								}
							}
						}()

						// 遍历每个分组进行扫描
						taskIdForCallback := task.TaskId
						severities := []string{}
						if config.PocScan.Severity != "" {
							severities = strings.Split(config.PocScan.Severity, ",")
						}

						for _, group := range groups {
							groupTemplates := w.getTemplatesByTags(ctx, group.Tags, severities)
							if len(groupTemplates) == 0 {
								w.taskLog(task.TaskId, LevelInfo, "Group (tags=%v): no templates loaded, skipping", group.Tags)
								continue
							}
							w.taskLog(task.TaskId, LevelInfo, "Group (tags=%v, assets=%d): loaded %d templates", group.Tags, len(group.Assets), len(groupTemplates))

							// 构建该分组的扫描选项（并发和速率由自适应调度器决定）
							groupOpts := &scanner.NucleiOptions{
								Severity:        config.PocScan.Severity,
								Tags:            group.Tags,
								ExcludeTags:     config.PocScan.ExcludeTags,
								TargetTimeout:   targetTimeout,
								AutoScan:        false,
								AutomaticScan:   false,
								CustomPocOnly:   false,
								CustomTemplates: groupTemplates,
								TagMappings:     nil,
								CustomHeaders:   config.PocScan.CustomHeaders,
								OnVulnerabilityFound: func(vul *scanner.Vulnerability) {
									vulCount++
									w.taskLog(taskIdForCallback, LevelInfo, "Vulnerability found: %s → %s", vul.PocFile, vul.Url)
									vulBuffer.Add(vul)
								},
							}

							// 创建任务日志回调
							pocTaskLogger := func(level, format string, args ...interface{}) {
								w.taskLog(task.TaskId, level, format, args...)
							}

							// 扫描该分组的资产
							result, err := s.Scan(pocCtx, &scanner.ScanConfig{
								Assets:     group.Assets,
								Options:    groupOpts,
								TaskLogger: pocTaskLogger,
							})

							if err != nil {
								w.taskLog(task.TaskId, LevelError, "POC scan error (group tags=%v): %v", group.Tags, err)
							}
							if result != nil {
								allVuls = append(allVuls, result.Vulnerabilities...)
							}
						}

						pocCancel()

						// 扫描完成后，刷新剩余的漏洞
						vulBuffer.Flush(ctx, func(vuls []*scanner.Vulnerability) {
							w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
						})

						if vulCount > 0 {
							w.taskLog(task.TaskId, LevelInfo, "POC scan completed: found %d vulnerabilities", vulCount)
						}
					} else {
						w.taskLog(task.TaskId, LevelWarn, "No POC templates configured (no tags matched), skipping POC scan")
					}
				}

				// 统一扫描执行：当模板通过 ID 或 CustomPocOnly 方式加载后，执行扫描
				if len(templates) > 0 {
					// 用于统计漏洞数量
					var vulCount int

					// 创建漏洞缓冲区，发现漏洞立即保存
					vulBuffer := NewVulnerabilityBuffer(1)

					// 获取单目标超时配置
					pocTargetTimeout := config.PocScan.TargetTimeout
					if pocTargetTimeout <= 0 {
						pocTargetTimeout = 600
					}

					// 超时直接使用单目标超时，由自适应调度器管理并发和速率
					w.taskLog(task.TaskId, LevelInfo, "POC scan: target timeout=%ds, assets=%d (concurrency/rate managed by adaptive scheduler)",
						pocTargetTimeout, len(allAssets))
					pocCtx, pocCancel := context.WithTimeout(ctx, time.Duration(pocTargetTimeout)*time.Second)

					// 启动后台刷新协程
					flushDone := make(chan struct{})
					go func() {
						defer close(flushDone)
						ticker := time.NewTicker(5 * time.Second)
						defer ticker.Stop()
						for {
							select {
							case <-pocCtx.Done():
								return
							case <-flushDone:
								return
							case <-vulBuffer.flushChan:
								vulBuffer.Flush(pocCtx, func(vuls []*scanner.Vulnerability) {
									w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
								})
							case <-ticker.C:
								vulBuffer.Flush(pocCtx, func(vuls []*scanner.Vulnerability) {
									w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
								})
							}
						}
					}()

					taskIdForCallback := task.TaskId
					// 并发和速率由自适应调度器决定
					nucleiOpts := &scanner.NucleiOptions{
						Severity:        config.PocScan.Severity,
						ExcludeTags:     config.PocScan.ExcludeTags,
						TargetTimeout:   pocTargetTimeout,
						AutoScan:        false,
						AutomaticScan:   false,
						CustomPocOnly:   config.PocScan.CustomPocOnly,
						CustomTemplates: templates,
						TagMappings:     config.PocScan.TagMappings,
						CustomHeaders:   config.PocScan.CustomHeaders,
						OnVulnerabilityFound: func(vul *scanner.Vulnerability) {
							vulCount++
							w.taskLog(taskIdForCallback, LevelInfo, "Vulnerability found: %s → %s", vul.PocFile, vul.Url)
							vulBuffer.Add(vul)
						},
					}

					pocTaskLogger := func(level, format string, args ...interface{}) {
						w.taskLog(task.TaskId, level, format, args...)
					}

					result, err := s.Scan(pocCtx, &scanner.ScanConfig{
						Assets:     allAssets,
						Options:    nucleiOpts,
						TaskLogger: pocTaskLogger,
					})

					if err != nil {
						w.taskLog(task.TaskId, LevelError, "POC scan error: %v", err)
					}
					if result != nil {
						allVuls = append(allVuls, result.Vulnerabilities...)
					}

					pocCancel()

					// 扫描完成后，刷新剩余的漏洞
					vulBuffer.Flush(ctx, func(vuls []*scanner.Vulnerability) {
						w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, vuls)
					})

					if vulCount > 0 {
						w.taskLog(task.TaskId, LevelInfo, "POC scan completed: found %d vulnerabilities", vulCount)
					}
				}
			}
			// POC扫描模块完成，递增子任务进度
			w.incrSubTaskDone(ctx, task, "漏洞扫描", false, 1)
			incrSent++
		} // 结束 len(allAssets) > 0 的 else 分支
	}

	// 更新任务状态为完成
	duration := time.Since(startTime).Seconds()
	result := fmt.Sprintf("Assets:%d Vuls:%d Duration:%.0fs", len(allAssets), len(allVuls), duration)

	// 显式递增计数器，确保 progress=100 与 status=SUCCESS 原子落盘。
	// 正常路径下各模块已递增 enabledModules 次，此处补齐最终 +1 即可；
	// 若中途有路径未发出预期增量，clamp 兜底确保 sub_task_done 不超 sub_task_count。
	finalRemaining := expectedIncr - incrSent
	if finalRemaining < 1 {
		finalRemaining = 1
	}
	w.incrSubTaskDone(ctx, task, "完成", true, finalRemaining)
	finalIncrSent = true

	w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusSuccess, result)
	w.taskLog(task.TaskId, LevelInfo, "Completed: %s", result)
	// 注意：taskExecuted 由 defer 递增，无需在此处理
}

// updateTaskStatus 更新任务状态
func (w *Worker) updateTaskStatus(ctx context.Context, taskId string, status string, result string) {
	// 如果任务完成（SUCCESS/FAILURE），同时更新进度
	progress := 0
	if status == scheduler.TaskStatusSuccess || status == scheduler.TaskStatusFailure {
		progress = 100
	}
	w.updateTaskProgressWithPhase(ctx, taskId, progress, result, "完成")

	// 通过 HTTP 接口更新任务状态
	_, err := w.httpClient.UpdateTask(ctx, &TaskUpdateReq{
		TaskId: taskId,
		State:  status,
		Worker: w.config.Name,
		Result: result,
	})
	if err != nil {
		w.taskLog(taskId, LevelError, "update task status failed: %v", err)
	}
}

// updateTaskProgress 更新任务进度
// 注意：进度更新现在通过 HTTP 接口完成
func (w *Worker) updateTaskProgress(ctx context.Context, taskId string, progress int, message string) {
	w.updateTaskProgressWithPhase(ctx, taskId, progress, message, "")
}

// updateTaskProgressWithPhase 更新任务进度和当前阶段
// 注意：进度更新现在通过 HTTP 接口完成，不再直接写 Redis
func (w *Worker) updateTaskProgressWithPhase(ctx context.Context, taskId string, progress int, message string, currentPhase string) {
	// 通过 HTTP 接口更新任务状态
	// 进度信息包含在任务状态更新中
	if w.httpClient != nil && currentPhase != "" {
		_, err := w.httpClient.UpdateTask(ctx, &TaskUpdateReq{
			TaskId:   taskId,
			Progress: progress,
			Phase:    currentPhase,
			Result:   message,
		})
		if err != nil {
			w.taskLog(taskId, LevelError, "update task progress failed: %v", err)
		}
	}
}

// expectedTaskIncr 根据任务配置计算单个 sub-task 应发出的总增量数：
// = 启用模块数 + 1（每模块 1 次 + 最终完成 1 次）。配置解析失败时回退为 1。
// 早退路径据此补齐，避免主任务计数永远到不了 sub_task_count。
func (w *Worker) expectedTaskIncr(configStr string) int {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &cfg); err != nil {
		return 1
	}
	return utils.CountEnabledModules(cfg) + 1
}

// incrSubTaskDone 递增子任务完成数（模块级别）
// 每完成一个扫描模块就调用此方法，通知主任务进度更新
// isCompleted: true 表示子任务全部阶段完成，此时才递增计数器
// incrAmount: 递增数量（早退路径下需补齐 expectedTaskIncr - alreadySent，正常路径恒为 1）
func (w *Worker) incrSubTaskDone(ctx context.Context, task *scheduler.TaskInfo, phase string, isCompleted bool, incrAmount int) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Increment subtask done panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	if w.httpClient == nil {
		return
	}

	if incrAmount <= 0 {
		incrAmount = 1
	}

	// 通过 HTTP 接口递增子任务完成数
	resp, err := w.httpClient.IncrSubTaskDone(ctx, &SubTaskDoneReq{
		TaskId:      task.TaskId,
		MainTaskId:  task.MainTaskId,
		WorkspaceId: task.WorkspaceId,
		Phase:       phase,
		IsCompleted: isCompleted,
		IncrAmount:  incrAmount,
	})
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Failed to incr sub task done: %v", err)
		return
	}

	if resp.AllDone {
		w.taskLog(task.TaskId, LevelInfo, "All sub-tasks completed: %d/%d", resp.SubTaskDone, resp.SubTaskCount)
	} else {
		w.taskLog(task.TaskId, LevelDebug, "Sub-task progress: %d/%d (phase: %s)", resp.SubTaskDone, resp.SubTaskCount, phase)
	}
}

// saveAssetResult 保存资产结果
func (w *Worker) saveAssetResult(ctx context.Context, workspaceId, mainTaskId, orgId string, assets []*scanner.Asset) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Save asset result panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	if len(assets) == 0 {
		return
	}

	// 分批保存，每批最多500个
	batchSize := 500
	totalAssets := len(assets)
	totalBatches := (totalAssets + batchSize - 1) / batchSize

	w.taskLog(mainTaskId, LevelInfo, "Saving %d assets in %d batches", totalAssets, totalBatches)

	var totalNew, totalUpdate int32

	for batchIdx := 0; batchIdx < totalBatches; batchIdx++ {
		start := batchIdx * batchSize
		end := start + batchSize
		if end > totalAssets {
			end = totalAssets
		}

		batchAssets := assets[start:end]
		httpAssets := make([]AssetDocument, 0, len(batchAssets))

		for _, asset := range batchAssets {
			httpAsset := AssetDocument{
				Authority:  asset.Authority,
				Host:       asset.Host,
				Port:       int32(asset.Port),
				Category:   asset.Category,
				Service:    asset.Service,
				Title:      asset.Title,
				App:        asset.App,
				HttpStatus: asset.HttpStatus,
				HttpHeader: asset.HttpHeader,
				HttpBody:   asset.HttpBody,
				IconHash:   asset.IconHash,
				IconData:   asset.IconData,
				Screenshot: asset.Screenshot,
				Server:     asset.Server,
				Banner:     asset.Banner,
				IsHttp:     asset.IsHTTP,
				Cname:      asset.CName,
				IsCdn:      asset.IsCDN,
				IsCloud:    asset.IsCloud,
				Source:     asset.Source,
			}

			// 添加IPv4信息
			for _, ip := range asset.IPV4 {
				httpAsset.Ipv4 = append(httpAsset.Ipv4, IPV4Info{
					IP:       ip.IP,
					Location: ip.Location,
				})
			}

			// 添加IPv6信息
			for _, ip := range asset.IPV6 {
				httpAsset.Ipv6 = append(httpAsset.Ipv6, IPV6Info{
					IP:       ip.IP,
					Location: ip.Location,
				})
			}

			httpAssets = append(httpAssets, httpAsset)
		}

		// 失败时使用新 context 重试，避免共享父 ctx 已 cancel 导致重试无效
		const maxBatchRetry = 3
		var resp *TaskResultResp
		var err error
		for attempt := 1; attempt <= maxBatchRetry; attempt++ {
			batchCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			resp, err = w.httpClient.SaveTaskResult(batchCtx, &TaskResultReq{
				WorkspaceId: workspaceId,
				MainTaskId:  mainTaskId,
				Assets:      httpAssets,
				OrgId:       orgId,
			})
			cancel()
			if err == nil {
				break
			}
			if attempt < maxBatchRetry {
				w.taskLog(mainTaskId, LevelWarn, "Batch %d/%d save attempt %d/%d failed: %v",
					batchIdx+1, totalBatches, attempt, maxBatchRetry, err)
				time.Sleep(time.Duration(attempt*2) * time.Second)
			}
		}

		if err != nil {
			// API 不可用时，将结果入队到本地队列
			if w.resultQueue != nil {
				queueReq := &TaskResultReq{
					WorkspaceId: workspaceId,
					MainTaskId:  mainTaskId,
					Assets:      httpAssets,
					OrgId:       orgId,
				}
				if queueErr := w.resultQueue.Enqueue(queueReq); queueErr != nil {
					w.taskLog(mainTaskId, LevelError, "Batch %d/%d save failed and queue failed: %v (queue error: %v)",
						batchIdx+1, totalBatches, maxBatchRetry, err, queueErr)
				} else {
					w.taskLog(mainTaskId, LevelWarn, "Batch %d/%d save failed after %d attempts, queued for retry: %v",
						batchIdx+1, totalBatches, maxBatchRetry, err)
				}
			} else {
				w.taskLog(mainTaskId, LevelError, "Batch %d/%d save failed after %d attempts: %v",
					batchIdx+1, totalBatches, maxBatchRetry, err)
			}
		} else {
			totalNew += resp.NewAsset
			totalUpdate += resp.UpdateAsset
			w.taskLog(mainTaskId, LevelDebug, "Batch %d/%d saved: new=%d, update=%d", batchIdx+1, totalBatches, resp.NewAsset, resp.UpdateAsset)
		}
	}

	w.taskLog(mainTaskId, LevelInfo, "Save completed: total=%d, new=%d, update=%d", totalAssets, totalNew, totalUpdate)
}

// saveVulResult 保存漏洞结果（支持去重与聚合）
func (w *Worker) saveVulResult(ctx context.Context, workspaceId, mainTaskId string, vuls []*scanner.Vulnerability) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Save vulnerability result panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	if len(vuls) == 0 {
		return
	}

	w.taskLog(mainTaskId, LevelInfo, "[SaveVul] Starting to save %d vulnerabilities via HTTP API", len(vuls))

	httpVuls := make([]VulDocument, 0, len(vuls))
	for _, vul := range vuls {
		// Debug: 打印扫描层与发送层的关键字段
		w.taskLog(mainTaskId, LevelDebug, "[SaveVul] scanner.PocFile=%s, scanner.VulName=%q, scanner.Tags=%v, CurlCommand len=%d, Request len=%d, Response len=%d",
			vul.PocFile, vul.VulName, vul.Tags, len(vul.CurlCommand), len(vul.Request), len(vul.Response))

		httpVul := ToVulDocument(vul, mainTaskId)
		httpVulName := ""
		if httpVul.VulName != nil {
			httpVulName = *httpVul.VulName
		}

		// 输出httpVul中的关键字段
		w.taskLog(mainTaskId, LevelDebug, "[SaveVul] httpVul.VulName.nil=%v, httpVul.VulName=%q, httpVul.Tags=%v, httpVul.CurlCommand=%v, httpVul.Request=%v, httpVul.Response=%v",
			httpVul.VulName == nil, httpVulName, httpVul.Tags, httpVul.CurlCommand != nil, httpVul.Request != nil, httpVul.Response != nil)

		httpVuls = append(httpVuls, httpVul)
	}

	w.taskLog(mainTaskId, LevelInfo, "[SaveVul] Calling HTTP API to save %d vulnerabilities, workspaceId=%s", len(httpVuls), workspaceId)

	// 通过 HTTP 接口保存漏洞结果
	resp, err := w.httpClient.SaveVulResult(ctx, &VulResultReq{
		WorkspaceId: workspaceId,
		MainTaskId:  mainTaskId,
		Vuls:        httpVuls,
	})
	if err != nil {
		w.taskLog(mainTaskId, LevelError, "[SaveVul] HTTP request failed: %v", err)
		return
	}

	if resp != nil {
		w.taskLog(mainTaskId, LevelInfo, "[SaveVul] HTTP API response: success=%v, message=%s, total=%d", resp.Success, resp.Msg, resp.Total)
	} else {
		w.taskLog(mainTaskId, LevelWarn, "[SaveVul] HTTP API response is nil")
	}
}

// reportResultLoop 上报结果循环（内部方法）
func (w *Worker) reportResultLoop() {
	for {
		select {
		case <-w.stopChan:
			return
		case result := <-w.resultChan:
			w.handleResult(result)
		}
	}
}

// handleResult 处理结果
func (w *Worker) handleResult(result *scanner.ScanResult) {
	ctx := context.Background()
	w.saveAssetResult(ctx, result.WorkspaceId, result.MainTaskId, "", result.Assets)
	w.saveVulResult(ctx, result.WorkspaceId, result.MainTaskId, result.Vulnerabilities)
}

// keepAliveLoop 心跳循环（内部方法）
// 心跳使用独立协程，不受扫描任务阻塞影响
func (w *Worker) keepAliveLoop() {
	// 启动时立即发送一次心跳
	w.sendHeartbeat()

	const (
		normalInterval  = 30 * time.Second  // 正常心跳间隔
		circuitInterval = 60 * time.Second  // 熔断期间心跳间隔
		circuitThreshold = 5                // 连续失败多少次进入熔断
	)

	ticker := time.NewTicker(normalInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	inCircuit := false

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			if err := w.sendHeartbeatWithRetry(); err != nil {
				consecutiveFailures++

				// 进入熔断状态
				if !inCircuit && consecutiveFailures >= circuitThreshold {
					inCircuit = true
					ticker.Reset(circuitInterval)
					w.logger.Warn("Heartbeat circuit breaker OPEN after %d failures, interval increased to %v", consecutiveFailures, circuitInterval)
				}
			} else {
				// 退出熔断状态
				if inCircuit {
					inCircuit = false
					ticker.Reset(normalInterval)
					w.logger.Info("Heartbeat circuit breaker CLOSED, recovered after %d failures", consecutiveFailures)
				}
				consecutiveFailures = 0
			}
		}
	}
}

// sendHeartbeatWithRetry 带重试的心跳发送
func (w *Worker) sendHeartbeatWithRetry() error {
	var lastErr error
	for i := 0; i < 2; i++ { // 最多重试 1 次
		if i > 0 {
			time.Sleep(2 * time.Second)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := w.doSendHeartbeat(ctx)
		cancel()

		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// doSendHeartbeat 执行心跳发送
func (w *Worker) doSendHeartbeat(ctx context.Context) error {
	// 获取系统资源使用情况（快速采样，避免阻塞）
	cpuPercent, _ := cpu.Percent(0, false) // 使用 0 表示不等待，返回上次采样值
	memInfo, _ := mem.VirtualMemory()

	cpuLoad := 0.0
	if len(cpuPercent) > 0 {
		cpuLoad = cpuPercent[0]
	}
	memUsed := 0.0
	if memInfo != nil {
		memUsed = memInfo.UsedPercent
	}

	// 确保数值有效
	if cpuLoad < 0 || cpuLoad > 100 {
		cpuLoad = 0.0
	}
	if memUsed < 0 || memUsed > 100 {
		memUsed = 0.0
	}

	// 计算正在执行的任务数
	w.mu.Lock()
	runningTasks := w.taskStarted - w.taskExecuted
	if runningTasks < 0 {
		runningTasks = 0
	}
	w.mu.Unlock()

	// 获取调度器状态
	var schedulerMode string
	var effectiveConcurrency int
	var isThrottled bool
	if w.adaptiveScheduler != nil {
		schedulerMode = w.adaptiveScheduler.GetCurrentMode().String()
		effectiveConcurrency = w.adaptiveScheduler.GetCurrentConcurrency()
		isThrottled = w.adaptiveScheduler.IsThrottled()
	} else {
		effectiveConcurrency = w.config.Concurrency
	}

	// 通过 HTTP 接口发送心跳
	resp, err := w.httpClient.Heartbeat(ctx, &HeartbeatReq{
		WorkerName:           w.config.Name,
		IP:                   w.config.IP,
		CpuLoad:              cpuLoad,
		MemUsed:              memUsed,
		TaskStartedNumber:    int32(w.taskStarted),
		TaskExecutedNumber:   int32(w.taskExecuted),
		IsDaemon:             false,
		Concurrency:          w.config.Concurrency,
		SchedulerMode:        schedulerMode,
		EffectiveConcurrency: effectiveConcurrency,
		IsThrottled:          isThrottled,
	})

	if err != nil {
		return err
	}

	// 处理控制指令（互斥，仅执行一次 Stop）
	if resp.ManualStopFlag {
		w.logger.Info("received stop signal, stopping worker...")
		go func() {
			w.Stop()
			os.Exit(0)
		}()
	} else if resp.ManualReloadFlag {
		w.logger.Info("received reload/restart signal, restarting worker...")
		go func() {
			w.Stop()
			os.Exit(0)
		}()
	}

	// 应用管理端持久化的期望并发数（Worker重启后自动恢复，值未变化时为空操作）
	if resp.DesiredConcurrency > 0 {
		w.applyConcurrency(resp.DesiredConcurrency)
	}

	return nil
}

// sendHeartbeat 发送心跳（简单包装，用于外部调用）
func (w *Worker) sendHeartbeat() {
	_ = w.sendHeartbeatWithRetry()
}

// controlPollingLoop HTTP轮询控制信号循环（内部方法，作为WebSocket的备份方案）
func (w *Worker) controlPollingLoop() {
	ticker := time.NewTicker(2 * time.Second) // 每2秒轮询一次
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			// 获取当前正在执行的任务ID列表
			taskIds := w.getRunningTaskIds()
			if len(taskIds) == 0 {
				continue
			}

			// 通过HTTP轮询获取控制信号（始终执行，作为WebSocket的备份）
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := w.httpClient.GetTaskControlSignals(ctx, taskIds)
			cancel()

			if err != nil {
				// 轮询失败，静默处理（避免日志刷屏）
				continue
			}

			// 处理控制信号
			for _, signal := range resp.Signals {
				w.handleControlSignal(signal.TaskId, signal.Action)
			}
		}
	}
}

// getRunningTaskIds 获取当前正在执行的任务ID列表
func (w *Worker) getRunningTaskIds() []string {
	var taskIds []string
	w.runningTasks.Range(func(key, value interface{}) bool {
		if taskId, ok := key.(string); ok {
			taskIds = append(taskIds, taskId)
		}
		return true
	})
	return taskIds
}

// CPU负载阈值常量
const (
	CPULoadThreshold     = 80.0 // CPU负载阈值，超过此值暂停任务拉取
	CPULoadRecovery      = 60.0 // CPU负载恢复阈值，低于此值恢复任务拉取
	CPUCheckInterval     = 5    // CPU检查间隔(秒)
	CPUOverloadThreshold = 3    // 连续过载次数阈值，超过则进入限流
	ThrottleDuration     = 30   // 限流持续时间(秒)
)

// isCPUOverloaded 检查CPU是否过载
// 当CPU负载超过80%时返回true，暂停任务下发以防止扫描引擎崩溃
// 实现智能限流：连续多次过载后进入限流状态，等待一段时间后自动恢复
func (w *Worker) isCPUOverloaded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 检查是否处于限流状态
	if w.isThrottled {
		if time.Now().Before(w.throttleUntil) {
			return true // 仍在限流期间
		}
		// 限流期结束，重置状态
		w.isThrottled = false
		w.cpuOverloadCount = 0
		w.logger.Info("CPU throttle period ended, resuming task fetch")
	}

	// 避免频繁检查CPU
	if time.Since(w.lastCPUCheck) < time.Duration(CPUCheckInterval)*time.Second {
		return false
	}
	w.lastCPUCheck = time.Now()

	// 快速获取CPU使用率（1秒采样）
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil || len(cpuPercent) == 0 {
		return false // 获取失败时不阻止任务
	}

	cpuLoad := cpuPercent[0]

	if cpuLoad >= CPULoadThreshold {
		w.cpuOverloadCount++
		w.logger.Warn("CPU load %.1f%% exceeds threshold %.1f%% (count: %d/%d)",
			cpuLoad, CPULoadThreshold, w.cpuOverloadCount, CPUOverloadThreshold)

		// 连续多次过载，进入限流状态
		if w.cpuOverloadCount >= CPUOverloadThreshold {
			w.isThrottled = true
			w.throttleUntil = time.Now().Add(time.Duration(ThrottleDuration) * time.Second)
			w.logger.Warn("Entering throttle mode for %d seconds to prevent engine crash", ThrottleDuration)
		}
		return true
	} else if cpuLoad < CPULoadRecovery {
		// CPU负载恢复正常，重置计数
		if w.cpuOverloadCount > 0 {
			w.cpuOverloadCount = 0
			w.logger.Info("CPU load %.1f%% recovered below %.1f%%, resetting overload count",
				cpuLoad, CPULoadRecovery)
		}
	}

	return false
}

// NOTE: subscribeStatusQuery 已移除，将在 Task 6 中通过 WebSocket 实现
// NOTE: reportStatusToRedis 已移除，将在 Task 6 中通过 WebSocket 实现

// GetWorkerName 获取Worker名称
func GetWorkerName() string {
	hostname, _ := os.Hostname()
	// 使用 hostname + pid + 随机后缀，确保唯一性
	return fmt.Sprintf("%s-%d-%s", hostname, os.Getpid(), randomSuffix(4))
}

// randomSuffix 生成随机后缀
func randomSuffix(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}

// NOTE: ensureUniqueWorkerName 已移除，将在 Task 6 中通过 WebSocket 实现

// GetLocalIP 获取本机IP地址
func GetLocalIP() string {
	// 1. 优先使用环境变量 WORKER_IP（适用于 Docker 等容器环境）
	if ip := os.Getenv("WORKER_IP"); ip != "" {
		return ip
	}

	// 2. 尝试通过 UDP 连接获取出口 IP（更可靠的方式）
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return localAddr.IP.String()
		}
	}

	// 3. 回退到遍历网络接口
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// GetSystemInfo 获取系统信息
func GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"cpus":     runtime.NumCPU(),
		"hostname": func() string { h, _ := os.Hostname(); return h }(),
		"ip":       GetLocalIP(),
	}
}

// TagMatchInfo 标签匹配信息
type TagMatchInfo struct {
	Fingerprint string   // 匹配的指纹名称
	Tags        []string // 匹配到的标签
	Source      string   // 来源: "custom"(自定义标签映射) 或 "builtin"(内置映射)
}

// generateAutoTags 根据资产的应用信息生成Nuclei标签
// 返回: 标签列表, 匹配信息列表
func (w *Worker) generateAutoTags(assets []*scanner.Asset, pocConfig *scheduler.PocScanConfig) ([]string, []TagMatchInfo) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Generate auto tags panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	tagSet := make(map[string]bool)
	matchInfoMap := make(map[string]*TagMatchInfo) // 用于去重，key为 fingerprint+source

	for _, asset := range assets {
		for _, app := range asset.App {
			appName := parseAppName(app)
			appNameLower := strings.ToLower(appName)

			// 模式1: 基于自定义标签映射
			if pocConfig.AutoScan && pocConfig.TagMappings != nil {
				for mappedApp, tags := range pocConfig.TagMappings {
					if strings.ToLower(mappedApp) == appNameLower {
						key := appName + "_custom"
						if _, exists := matchInfoMap[key]; !exists {
							matchInfoMap[key] = &TagMatchInfo{
								Fingerprint: appName,
								Tags:        tags,
								Source:      "custom",
							}
						}
						for _, tag := range tags {
							tagSet[tag] = true
						}
						break
					}
				}
			}

			// 模式2: 基于Wappalyzer内置映射
			if pocConfig.AutomaticScan {
				if tags, ok := mapping.WappalyzerNucleiMapping[appNameLower]; ok {
					key := appName + "_builtin"
					if _, exists := matchInfoMap[key]; !exists {
						matchInfoMap[key] = &TagMatchInfo{
							Fingerprint: appName,
							Tags:        tags,
							Source:      "builtin",
						}
					}
					for _, tag := range tags {
						tagSet[tag] = true
					}
				}
			}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}

	matchInfos := make([]TagMatchInfo, 0, len(matchInfoMap))
	for _, info := range matchInfoMap {
		matchInfos = append(matchInfos, *info)
	}

	return tags, matchInfos
}

// AssetGroup 资产组，具有相同标签集的资产归为一组
type AssetGroup struct {
	Assets []*scanner.Asset
	Tags   []string
}

// generateAssetTags 为单个资产生成标签（基于自定义标签映射和Wappalyzer映射）
func (w *Worker) generateAssetTags(asset *scanner.Asset, pocConfig *scheduler.PocScanConfig) []string {
	tagSet := make(map[string]bool)

	for _, app := range asset.App {
		appName := parseAppName(app)
		appNameLower := strings.ToLower(appName)

		// 模式1: 基于自定义标签映射
		if pocConfig.AutoScan && pocConfig.TagMappings != nil {
			for mappedApp, tags := range pocConfig.TagMappings {
				if strings.ToLower(mappedApp) == appNameLower {
					for _, tag := range tags {
						tagSet[tag] = true
					}
					break
				}
			}
		}

		// 模式2: 基于Wappalyzer内置映射
		if pocConfig.AutomaticScan {
			if tags, ok := mapping.WappalyzerNucleiMapping[appNameLower]; ok {
				for _, tag := range tags {
					tagSet[tag] = true
				}
			}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// groupAssetsByTags 按标签集对资产进行分组
// 具有相同标签集的资产归为同一组，可以共享同一套POC模板
func (w *Worker) groupAssetsByTags(assets []*scanner.Asset, pocConfig *scheduler.PocScanConfig) []*AssetGroup {
	// 使用标签集的签名作为key进行分组
	groups := make(map[string]*AssetGroup)

	for _, asset := range assets {
		tags := w.generateAssetTags(asset, pocConfig)
		if len(tags) == 0 {
			continue
		}

		// 创建标签集的签名（排序后拼接）
		sortedTags := make([]string, len(tags))
		copy(sortedTags, tags)
		sort.Strings(sortedTags)
		sig := strings.Join(sortedTags, ",")

		if _, ok := groups[sig]; !ok {
			groups[sig] = &AssetGroup{
				Assets: make([]*scanner.Asset, 0),
				Tags:   tags,
			}
		}
		groups[sig].Assets = append(groups[sig].Assets, asset)
	}

	result := make([]*AssetGroup, 0, len(groups))
	for _, group := range groups {
		result = append(result, group)
	}
	return result
}

// getTemplatesByTags 通过 HTTP 接口从数据库获取符合标签的模板
func (w *Worker) getTemplatesByTags(ctx context.Context, tags []string, severities []string) []string {
	if len(tags) == 0 {
		return nil
	}

	// 通过 HTTP 接口获取模板
	resp, err := w.httpClient.GetTemplates(ctx, &TemplatesReq{
		Tags:       tags,
		Severities: severities,
	})
	if err != nil {
		w.logger.Error("GetTemplates HTTP failed: %v", err)
		return nil
	}

	if !resp.Success {
		w.logger.Error("GetTemplates failed: %s", resp.Msg)
		return nil
	}

	w.logger.Info("GetTemplatesByTags: fetched %d templates for tags %v", resp.Count, tags)
	return resp.Templates
}

// getTemplatesByIds 通过 HTTP 接口根据ID列表获取模板内容
func (w *Worker) getTemplatesByIds(ctx context.Context, nucleiTemplateIds, customPocIds []string) []string {
	if len(nucleiTemplateIds) == 0 && len(customPocIds) == 0 {
		return nil
	}

	// 通过 HTTP 接口获取模板
	resp, err := w.httpClient.GetTemplates(ctx, &TemplatesReq{
		NucleiTemplateIds: nucleiTemplateIds,
		CustomPocIds:      customPocIds,
	})
	if err != nil {
		w.logger.Error("GetTemplates HTTP failed: %v", err)
		return nil
	}

	if !resp.Success {
		w.logger.Error("GetTemplates failed: %s", resp.Msg)
		return nil
	}

	w.logger.Info("GetTemplatesByIds: requested nucleiIds=%d customPocIds=%d, fetched %d templates", len(nucleiTemplateIds), len(customPocIds), resp.Count)
	return resp.Templates
}

// getAllCustomPocs 获取所有自定义POC
func (w *Worker) getAllCustomPocs(ctx context.Context, severities []string) []string {
	// 通过 HTTP 接口获取所有自定义POC
	resp, err := w.httpClient.GetTemplates(ctx, &TemplatesReq{
		Severities:    severities,
		CustomPocOnly: true,
	})
	if err != nil {
		w.logger.Error("GetAllCustomPocs HTTP failed: %v", err)
		return nil
	}

	if !resp.Success {
		w.logger.Error("GetAllCustomPocs failed: %s", resp.Msg)
		return nil
	}

	w.logger.Info("GetAllCustomPocs: fetched %d custom POC templates", resp.Count)
	return resp.Templates
}

// parseAppName 解析应用名称，去除版本号和来源标�?
func parseAppName(app string) string {
	appName := app
	// 先去�?[source] 后缀
	if idx := strings.Index(appName, "["); idx > 0 {
		appName = appName[:idx]
	}
	// 再去除 :version 后缀
	if idx := strings.Index(appName, ":"); idx > 0 {
		appName = appName[:idx]
	}
	return strings.TrimSpace(appName)
}

// loadCustomFingerprints 加载自定义指纹到指纹扫描器
// activeScan: 是否启用主动扫描，如果启用则同时加载主动指纹
func (w *Worker) loadCustomFingerprints(ctx context.Context, fpScanner *scanner.FingerprintScanner, activeScan bool) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Load custom fingerprints panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	// 通过 HTTP 接口获取被动指纹配置
	var passiveFingerprints []*model.Fingerprint
	passiveFpMap := make(map[string]*model.Fingerprint)

	resp, err := w.httpClient.GetFingerprints(ctx, &FingerprintsReq{
		EnabledOnly: true,
	})
	if err != nil {
		w.logger.Error("GetFingerprints HTTP failed: %v", err)
		// 不直接返回，继续尝试加载主动指纹
	} else if !resp.Success {
		w.logger.Error("GetFingerprints failed: %s", resp.Msg)
		// 不直接返回，继续尝试加载主动指纹
	} else {
		// 转换为model.Fingerprint（被动指纹）
		for _, fp := range resp.Fingerprints {
			mfp := &model.Fingerprint{
				Name:      fp.Name,
				Category:  fp.Category,
				Rule:      fp.Rule,
				Source:    fp.Source,
				Headers:   fp.Headers,
				Cookies:   fp.Cookies,
				HTML:      fp.Html,
				Scripts:   fp.Scripts,
				ScriptSrc: fp.ScriptSrc,
				Meta:      fp.Meta,
				CSS:       fp.Css,
				URL:       fp.Url,
				IsBuiltin: fp.IsBuiltin,
				Enabled:   fp.Enabled,
			}
			// 解析ID
			if fp.Id != "" {
				if oid, err := primitive.ObjectIDFromHex(fp.Id); err == nil {
					mfp.Id = oid
				}
			}
			passiveFingerprints = append(passiveFingerprints, mfp)
			// 存入映射（小写名称作为key，支持不区分大小写匹配）
			passiveFpMap[strings.ToLower(fp.Name)] = mfp
		}
	}

	// 如果启用主动扫描，加载主动指纹
	var activeFingerprints []*model.Fingerprint
	if activeScan {
		activeResp, err := w.httpClient.GetActiveFingerprints(ctx, true)
		if err != nil {
			w.logger.Warn("GetActiveFingerprints HTTP failed: %v", err)
		} else if activeResp.Success && len(activeResp.Fingerprints) > 0 {
			for _, afp := range activeResp.Fingerprints {
				// 创建主动指纹对象，直接使用API返回的规则（已包含关联的被动指纹规则）
				mfp := &model.Fingerprint{
					Name:        afp.Name,
					ActivePaths: afp.Paths,
					Enabled:     afp.Enabled,
					Type:        model.FingerprintTypeActive,
					// 使用API返回的匹配规则（服务端已关联被动指纹）
					Rule:      afp.Rule,
					Headers:   afp.Headers,
					Cookies:   afp.Cookies,
					HTML:      afp.Html,
					Scripts:   afp.Scripts,
					ScriptSrc: afp.ScriptSrc,
					Meta:      afp.Meta,
					CSS:       afp.Css,
					URL:       afp.Url,
				}

				// 如果API没有返回规则，尝试从本地被动指纹映射获取
				if mfp.Rule == "" && len(mfp.HTML) == 0 && len(mfp.Headers) == 0 {
					if passiveFp := passiveFpMap[strings.ToLower(afp.Name)]; passiveFp != nil {
						mfp.Rule = passiveFp.Rule
						mfp.Headers = passiveFp.Headers
						mfp.Cookies = passiveFp.Cookies
						mfp.HTML = passiveFp.HTML
						mfp.Scripts = passiveFp.Scripts
						mfp.ScriptSrc = passiveFp.ScriptSrc
						mfp.Meta = passiveFp.Meta
						mfp.CSS = passiveFp.CSS
						mfp.URL = passiveFp.URL
						mfp.Category = passiveFp.Category
						w.logger.Debug("Active fingerprint '%s' linked to local passive fingerprint with rule: %s", afp.Name, passiveFp.Rule)
					} else {
						w.logger.Warn("Active fingerprint '%s' has no matching rule", afp.Name)
					}
				} else if mfp.Rule != "" {
					w.logger.Debug("Active fingerprint '%s' loaded with rule from API: %s", afp.Name, mfp.Rule)
				}

				// 解析ID
				if afp.Id != "" {
					if oid, err := primitive.ObjectIDFromHex(afp.Id); err == nil {
						mfp.Id = oid
					}
				}
				activeFingerprints = append(activeFingerprints, mfp)
			}
			w.logger.Info("Loaded %d active fingerprints", len(activeFingerprints))
		}
	}

	// 创建自定义指纹引擎并设置到扫描器
	// 即使被动指纹为空，只要有主动指纹也要创建引擎
	if len(passiveFingerprints) > 0 || len(activeFingerprints) > 0 {
		var customEngine *scanner.CustomFingerprintEngine
		if len(activeFingerprints) > 0 {
			customEngine = scanner.NewCustomFingerprintEngineWithActive(passiveFingerprints, activeFingerprints)
		} else {
			customEngine = scanner.NewCustomFingerprintEngine(passiveFingerprints)
		}
		fpScanner.SetCustomFingerprintEngine(customEngine)
		w.logger.Info("Loaded %d passive fingerprints, %d active fingerprints into scanner", len(passiveFingerprints), len(activeFingerprints))
	} else {
		w.logger.Info("No fingerprints found")
	}
}

// filterSkippedHostsAssets 过滤掉因端口阈值超限被跳过的主机的资产
func filterSkippedHostsAssets(assets []*scanner.Asset, skippedHosts []string) []*scanner.Asset {
	if len(skippedHosts) == 0 || len(assets) == 0 {
		return assets
	}
	skippedSet := make(map[string]bool, len(skippedHosts))
	for _, h := range skippedHosts {
		skippedSet[h] = true
	}
	var result []*scanner.Asset
	for _, a := range assets {
		if !skippedSet[a.Host] {
			result = append(result, a)
		}
	}
	return result
}

// generateBruteAssetsFromTargets 从目标生成弱口令扫描资产
// 用于强制扫描模式：
// - 如果目标携带端口（如 192.168.1.215:63791），保留该端口进行扫描
// - 如果目标没有端口，为指定服务生成默认端口资产
func (w *Worker) generateBruteAssetsFromTargets(target string, services []string) []*scanner.Asset {
	var assets []*scanner.Asset

	// 服务默认端口映射
	servicePorts := map[string]int{
		"ssh":        22,
		"mysql":      3306,
		"redis":      6379,
		"mongodb":    27017,
		"postgresql": 5432,
		"mssql":      1433,
		"ftp":        21,
		"snmp":       161,
		"oracle":     1521,
		"smb":        445,
		"mqtt":       1883,
	}

	// 端口到服务的反向映射
	portToService := map[int]string{
		22:    "ssh",
		3306:  "mysql",
		6379:  "redis",
		27017: "mongodb",
		5432:  "postgresql",
		1433:  "mssql",
		21:    "ftp",
		161:   "snmp",
		1521:  "oracle",
		445:   "smb",
		1883:  "mqtt",
	}

	// 解析目标，生成临时资产
	tempAssets := scanner.GenerateAssetsFromTargetsWithoutDNS(target)
	if len(tempAssets) == 0 {
		return assets
	}

	// 确定目标服务列表
	var targetServices []string
	if len(services) > 0 {
		targetServices = services
	} else {
		// 如果没有指定服务，使用所有已知服务
		for svc := range servicePorts {
			targetServices = append(targetServices, svc)
		}
	}

	// 转换为集合便于查找
	targetServiceSet := make(map[string]bool)
	for _, svc := range targetServices {
		targetServiceSet[svc] = true
	}

	// 按主机分组处理，避免重复
	hostAssets := make(map[string][]*scanner.Asset)

	for _, tempAsset := range tempAssets {
		host := tempAsset.Host

		// 检查是否已处理过该主机
		if _, exists := hostAssets[host]; exists {
			continue
		}

		// 如果目标有明确端口（用户指定了端口）
		if tempAsset.Port > 0 {
			// 根据端口识别服务
			if svc, ok := portToService[tempAsset.Port]; ok {
				// 检查该服务是否在目标列表中
				if targetServiceSet[svc] {
					asset := &scanner.Asset{
						Host:    host,
						Port:    tempAsset.Port, // 使用用户指定的端口
						Service: svc,
						IsHTTP:  false,
					}
					hostAssets[host] = append(hostAssets[host], asset)
				}
			} else {
				// 端口没有匹配到已知服务，但用户明确指定了端口
				// 为所有目标服务生成资产，但保留用户指定的端口
				for _, svc := range targetServices {
					asset := &scanner.Asset{
						Host:    host,
						Port:    tempAsset.Port, // 保留用户指定的端口
						Service: svc,
						IsHTTP:  false,
					}
					hostAssets[host] = append(hostAssets[host], asset)
				}
			}
		} else {
			// 没有指定端口，为所有目标服务生成默认端口资产
			for _, svc := range targetServices {
				port, ok := servicePorts[svc]
				if !ok {
					continue
				}
				asset := &scanner.Asset{
					Host:    host,
					Port:    port,
					Service: svc,
					IsHTTP:  false,
				}
				hostAssets[host] = append(hostAssets[host], asset)
			}
		}
	}

	// 合并所有资产
	for _, hostAssetList := range hostAssets {
		assets = append(assets, hostAssetList...)
	}

	return assets
}

// executePocValidateTask 执行POC验证任务
func (w *Worker) executePocValidateTask(ctx context.Context, task *scheduler.TaskInfo, taskConfig map[string]interface{}, startTime time.Time) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "POC validation task panic recovered: %v, stack: %s", r, string(getStackTrace()))
			// 更新任务状态为失败
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, fmt.Sprintf("POC validation panic: %v", r))
			// 保存失败结果
			batchId, _ := taskConfig["batchId"].(string)
			w.savePocValidationResult(ctx, task.TaskId, batchId, nil, fmt.Sprintf("POC validation panic: %v", r))
		}
	}()

	// 解析配置
	url, _ := taskConfig["url"].(string)
	pocId, _ := taskConfig["pocId"].(string)
	pocType, _ := taskConfig["pocType"].(string)
	timeout, _ := taskConfig["timeout"].(float64)
	batchId, _ := taskConfig["batchId"].(string)
	workspaceId, _ := taskConfig["workspaceId"].(string)
	if workspaceId == "" {
		workspaceId = task.WorkspaceId
	}
	if workspaceId == "" {
		workspaceId = "default"
	}

	// 立即输出任务接收日志
	w.taskLog(task.TaskId, LevelInfo, "[%s] 收到POC验证任务, 目标: %s", task.TaskId, url)

	if url == "" {
		w.taskLog(task.TaskId, LevelError, "[%s] POC验证失败: URL为空", task.TaskId)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "URL为空")
		w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "URL为空")
		return
	}

	if timeout == 0 {
		timeout = 30
	}

	// 获取Nuclei扫描器
	nucleiScanner, ok := w.scanners["nuclei"]
	if !ok {
		w.taskLog(task.TaskId, LevelError, "[%s] POC验证失败: Nuclei扫描器未初始化", task.TaskId)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "Nuclei扫描器未初始化")
		w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "Nuclei扫描器未初始化")
		return
	}

	// 获取POC模板
	var templates []string
	var pocName string
	var pocSeverity string

	// 如果指定了pocId，通过 HTTP 接口获取POC内容
	if pocId != "" {
		w.taskLog(task.TaskId, LevelInfo, "[%s] Loading POC template...", task.TaskId)
		resp, err := w.httpClient.GetPocById(ctx, pocId, pocType)
		if err != nil {
			w.taskLog(task.TaskId, LevelError, "[%s] POC validation failed: failed to get POC - %v", task.TaskId, err)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "Failed to get POC: "+err.Error())
			w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "Failed to get POC: "+err.Error())
			return
		}
		if !resp.Success {
			w.taskLog(task.TaskId, LevelError, "[%s] POC validation failed: POC not found - %s", task.TaskId, resp.Msg)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "POC not found: "+resp.Msg)
			w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "POC not found: "+resp.Msg)
			return
		}
		if resp.Content == "" {
			w.taskLog(task.TaskId, LevelError, "[%s] POC validation failed: POC content is empty", task.TaskId)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "POC content is empty")
			w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "POC content is empty")
			return
		}
		templates = []string{resp.Content}
		pocName = resp.Name
		pocSeverity = resp.Severity
		pocType = resp.PocType
		w.taskLog(task.TaskId, LevelInfo, "[%s] POC template loaded: %s", task.TaskId, pocName)
	} else {
		// 没有指定pocId，尝试通过标签获取模板
		var severities []string
		var tags []string

		// 解析严重级别
		if sevList, ok := taskConfig["severities"].([]interface{}); ok {
			for _, s := range sevList {
				if str, ok := s.(string); ok {
					severities = append(severities, str)
				}
			}
		}

		// 解析标签
		if tagList, ok := taskConfig["tags"].([]interface{}); ok {
			for _, t := range tagList {
				if str, ok := t.(string); ok {
					tags = append(tags, str)
				}
			}
		}

		// 根据标签获取模板
		if len(tags) > 0 {
			templates = w.getTemplatesByTags(ctx, tags, severities)
		}

		if len(templates) == 0 {
			w.taskLog(task.TaskId, LevelError, "[%s] POC validation failed: no POC templates found", task.TaskId)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "No POC templates found")
			w.savePocValidationResult(ctx, task.TaskId, batchId, nil, "No POC templates found")
			return
		}
	}

	// 输出开始扫描日志
	w.taskLog(task.TaskId, LevelInfo, "[%s] Initializing Nuclei scan engine...", task.TaskId)

	// 构建Nuclei扫描选项
	nucleiOpts := &scanner.NucleiOptions{
		RateLimit:       50,
		Concurrency:     10,
		CustomTemplates: templates,
		CustomPocOnly:   true, // 只使用自定义POC
	}

	w.taskLog(task.TaskId, LevelInfo, "[%s] Scanning target: %s", task.TaskId, url)

	// 执行扫描 - 直接传递URL作为目标，不通过Asset构建
	result, err := nucleiScanner.Scan(ctx, &scanner.ScanConfig{
		Targets: []string{url}, // 直接使用URL作为目标
		Options: nucleiOpts,
	})

	duration := time.Since(startTime).Seconds()

	if err != nil {
		w.taskLog(task.TaskId, LevelError, "[%s] POC validation failed: %v", task.TaskId, err)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, fmt.Sprintf("Scan failed: %v", err))
		w.savePocValidationResult(ctx, task.TaskId, batchId, nil, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	// 构建验证结果
	var validationResults []*PocValidationResult
	matched := false
	vulCount := 0
	if result != nil {
		vulCount = len(result.Vulnerabilities)
	}

	w.taskLog(task.TaskId, LevelInfo, "[%s] Scan completed, duration: %.2fs", task.TaskId, duration)

	if result != nil && len(result.Vulnerabilities) > 0 {
		matched = true
		for _, vul := range result.Vulnerabilities {
			// 优先使用配置中的POC信息
			resultPocName := pocName
			resultSeverity := pocSeverity
			if resultPocName == "" {
				resultPocName = vul.PocFile
			}
			if resultSeverity == "" {
				resultSeverity = vul.Severity
			}
			validationResults = append(validationResults, &PocValidationResult{
				PocId:      pocId,
				PocName:    resultPocName,
				TemplateId: pocId,
				Severity:   resultSeverity,
				Matched:    true,
				MatchedUrl: vul.Url,
				Details:    vul.Result,
				Output:     vul.Extra,
				PocType:    pocType,
			})
			logx.Infof("[%s] Vulnerability found! Matched URL: %s", task.TaskId, vul.Url)
			w.taskLog(task.TaskId, LevelInfo, "[%s] Vulnerability found! Matched URL: %s", task.TaskId, vul.Url)
		}
		// 保存漏洞到数据库
		w.saveVulResult(ctx, workspaceId, task.TaskId, result.Vulnerabilities)
	} else {
		// 没有发现漏洞，添加一个未匹配的结果
		resultPocName := pocName
		if resultPocName == "" {
			resultPocName = pocId
		}
		validationResults = append(validationResults, &PocValidationResult{
			PocId:      pocId,
			PocName:    resultPocName,
			Severity:   pocSeverity,
			Matched:    false,
			MatchedUrl: url,
			Details:    "No vulnerability found",
			PocType:    pocType,
		})
		w.taskLog(task.TaskId, LevelInfo, "[%s] No vulnerability found", task.TaskId)
	}

	// 先更新任务状态和进度
	resultMsg := fmt.Sprintf("Validation completed: matched=%v, vuls=%d, duration=%.2fs", matched, vulCount, duration)
	w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusSuccess, resultMsg)

	// 最后保存验证结果到Redis（包含详细的results JSON数据）
	// 注意：必须在updateTaskStatus之后调用，否则result字段会被纯文本覆盖，
	// 导致RPC层解析results失败，前端误判为"未发现漏洞"
	w.savePocValidationResult(ctx, task.TaskId, batchId, validationResults, "")
	// 注意：taskExecuted 由 executeTask 的 defer 递增，无需在此处理
}

// executePocBatchValidateTask 执行POC批量验证任务（使用单个Nuclei引擎扫描所有目标）
func (w *Worker) executePocBatchValidateTask(ctx context.Context, task *scheduler.TaskInfo, taskConfig map[string]interface{}, startTime time.Time) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "POC batch validation task panic recovered: %v, stack: %s", r, string(getStackTrace()))
			// 更新任务状态为失败
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, fmt.Sprintf("POC batch validation panic: %v", r))
		}
	}()

	// 解析配置
	pocId, _ := taskConfig["pocId"].(string)
	pocType, _ := taskConfig["pocType"].(string)
	timeout, _ := taskConfig["timeout"].(float64)
	workspaceId, _ := taskConfig["workspaceId"].(string)
	if workspaceId == "" {
		workspaceId = task.WorkspaceId
	}
	if workspaceId == "" {
		workspaceId = "default"
	}

	// 解析目标URL列表
	var urls []string
	if urlsInterface, ok := taskConfig["urls"].([]interface{}); ok {
		for _, u := range urlsInterface {
			if urlStr, ok := u.(string); ok && urlStr != "" {
				urls = append(urls, urlStr)
			}
		}
	}

	w.taskLog(task.TaskId, LevelInfo, "[%s] 收到POC批量扫描任务, 目标数: %d", task.TaskId, len(urls))

	if len(urls) == 0 {
		w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描失败: 目标列表为空", task.TaskId)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "目标列表为空")
		return
	}

	if timeout == 0 {
		// 每个目标30秒，最少60秒
		timeout = float64(len(urls) * 30)
		if timeout < 60 {
			timeout = 60
		}
	}

	// 获取Nuclei扫描器
	nucleiScanner, ok := w.scanners["nuclei"].(*scanner.NucleiScanner)
	if !ok {
		w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描失败: Nuclei扫描器未初始化", task.TaskId)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "Nuclei扫描器未初始化")
		return
	}

	// 获取POC模板
	var templates []string
	var pocName string
	var pocSeverity string

	if pocId != "" {
		w.taskLog(task.TaskId, LevelInfo, "[%s] Loading POC template...", task.TaskId)
		resp, err := w.httpClient.GetPocById(ctx, pocId, pocType)
		if err != nil {
			w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描失败: 获取POC失败 - %v", task.TaskId, err)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "获取POC失败: "+err.Error())
			return
		}
		if !resp.Success || resp.Content == "" {
			w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描失败: POC不存在或内容为空", task.TaskId)
			w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "POC不存在或内容为空")
			return
		}
		templates = []string{resp.Content}
		pocName = resp.Name
		pocSeverity = resp.Severity
		pocType = resp.PocType
		w.taskLog(task.TaskId, LevelInfo, "[%s] POC template loaded: %s", task.TaskId, pocName)
	} else {
		w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描失败: 未指定POC ID", task.TaskId)
		w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusFailure, "未指定POC ID")
		return
	}

	// 构建Nuclei扫描选项
	nucleiOpts := &scanner.NucleiOptions{
		RateLimit:       150,
		Concurrency:     25,
		Timeout:         int(timeout),
		CustomTemplates: templates,
		CustomPocOnly:   true,
		// 设置回调函数，发现漏洞时立即保存到数据库
		OnVulnerabilityFound: func(vul *scanner.Vulnerability) {
			w.taskLog(task.TaskId, LevelInfo, "[%s] Vulnerability found! %s → %s", task.TaskId, vul.PocFile, vul.Url)
			// 立即保存到数据库
			w.saveVulResult(ctx, workspaceId, task.TaskId, []*scanner.Vulnerability{vul})
		},
	}

	// 使用批量扫描方法
	w.taskLog(task.TaskId, LevelInfo, "[%s] Starting batch scan: %d targets, timeout %ds", task.TaskId, len(urls), int(timeout))

	vuls, err := nucleiScanner.ScanBatch(ctx, urls, nucleiOpts, func(level, format string, args ...interface{}) {
		w.taskLog(task.TaskId, level, "[%s] "+format, append([]interface{}{task.TaskId}, args...)...)
	})

	duration := time.Since(startTime).Seconds()

	if err != nil {
		w.taskLog(task.TaskId, LevelError, "[%s] POC批量扫描出错: %v", task.TaskId, err)
	}

	vulCount := len(vuls)
	w.taskLog(task.TaskId, LevelInfo, "[%s] Batch scan completed, duration: %.2fs, vuls: %d", task.TaskId, duration, vulCount)

	// 漏洞已在回调中实时保存，这里不需要再保存
	if vulCount > 0 {
		w.taskLog(task.TaskId, LevelInfo, "[%s] Total %d vulnerabilities saved to database", task.TaskId, vulCount)
	}

	// 构建验证结果
	var validationResults []*PocValidationResult
	if vulCount > 0 {
		for _, vul := range vuls {
			validationResults = append(validationResults, &PocValidationResult{
				PocId:      pocId,
				PocName:    pocName,
				TemplateId: pocId,
				Severity:   pocSeverity,
				Matched:    true,
				MatchedUrl: vul.Url,
				Details:    vul.Result,
				Output:     vul.Extra,
				PocType:    pocType,
			})
		}
	}

	// 先更新任务状态和进度
	resultMsg := fmt.Sprintf("Batch scan completed: targets=%d, vuls=%d, duration=%.2fs", len(urls), vulCount, duration)
	w.updateTaskStatus(ctx, task.TaskId, scheduler.TaskStatusSuccess, resultMsg)

	// 最后保存验证结果到Redis（包含详细的results JSON数据）
	// 注意：必须在updateTaskStatus之后调用，否则result字段会被纯文本覆盖，
	// 导致RPC层解析results失败，前端误判为"未发现漏洞"
	w.savePocValidationResult(ctx, task.TaskId, "", validationResults, "")
	// 注意：taskExecuted 由 executeTask 的 defer 递增，无需在此处理
}

// PocValidationResult POC验证结果
type PocValidationResult struct {
	PocId      string   `json:"pocId"`
	PocName    string   `json:"pocName"`
	TemplateId string   `json:"templateId"`
	Severity   string   `json:"severity"`
	Matched    bool     `json:"matched"`
	MatchedUrl string   `json:"matchedUrl"`
	Details    string   `json:"details"`
	Output     string   `json:"output"`
	PocType    string   `json:"pocType"`
	Tags       []string `json:"tags"`
}

// savePocValidationResult 保存POC验证结果
// NOTE: POC验证结果现在通过任务状态更新接口保存，不再直接写 Redis
func (w *Worker) savePocValidationResult(ctx context.Context, taskId, batchId string, results []*PocValidationResult, errorMsg string) {
	// 构建结果数据
	resultData := map[string]interface{}{
		"taskId":     taskId,
		"batchId":    batchId,
		"status":     "SUCCESS",
		"results":    results,
		"updateTime": time.Now().Local().Format("2006-01-02 15:04:05"),
	}

	if errorMsg != "" {
		resultData["status"] = "FAILURE"
		resultData["error"] = errorMsg
	}

	resultJson, err := json.Marshal(resultData)
	if err != nil {
		w.taskLog(taskId, LevelError, "Failed to marshal POC validation result: %v", err)
		return
	}

	// 通过 HTTP 接口更新任务结果
	status := scheduler.TaskStatusSuccess
	if errorMsg != "" {
		status = scheduler.TaskStatusFailure
	}
	_, err = w.httpClient.UpdateTask(ctx, &TaskUpdateReq{
		TaskId: taskId,
		State:  status,
		Result: string(resultJson),
	})
	if err != nil {
		w.taskLog(taskId, LevelError, "Failed to save POC validation result: %v", err)
	}
}

// WorkerHttpServiceChecker Worker端的HTTP服务检查器实现
type WorkerHttpServiceChecker struct {
	serviceCache map[string]bool // serviceName -> isHttp
	httpPorts    map[int]bool    // HTTP端口
	httpsPorts   map[int]bool    // HTTPS端口
	nonHttpPorts map[int]bool    // 非HTTP端口（明确排除）
	mu           sync.RWMutex
}

// NewWorkerHttpServiceChecker 创建HTTP服务检查器
func NewWorkerHttpServiceChecker() *WorkerHttpServiceChecker {
	return &WorkerHttpServiceChecker{
		serviceCache: make(map[string]bool),
		httpPorts:    make(map[int]bool),
		httpsPorts:   make(map[int]bool),
		nonHttpPorts: make(map[int]bool),
	}
}

// IsHttpService 判断服务名称是否为HTTP服务
func (c *WorkerHttpServiceChecker) IsHttpService(serviceName string) (isHttp bool, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	isHttp, found = c.serviceCache[serviceName]
	return
}

// IsHttpPort 判断端口是否为HTTP端口
func (c *WorkerHttpServiceChecker) IsHttpPort(port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.httpPorts[port] || c.httpsPorts[port]
}

// IsNonHttpPort 判断端口是否为非HTTP端口（明确排除）
func (c *WorkerHttpServiceChecker) IsNonHttpPort(port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nonHttpPorts[port]
}

// CheckIsHttp 综合判断是否为HTTP服务（服务名称+端口）
func (c *WorkerHttpServiceChecker) CheckIsHttp(serviceName string, port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. 先检查是否在非HTTP端口列表中（明确排除）
	if c.nonHttpPorts[port] {
		return false
	}

	// 2. 检查服务名称映射
	if isHttp, found := c.serviceCache[serviceName]; found {
		return isHttp
	}

	// 3. 检查HTTP/HTTPS端口
	return c.httpPorts[port] || c.httpsPorts[port]
}

// SetMapping 设置服务映射
func (c *WorkerHttpServiceChecker) SetMapping(serviceName string, isHttp bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serviceCache[serviceName] = isHttp
}

// SetHttpPorts 设置HTTP端口列表
func (c *WorkerHttpServiceChecker) SetHttpPorts(ports []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.httpPorts = make(map[int]bool)
	for _, port := range ports {
		c.httpPorts[port] = true
	}
}

// SetHttpsPorts 设置HTTPS端口列表
func (c *WorkerHttpServiceChecker) SetHttpsPorts(ports []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.httpsPorts = make(map[int]bool)
	for _, port := range ports {
		c.httpsPorts[port] = true
	}
}

// SetNonHttpPorts 设置非HTTP端口列表
func (c *WorkerHttpServiceChecker) SetNonHttpPorts(ports []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonHttpPorts = make(map[int]bool)
	for _, port := range ports {
		c.nonHttpPorts[port] = true
	}
}

// executePortIdentify 执行端口识别阶段（Nmap/Fingerprintx 服务识别）
func (w *Worker) executePortIdentify(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.PortIdentifyConfig) []*scanner.Asset {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "Port identify panic recovered: %v, stack: %s", r, string(getStackTrace()))
			// panic 时返回原始资产，确保任务能继续执行
			for _, asset := range assets {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
			}
		}
	}()

	// 确定使用的工具
	tool := config.Tool
	if tool == "" {
		w.taskLog(task.TaskId, LevelInfo, "Port identify: tool not specified, using default 'nmap'")
		tool = "nmap" // 默认使用 nmap
	}

	w.taskLog(task.TaskId, LevelInfo, "Port identify: using tool '%s' (%d assets)", tool, len(assets))

	// 根据工具选择不同的执行逻辑
	if tool == "fingerprintx" {
		w.taskLog(task.TaskId, LevelInfo, "Port identify: executing with Fingerprintx")
		return w.executePortIdentifyWithFingerprintx(ctx, task, assets, config)
	} else {
		w.taskLog(task.TaskId, LevelInfo, "Port identify: executing with Nmap")
		return w.executePortIdentifyWithNmap(ctx, task, assets, config)
	}
}

// executePortIdentifyWithNmap 使用 Nmap 执行端口识别
func (w *Worker) executePortIdentifyWithNmap(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.PortIdentifyConfig) []*scanner.Asset {
	// 获取超时配置
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 // 默认30秒/主机
	}

	// 按主机分组
	hostPorts := make(map[string][]int)
	hostAssets := make(map[string][]*scanner.Asset)
	for _, asset := range assets {
		hostPorts[asset.Host] = append(hostPorts[asset.Host], asset.Port)
		hostAssets[asset.Host] = append(hostAssets[asset.Host], asset)
	}

	// 计算总超时时间：单主机超时 × 主机数 / 并发数
	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	totalTimeout := timeout * len(hostPorts) / concurrency
	if totalTimeout < 60 {
		totalTimeout = 60
	}
	w.taskLog(task.TaskId, LevelInfo, "Port identify(nmap): timeout=%ds (single=%ds, hosts=%d, concurrency=%d)",
		totalTimeout, timeout, len(hostPorts), concurrency)

	// 使用分离的 Context 以避免前面模块的超时拖累此独立模块
	// 同时使用一个 goroutine 定期检查整个任务有没有被用户下发全局 STOP 命令
	identifyCtx, identifyCancel := context.WithTimeout(context.Background(), time.Duration(totalTimeout)*time.Second)
	defer identifyCancel()

	// 监听父上下文取消或主动停止信号
	go func() {
		select {
		case <-identifyCtx.Done():
		case <-ctx.Done(): // 接收任务全局退出（异常停滞等）
			identifyCancel()
		}
	}()

	var identifiedAssets []*scanner.Asset
	nmapScanner := w.scanners["nmap"]

	// Nmap 内部并发数（nmap 本身已有并发控制，这里限制同时扫描的端口数）
	nmapConcurrency := concurrency
	if nmapConcurrency > 5 {
		nmapConcurrency = 5
	}

	for host, ports := range hostPorts {
		// 检查是否被停止或超时
		if identifyCtx.Err() == context.DeadlineExceeded {
			w.taskLog(task.TaskId, LevelWarn, "Port identify timeout, using partial results")
			// 超时时使用原始资产
			for _, asset := range hostAssets[host] {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
				identifiedAssets = append(identifiedAssets, asset)
			}
			continue
		}
		if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
			w.taskLog(task.TaskId, LevelInfo, "Task stopped")
			return identifiedAssets
		}

		// 构建端口字符串
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		portsStr := strings.Join(portStrs, ",")

		// 构建 Nmap 选项
		nmapOpts := &scanner.NmapOptions{
			Ports:      portsStr,
			Timeout:    timeout,
			Concurrent: nmapConcurrency,
		}
		if config.Args != "" {
			nmapOpts.Args = config.Args
		}

		nmapResult, err := nmapScanner.Scan(identifyCtx, &scanner.ScanConfig{
			Target:  host,
			Options: nmapOpts,
			TaskLogger: func(level, format string, args ...interface{}) {
				w.taskLog(task.TaskId, level, format, args...)
			},
		})

		// 检查是否被停止
		if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
			w.taskLog(task.TaskId, LevelInfo, "Task stopped")
			return identifiedAssets
		}

		if err != nil {
			w.taskLog(task.TaskId, LevelError, "Nmap error %s: %v", host, err)
			// Nmap失败时，使用原始资产
			for _, asset := range hostAssets[host] {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
				identifiedAssets = append(identifiedAssets, asset)
			}
			continue
		}

		if nmapResult != nil && len(nmapResult.Assets) > 0 {
			// 设置 IsHTTP 字段
			for _, asset := range nmapResult.Assets {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
			}
			identifiedAssets = append(identifiedAssets, nmapResult.Assets...)
		} else {
			// Nmap没有结果时，使用原始资产
			for _, asset := range hostAssets[host] {
				asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
				identifiedAssets = append(identifiedAssets, asset)
			}
		}
	}

	w.taskLog(task.TaskId, LevelInfo, "Port identify completed: %d assets", len(identifiedAssets))
	return identifiedAssets
}

// executePortIdentifyWithFingerprintx 使用 Fingerprintx 执行端口识别
func (w *Worker) executePortIdentifyWithFingerprintx(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.PortIdentifyConfig) []*scanner.Asset {
	// 获取配置
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 // fingerprintx 默认10秒/目标
	}

	concurrency := config.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	// 按单目标超时计算总超时：单目标超时 × 目标数 / 并发数
	totalTimeout := timeout * len(assets) / concurrency
	if totalTimeout < 60 {
		totalTimeout = 60
	}
	w.taskLog(task.TaskId, LevelInfo, "Port identify(fingerprintx): timeout=%ds (single=%ds, assets=%d, concurrency=%d)",
		totalTimeout, timeout, len(assets), concurrency)

	// 同样做防超时继承处理，保证独立阶段时间充足
	fingerCtx, fingerCancel := context.WithTimeout(context.Background(), time.Duration(totalTimeout)*time.Second)
	defer fingerCancel()

	go func() {
		select {
		case <-fingerCtx.Done():
		case <-ctx.Done():
			fingerCancel()
		}
	}()

	// 构建 fingerprintx 选项
	fpxOpts := &scanner.FingerprintxOptions{
		Timeout:     timeout,
		Concurrency: concurrency,
		UDP:         config.UDP,
		FastMode:    config.FastMode,
	}

	// 创建扫描配置
	scanConfig := &scanner.ScanConfig{
		Assets:      assets,
		Options:     fpxOpts,
		WorkspaceId: task.WorkspaceId,
		MainTaskId:  task.TaskId,
		TaskLogger: func(level, format string, args ...interface{}) {
			w.taskLog(task.TaskId, level, format, args...)
		},
		OnProgress: func(progress int, message string) {
			// 可以在这里更新任务进度
			w.taskLog(task.TaskId, LevelDebug, "Progress: %d%% - %s", progress, message)
		},
	}

	// 执行扫描
	fpxScanner := w.scanners["fingerprintx"]
	result, err := fpxScanner.Scan(ctx, scanConfig)

	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Fingerprintx error: %v", err)
		// 失败时返回原始资产
		for _, asset := range assets {
			asset.IsHTTP = scanner.IsHTTPService(asset.Service, asset.Port)
		}
		return assets
	}

	w.taskLog(task.TaskId, LevelInfo, "Port identify completed: %d assets", len(result.Assets))
	return result.Assets
}

// executeBruteScan 执行弱口令扫描阶段
func (w *Worker) executeBruteScan(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.BruteScanConfig, orgId string) []*scanner.Vulnerability {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "Brute scan panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	// 过滤出可爆破的资产（有明确服务识别的资产）
	var bruteAssets []*scanner.Asset

	// 如果配置了服务列表，建立服务集合
	serviceSet := make(map[string]bool)
	hasServiceFilter := len(config.Services) > 0
	if hasServiceFilter {
		for _, svc := range config.Services {
			serviceSet[svc] = true
		}
	}

	for _, asset := range assets {
		if asset.Service == "" {
			continue
		}
		// 检查服务是否在目标列表中（只有配置了服务列表时才过滤）
		if hasServiceFilter && !serviceSet[asset.Service] {
			continue
		}
		bruteAssets = append(bruteAssets, asset)
	}

	if len(bruteAssets) == 0 {
		w.taskLog(task.TaskId, LevelInfo, "Brute scan: skipped (no service assets)")
		return nil
	}

	// 预检查：是否有资产匹配到暴力破解插件
	hasPlugin := false
	for _, asset := range bruteAssets {
		normalizedService := brute.NormalizeServiceName(asset.Service)
		if brute.GetPlugin(normalizedService) != nil {
			hasPlugin = true
			break
		}
	}
	if !hasPlugin {
		w.taskLog(task.TaskId, LevelInfo, "Brute scan: skipped (no matching brute-force plugin for detected services)")
		return nil
	}

	w.taskLog(task.TaskId, LevelInfo, "Brute scan: %d target assets, services=%v", len(bruteAssets), config.Services)

	// 获取字典内容
	// 字典格式是 user:password，需要拆分
	var usernameDict, passwordDict string
	usernameSet := make(map[string]struct{})
	passwordSet := make(map[string]struct{})

	// 服务特定字典：service -> entries
	serviceDicts := make(map[string][]scanner.ServiceDictEntry)

	// 获取要使用的字典ID列表和目标服务列表
	dictIds := config.WeakpassDictIds
	targetServices := config.Services

	// 获取字典内容（后端会根据服务类型过滤字典）
	dictResp, err := w.httpClient.GetWeakpassDicts(ctx, dictIds, targetServices)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Brute scan: get dicts failed: %v", err)
		return nil
	}

	if len(dictResp.Dicts) > 0 {
		for _, dict := range dictResp.Dicts {
			// 获取字典的服务类型
			serviceType := strings.ToLower(strings.TrimSpace(dict.Service))
			if serviceType == "" {
				serviceType = "common"
			}

			// 解析 user:password 格式的字典内容
			lines := strings.Split(dict.Content, "\n")
			currentService := serviceType

			for _, line := range lines {
				// 清理行尾的 \r（处理 Windows CRLF 格式）
				line = strings.TrimRight(line, "\r")
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// 检查是否是服务分组标记 [service]
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					currentService = strings.ToLower(strings.Trim(line, "[]"))
					continue
				}

				// 按冒号分割
				parts := strings.SplitN(line, ":", 2)
				username := ""
				password := ""
				if len(parts) >= 1 {
					username = strings.TrimSpace(parts[0])
				}
				if len(parts) >= 2 {
					password = strings.TrimSpace(parts[1])
				}

				// 添加到通用集合
				if username != "" {
					usernameSet[username] = struct{}{}
				}
				if password != "" {
					passwordSet[password] = struct{}{}
				}

				// 添加到服务特定字典
				if username != "" || password != "" {
					entry := scanner.ServiceDictEntry{
						Username: username,
						Password: password,
					}
					serviceDicts[currentService] = append(serviceDicts[currentService], entry)
				}
			}
		}
		// 去重后合并到字符串
		for u := range usernameSet {
			usernameDict += u + "\n"
		}
		for p := range passwordSet {
			passwordDict += p + "\n"
		}

		// 统计服务字典信息
		serviceDictInfo := make([]string, 0, len(serviceDicts))
		for svc, entries := range serviceDicts {
			serviceDictInfo = append(serviceDictInfo, fmt.Sprintf("%s(%d)", svc, len(entries)))
		}

		w.taskLog(task.TaskId, LevelInfo, "Brute scan: using %d dicts, %d usernames, %d passwords, services: %v",
			len(dictResp.Dicts), len(usernameSet), len(passwordSet), serviceDictInfo)
	}

	// 如果没有获取到字典内容且没有启用默认字典，跳过
	if usernameDict == "" && passwordDict == "" && len(serviceDicts) == 0 && !config.UseDefaultDict {
		w.taskLog(task.TaskId, LevelWarn, "Brute scan: no dicts configured")
		return nil
	}

	// 构建扫描配置 - 使用 Worker 的并发数
	bruteScanConfig := &scanner.BruteScanConfig{
		Services:       config.Services,
		Threads:        w.config.Concurrency, // 使用 Worker 并发数
		Timeout:        config.Timeout,
		DelayMs:        config.DelayMs,
		UseDefaultDict: config.UseDefaultDict,
		StopOnFirst:    config.StopOnFirst,
		ForceScan:      config.ForceScan,
		UsernameDict:   usernameDict,
		PasswordDict:   passwordDict,
		ServiceDicts:   serviceDicts,
	}

	// 构建扫描器配置
	scanConfig := &scanner.ScanConfig{
		Assets:      bruteAssets,
		Options:     bruteScanConfig,
		WorkspaceId: task.WorkspaceId,
		MainTaskId:  task.MainTaskId,
		TaskLogger: func(level, format string, args ...interface{}) {
			w.taskLog(task.TaskId, level, format, args...)
		},
	}

	// 获取 brutescan 扫描器
	bruteScanner, ok := w.scanners["brutescan"]
	if !ok {
		w.taskLog(task.TaskId, LevelError, "Brute scan: brutescan scanner not found")
		return nil
	}

	// 执行扫描
	result, err := bruteScanner.Scan(ctx, scanConfig)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Brute scan error: %v", err)
		return nil
	}

	// 保存漏洞结果
	if len(result.Vulnerabilities) > 0 {
		w.saveVulResult(ctx, task.WorkspaceId, task.MainTaskId, result.Vulnerabilities)
		w.taskLog(task.TaskId, LevelInfo, "Brute scan: saved %d vulnerabilities", len(result.Vulnerabilities))
	}

	return result.Vulnerabilities
}

// executeDirScan 执行目录扫描阶段
func (w *Worker) executeDirScan(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.DirScanConfig, orgId string) []*scanner.Asset {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "Directory scan panic recovered: %v, stack: %s", r, string(getStackTrace()))
			// panic 时返回 nil，让任务继续执行后续阶段
		}
	}()

	// 过滤出HTTP资产（必须同时满足 IsHTTP=true 且端口是常见HTTP端口或已确认为HTTP服务）
	var httpAssets []*scanner.Asset
	for _, asset := range assets {
		// 只有明确标记为HTTP服务的资产才进行目录扫描
		// 避免对非HTTP服务（如SSH、MySQL等）进行无效扫描
		if asset.IsHTTP && scanner.IsHTTPService(asset.Service, asset.Port) {
			httpAssets = append(httpAssets, asset)
		} else if asset.IsHTTP {
			// IsHTTP=true 但端口不是常见HTTP端口，记录跳过原因
			w.taskLog(task.TaskId, LevelDebug, "Dir scan: skipping %s:%d (port not recognized as HTTP service)", asset.Host, asset.Port)
		}
	}

	if len(httpAssets) == 0 {
		w.taskLog(task.TaskId, LevelInfo, "Dir scan: skipped (no HTTP assets)")
		return nil
	}

	w.taskLog(task.TaskId, LevelInfo, "Dir scan: %d HTTP assets, %d dicts", len(httpAssets), len(config.DictIds))

	// 获取字典内容
	if len(config.DictIds) == 0 {
		w.taskLog(task.TaskId, LevelWarn, "Dir scan: no dicts configured")
		return nil
	}

	dictResp, err := w.httpClient.GetDirScanDicts(ctx, config.DictIds)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Dir scan: get dicts failed: %v", err)
		return nil
	}

	if len(dictResp.Dicts) == 0 {
		w.taskLog(task.TaskId, LevelWarn, "Dir scan: no dicts found")
		return nil
	}

	// 合并所有字典的路径
	var allPaths []string
	pathSet := make(map[string]bool)
	for _, dict := range dictResp.Dicts {
		for _, path := range dict.Paths {
			if !pathSet[path] {
				pathSet[path] = true
				allPaths = append(allPaths, path)
			}
		}
		w.taskLog(task.TaskId, LevelInfo, "Dir scan: loaded dict '%s' with %d paths", dict.Name, len(dict.Paths))
	}

	if len(allPaths) == 0 {
		w.taskLog(task.TaskId, LevelWarn, "Dir scan: no paths in dicts")
		return nil
	}

	w.taskLog(task.TaskId, LevelInfo, "Dir scan: total %d unique paths", len(allPaths))

	// 获取扫描器（优先使用 ffuf）
	ffufScanner, ok := w.scanners["ffuf"]
	if !ok {
		w.taskLog(task.TaskId, LevelError, "Dir scan: ffuf scanner not found")
		return nil
	}

	// 构建扫描选项，使用 Worker 并发数
	threads := w.config.Concurrency
	if threads <= 0 {
		threads = 10
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	opts := &scanner.FFufOptions{
		Paths:           allPaths,
		Threads:         threads,
		Timeout:         timeout,
		Extensions:      config.Extensions,
		FollowRedirect:  config.FollowRedirect,
		AutoCalibration: config.AutoCalibration,
		FilterSize:      config.FilterSize,
		FilterWords:     config.FilterWords,
		FilterLines:     config.FilterLines,
		FilterRegex:     config.FilterRegex,
		MatcherMode:     config.MatcherMode,
		FilterMode:      config.FilterMode,
		Rate:            config.Rate,
		Recursion:       config.Recursion,
		RecursionDepth:  config.RecursionDepth,
	}

	// 按单目标超时计算总超时：单目标超时 × 资产数 × 路径数 / 线程数
	totalTimeout := timeout * len(httpAssets) * len(allPaths) / threads
	if totalTimeout < 60 {
		totalTimeout = 60
	}
	w.taskLog(task.TaskId, LevelInfo, "Dir scan: total timeout=%ds (single=%ds, assets=%d, paths=%d, threads=%d)",
		totalTimeout, timeout, len(httpAssets), len(allPaths), threads)
	dirCtx, dirCancel := context.WithTimeout(ctx, time.Duration(totalTimeout)*time.Second)
	defer dirCancel()

	// 创建任务日志回调
	taskLogger := func(level, format string, args ...interface{}) {
		w.taskLog(task.TaskId, level, format, args...)
	}

	// 创建进度回调
	onProgress := func(progress int, message string) {
		w.updateTaskProgress(ctx, task.TaskId, 70+progress/5, message) // 70-90%
	}

	// 执行扫描
	result, err := ffufScanner.Scan(dirCtx, &scanner.ScanConfig{
		Assets:      httpAssets,
		Options:     opts,
		WorkspaceId: task.WorkspaceId,
		MainTaskId:  task.MainTaskId,
		TaskLogger:  taskLogger,
		OnProgress:  onProgress,
	})

	// 检查是否超时
	if dirCtx.Err() == context.DeadlineExceeded {
		w.taskLog(task.TaskId, LevelWarn, "Dir scan timeout after %ds, using partial results", totalTimeout)
	}

	// 检查是否被停止
	if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
		w.taskLog(task.TaskId, LevelInfo, "Task stopped")
		return nil
	}

	if err != nil {
		// 目录扫描错误不应导致任务退出，只记录警告并继续
		w.taskLog(task.TaskId, LevelWarn, "Dir scan error (continuing): %v", err)
		// 如果有部分结果，仍然返回
		if result != nil && len(result.Assets) > 0 {
			w.taskLog(task.TaskId, LevelInfo, "Dir scan: returning %d partial results despite error", len(result.Assets))
			w.saveDirScanResults(ctx, task, result.Assets)
			return result.Assets
		}
		return nil
	}

	if result != nil && len(result.Assets) > 0 {
		w.taskLog(task.TaskId, LevelInfo, "Dir scan completed: found %d paths", len(result.Assets))

		// 保存目录扫描结果到数据库
		w.saveDirScanResults(ctx, task, result.Assets)

		return result.Assets
	}

	return nil
}

// saveDirScanResults 保存目录扫描结果到数据库
func (w *Worker) saveDirScanResults(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset) {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "Save directory scan results panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	if len(assets) == 0 {
		w.taskLog(task.TaskId, LevelDebug, "Dir scan: no assets to save")
		return
	}

	w.taskLog(task.TaskId, LevelInfo, "Dir scan: saving %d results to database", len(assets))

	// 转换为目录扫描结果文档
	var results []DirScanResultDocument
	for _, asset := range assets {
		// 构建完整URL
		scheme := "http"
		if asset.Port == 443 || strings.HasPrefix(asset.Service, "https") {
			scheme = "https"
		}
		var fullURL string
		if (scheme == "http" && asset.Port == 80) || (scheme == "https" && asset.Port == 443) {
			fullURL = fmt.Sprintf("%s://%s%s", scheme, asset.Host, asset.Path)
		} else {
			fullURL = fmt.Sprintf("%s://%s:%d%s", scheme, asset.Host, asset.Port, asset.Path)
		}

		results = append(results, DirScanResultDocument{
			Authority:     asset.Authority,
			Host:          asset.Host,
			Port:          asset.Port,
			URL:           fullURL,
			Path:          asset.Path,
			StatusCode:    parseStatusCode(asset.HttpStatus),
			ContentLength: asset.ContentLength,
			ContentType:   asset.ContentType,
			Title:         asset.Title,
			ContentWords:  asset.ContentWords,
			ContentLines:  asset.ContentLines,
			Duration:      asset.Duration,
		})
	}

	// 调用 HTTP 接口保存结果
	req := &DirScanResultReq{
		WorkspaceId: task.WorkspaceId,
		MainTaskId:  task.MainTaskId,
		Results:     results,
	}

	w.taskLog(task.TaskId, LevelDebug, "Dir scan: calling SaveDirScanResult API with %d results", len(results))

	resp, err := w.httpClient.SaveDirScanResult(ctx, req)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "Dir scan: save results failed: %v", err)
		return
	}

	if resp.Success {
		w.taskLog(task.TaskId, LevelInfo, "Dir scan: saved %d results to database", resp.Total)
	} else {
		w.taskLog(task.TaskId, LevelWarn, "Dir scan: save results response: %s", resp.Msg)
	}
}

// executeJSFinder 执行 JSFinder 扫描阶段（JS 敏感信息 + 未授权检测）
func (w *Worker) executeJSFinder(ctx context.Context, task *scheduler.TaskInfo, assets []*scanner.Asset, config *scheduler.JSFinderConfig, orgId string) []*scanner.JSFinderResult {
	defer func() {
		if r := recover(); r != nil {
			w.taskLog(task.TaskId, LevelError, "JSFinder panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	var httpAssets []*scanner.Asset
	for _, asset := range assets {
		if asset.IsHTTP || scanner.IsHTTPService(asset.Service, asset.Port) {
			httpAssets = append(httpAssets, asset)
		}
	}

	if len(httpAssets) == 0 {
		w.taskLog(task.TaskId, LevelInfo, "JSFinder: skipped (no HTTP assets)")
		return nil
	}

	// 拉取 4 份清单（高危路由 / 鉴权关键词 / 敏感数据关键词 / 域名黑名单）
	cfgResp, err := w.httpClient.LoadJSFinderConfig(ctx)
	if err != nil {
		w.taskLog(task.TaskId, LevelError, "JSFinder: load config failed: %v", err)
		return nil
	}
	if cfgResp.Code != 0 {
		w.taskLog(task.TaskId, LevelWarn, "JSFinder: load config response: %s", cfgResp.Msg)
		return nil
	}

	threads := config.Threads
	if threads <= 0 {
		threads = 10
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	// nil 表示用户未显式设置，默认视为 true；&false 表示用户明确关闭
	enableSourcemap := config.EnableSourcemap == nil || *config.EnableSourcemap
	enableUnauthCheck := config.EnableUnauthCheck == nil || *config.EnableUnauthCheck

	w.taskLog(task.TaskId, LevelInfo, "JSFinder: %d HTTP assets, threads=%d, timeout=%ds, sourcemap=%v, unauth=%v",
		len(httpAssets), threads, timeout, enableSourcemap, enableUnauthCheck)

	jsScanner, ok := w.scanners["jsfinder"]
	if !ok {
		w.taskLog(task.TaskId, LevelError, "JSFinder: scanner not found")
		return nil
	}

	opts := &scanner.JSFinderOptions{
		HighRiskRoutes:       cfgResp.HighRiskRoutes,
		AuthRequiredKeywords: cfgResp.AuthRequiredKeywords,
		SensitiveKeywords:    cfgResp.SensitiveKeywords,
		DomainBlacklist:      cfgResp.DomainBlacklist,
		Threads:              threads,
		Timeout:              timeout,
		EnableSourcemap:      enableSourcemap,
		EnableUnauthCheck:    enableUnauthCheck,
	}

	jsTaskLogger := func(level, format string, args ...interface{}) {
		w.taskLog(task.TaskId, level, format, args...)
	}

	result, err := jsScanner.Scan(ctx, &scanner.ScanConfig{
		Assets:      httpAssets,
		Options:     opts,
		WorkspaceId: task.WorkspaceId,
		MainTaskId:  task.MainTaskId,
		TaskLogger:  jsTaskLogger,
	})

	if ctx.Err() != nil || w.checkTaskControl(ctx, task.TaskId) == "STOP" {
		w.taskLog(task.TaskId, LevelInfo, "JSFinder: task stopped")
		return nil
	}

	if err != nil {
		w.taskLog(task.TaskId, LevelError, "JSFinder error: %v", err)
		return nil
	}

	if result == nil || len(result.JSFinderResults) == 0 {
		w.taskLog(task.TaskId, LevelInfo, "JSFinder: no findings")
		return nil
	}

	w.taskLog(task.TaskId, LevelInfo, "JSFinder: completed, found %d findings", len(result.JSFinderResults))
	return result.JSFinderResults
}

// parseStatusCode 解析状态码字符串为整数
func parseStatusCode(status string) int {
	if status == "" {
		return 0
	}
	var code int
	fmt.Sscanf(status, "%d", &code)
	return code
}

// generateHTTPAssetsFromTarget 从目标生成 HTTP 资产（用于只启用目录扫描的场景）
// 支持的目标格式：
// - 域名: example.com (默认生成 80 和 443 端口)
// - 带端口: example.com:8080
// - URL: http://example.com:8080 或 https://example.com
func (w *Worker) generateHTTPAssetsFromTarget(target string) []*scanner.Asset {
	var assets []*scanner.Asset

	targets := strings.Split(target, "\n")
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// 处理 URL 格式
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			asset := w.parseURLToAsset(t)
			if asset != nil {
				asset.IsHTTP = true
				assets = append(assets, asset)
			}
			continue
		}

		// 处理带端口的格式 host:port
		if strings.Contains(t, ":") && !strings.Contains(t, "/") {
			parts := strings.Split(t, ":")
			if len(parts) == 2 {
				host := parts[0]
				port := 80
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
				// 只有当端口是常见HTTP端口时才标记为HTTP服务
				isHTTP := scanner.IsHTTPService("", port)
				asset := &scanner.Asset{
					Host:      host,
					Port:      port,
					Authority: buildAuthority(host, port),
					IsHTTP:    isHTTP,
				}
				if isHTTP {
					assets = append(assets, asset)
				} else {
					w.logger.Debug("Skipping non-HTTP target: %s:%d", host, port)
				}
				continue
			}
		}

		// 跳过 CIDR 和 IP 范围格式（目录扫描不适用）
		if strings.Contains(t, "/") || (strings.Contains(t, "-") && !strings.Contains(t, ".")) {
			continue
		}

		// 单个主机（域名或IP），生成 80 和 443 端口
		for _, port := range []int{80, 443} {
			asset := &scanner.Asset{
				Host:      t,
				Port:      port,
				Authority: buildAuthority(t, port),
				Service:   map[int]string{80: "http", 443: "https"}[port],
				IsHTTP:    true,
			}
			assets = append(assets, asset)
		}
	}

	return assets
}

// generateAssetsFromTarget 从目标生成初始资产列表（用于端口扫描禁用时）
// 支持的目标格式：
// - 单个IP: 192.168.1.1
// - IP范围: 192.168.1.1-192.168.1.10
// - CIDR: 192.168.1.0/24
// - 域名: example.com
// - 带端口: 192.168.1.1:8080 或 example.com:443
// - URL: http://example.com:8080
// 域名无法解析到有效IPv4/IPv6地址时，该目标会被跳过
func (w *Worker) generateAssetsFromTarget(target string, portConfig *scheduler.PortScanConfig) []*scanner.Asset {
	var assets []*scanner.Asset

	// 默认端口列表（当不进行端口扫描时，默认只探测常见的 Web 端口）
	defaultPorts := []int{80, 443}

	// 只有在启用了端口扫描的情况下，才使用配置中的自定义端口列表进行资产拆分
	if portConfig != nil && portConfig.Enable && portConfig.Ports != "" {
		defaultPorts = parsePortList(portConfig.Ports)
	}

	// 解析目标
	targets := strings.Split(target, "\n")
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// 处理URL格式
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			asset := w.parseURLToAsset(t)
			if asset != nil && w.isDomainResolvable(asset.Host) {
				assets = append(assets, asset)
			} else if asset != nil {
				w.logger.Info("Skipping target %s: domain cannot be resolved to valid IP", asset.Host)
			}
			continue
		}

		// 处理带端口的格式 host:port
		if strings.Contains(t, ":") && !strings.Contains(t, "/") {
			parts := strings.Split(t, ":")
			if len(parts) == 2 {
				host := parts[0]
				port := 80
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
				if !w.isDomainResolvable(host) {
					w.logger.Info("Skipping target %s: domain cannot be resolved to valid IP", host)
					continue
				}
				asset := &scanner.Asset{
					Host:      host,
					Port:      port,
					Authority: fmt.Sprintf("%s:%d", host, port),
					IsHTTP:    scanner.IsHTTPService("", port),
				}
				assets = append(assets, asset)
				continue
			}
		}

		// 处理CIDR格式 - 跳过，因为没有端口扫描无法确定开放端口
		if strings.Contains(t, "/") {
			w.logger.Warn("CIDR target %s skipped: port scan disabled, cannot determine open ports", t)
			continue
		}

		// 处理IP范围格式 - 跳过
		if strings.Contains(t, "-") && !strings.Contains(t, ".") {
			w.logger.Warn("IP range target %s skipped: port scan disabled, cannot determine open ports", t)
			continue
		}

		// 单个主机（IP或域名），使用默认端口
		// 域名目标需先验证DNS解析
		if !w.isDomainResolvable(t) {
			w.logger.Info("Skipping target %s: domain cannot be resolved to valid IP", t)
			continue
		}
		for _, port := range defaultPorts {
			asset := &scanner.Asset{
				Host:      t,
				Port:      port,
				Authority: buildAuthority(t, port),
				IsHTTP:    scanner.IsHTTPService("", port),
			}
			assets = append(assets, asset)
		}
	}

	return assets
}

// isDomainResolvable 检查域名目标是否可以解析到有效的IPv4/IPv6地址
// IP地址目标直接返回true
func (w *Worker) isDomainResolvable(host string) bool {
	if host == "" {
		return false
	}
	// IP地址直接可用，无需DNS解析
	if net.ParseIP(host) != nil {
		return true
	}
	// 域名：尝试DNS解析
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	// 至少有一个非回环地址
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return true
		}
	}
	return false
}

// parseURLToAsset 解析URL为资产
func (w *Worker) parseURLToAsset(urlStr string) *scanner.Asset {
	// 简单解析URL
	scheme := "http"
	host := ""
	port := 80

	if strings.HasPrefix(urlStr, "https://") {
		scheme = "https"
		port = 443
		urlStr = strings.TrimPrefix(urlStr, "https://")
	} else if strings.HasPrefix(urlStr, "http://") {
		urlStr = strings.TrimPrefix(urlStr, "http://")
	}

	// 移除路径部分
	if idx := strings.Index(urlStr, "/"); idx > 0 {
		urlStr = urlStr[:idx]
	}

	// 解析host:port
	if strings.Contains(urlStr, ":") {
		parts := strings.Split(urlStr, ":")
		host = parts[0]
		if p, err := strconv.Atoi(parts[1]); err == nil {
			port = p
		}
	} else {
		host = urlStr
	}

	if host == "" {
		return nil
	}

	return &scanner.Asset{
		Host:      host,
		Port:      port,
		Authority: buildAuthority(host, port),
		Service:   scheme,
		IsHTTP:    true,
	}
}

// parsePortList 解析端口列表字符串
func parsePortList(portsStr string) []int {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 处理端口范围 (如 80-90)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start <= end {
					for p := start; p <= end && p <= 65535; p++ {
						if !seen[p] {
							seen[p] = true
							ports = append(ports, p)
						}
					}
				}
			}
		} else {
			// 单个端口
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		}
	}

	return ports
}

// initGeolocation 初始化 IP 地理位置服务
func (w *Worker) initGeolocation() {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Init geolocation panic recovered: %v", r)
		}
	}()

	w.logger.Info("InitGeolocation: starting initialization...")

	// 查找 data 目录（支持相对路径和绝对路径）
	dataDir := "data"

	// 首先检查当前目录下的 data
	if _, err := os.Stat(dataDir); err == nil {
		w.logger.Info("InitGeolocation: found data dir at current directory: %s", dataDir)
	} else {
		// 尝试可执行文件所在目录
		execPath, _ := os.Executable()
		if execPath != "" {
			projectRoot := filepath.Dir(execPath)
			dataDir = filepath.Join(projectRoot, "data")
			w.logger.Info("InitGeolocation: trying exec path: %s", dataDir)
		}
	}

	// 检查数据库文件是否存在
	v4Path := filepath.Join(dataDir, "ip2region_v4.xdb")
	w.logger.Info("InitGeolocation: checking database at: %s", v4Path)

	if _, err := os.Stat(v4Path); os.IsNotExist(err) {
		w.logger.Info("InitGeolocation: ip2region database NOT found at %s, geolocation disabled", v4Path)
		return
	}

	w.logger.Info("InitGeolocation: database file found, initializing service...")

	// 初始化 geolocation 服务
	config := geolocation.Config{
		Enabled:      true,
		DataDir:      dataDir,
		AutoDownload: false,
	}

	if err := geolocation.GetManager().InitWithConfig(config); err != nil {
		w.logger.Error("InitGeolocation: failed to init geolocation service: %v", err)
		return
	}

	w.logger.Info("InitGeolocation: SUCCESS, service initialized with data dir: %s", dataDir)
}

// loadHttpServiceMappings 从 HTTP 接口加载HTTP服务设置（端口配置+服务映射）
func (w *Worker) loadHttpServiceMappings() {
	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("Load HTTP service mappings panic recovered: %v, stack: %s", r, string(getStackTrace()))
		}
	}()

	ctx := context.Background()

	// 通过 HTTP 接口获取 HTTP 服务设置
	resp, err := w.httpClient.GetHttpServiceSettings(ctx)
	if err != nil {
		w.logger.Error("GetHttpServiceSettings HTTP failed: %v, using default settings", err)
		return
	}

	if !resp.Success {
		w.logger.Error("GetHttpServiceSettings failed: %s, using default settings", resp.Msg)
		return
	}

	// 创建检查器
	checker := NewWorkerHttpServiceChecker()

	// 设置端口配置
	if len(resp.Config.HttpPorts) > 0 {
		checker.SetHttpPorts(resp.Config.HttpPorts)
		w.logger.Info("Loaded %d HTTP ports from database", len(resp.Config.HttpPorts))
	}
	if len(resp.Config.HttpsPorts) > 0 {
		checker.SetHttpsPorts(resp.Config.HttpsPorts)
		w.logger.Info("Loaded %d HTTPS ports from database", len(resp.Config.HttpsPorts))
	}
	if len(resp.Config.NonHttpPorts) > 0 {
		checker.SetNonHttpPorts(resp.Config.NonHttpPorts)
		w.logger.Info("Loaded %d non-HTTP ports from database", len(resp.Config.NonHttpPorts))
	}

	// 设置服务映射
	for _, mapping := range resp.Mappings {
		checker.SetMapping(mapping.ServiceName, mapping.IsHttp)
	}
	if len(resp.Mappings) > 0 {
		w.logger.Info("Loaded %d HTTP service mappings from database", len(resp.Mappings))
	}

	// 设置全局检查器
	scanner.SetHttpServiceChecker(checker)
}

// getBlacklistMatcher 获取黑名单匹配器
func (w *Worker) getBlacklistMatcher(ctx context.Context, taskId string) *utils.BlacklistMatcher {
	// 从服务器获取黑名单规则
	resp, err := w.httpClient.GetBlacklistRules(ctx)
	if err != nil {
		w.taskLog(taskId, LevelWarn, "Failed to get blacklist rules: %v", err)
		return nil
	}

	if resp.Code != 0 {
		w.taskLog(taskId, LevelWarn, "Get blacklist rules failed: %s", resp.Msg)
		return nil
	}

	if len(resp.Rules) == 0 {
		return nil
	}

	matcher := utils.NewBlacklistMatcher(resp.Rules)
	w.taskLog(taskId, LevelDebug, "Loaded %d blacklist rules", matcher.RuleCount())
	return matcher
}

// filterAssetsByBlacklist 使用黑名单过滤资产
func (w *Worker) filterAssetsByBlacklist(assets []*scanner.Asset, matcher *utils.BlacklistMatcher, taskId string) []*scanner.Asset {
	if matcher == nil || matcher.IsEmpty() || len(assets) == 0 {
		return assets
	}

	var filtered []*scanner.Asset
	var skippedCount int

	for _, asset := range assets {
		// 检查主机名/域名
		if matcher.IsDomainBlacklisted(asset.Host) {
			skippedCount++
			continue
		}

		// 检查IP地址
		isBlacklisted := false
		for _, ipInfo := range asset.IPV4 {
			if matcher.IsIPBlacklisted(ipInfo.IP) {
				isBlacklisted = true
				break
			}
		}
		if isBlacklisted {
			skippedCount++
			continue
		}

		// 检查Authority（可能包含端口）
		if matcher.IsBlacklisted(asset.Authority) {
			skippedCount++
			continue
		}

		filtered = append(filtered, asset)
	}

	if skippedCount > 0 {
		w.taskLog(taskId, LevelInfo, "Blacklist: filtered %d assets", skippedCount)
	}

	return filtered
}

// filterAssetsByExcludeHosts 使用排除目标过滤资产（检查解析的IP）
// 与黑名单过滤类似，但专门用于端口扫描的排除目标配置
func (w *Worker) filterAssetsByExcludeHosts(assets []*scanner.Asset, matcher *utils.BlacklistMatcher, taskId string) []*scanner.Asset {
	if matcher == nil || matcher.IsEmpty() || len(assets) == 0 {
		return assets
	}

	var filtered []*scanner.Asset
	var skippedHosts []string

	for _, asset := range assets {
		// 检查主机名/域名本身是否在排除列表
		if matcher.IsBlacklisted(asset.Host) {
			skippedHosts = append(skippedHosts, asset.Host)
			continue
		}

		// 检查该资产解析出的所有IPv4地址
		isExcluded := false
		for _, ipInfo := range asset.IPV4 {
			if matcher.IsIPBlacklisted(ipInfo.IP) {
				isExcluded = true
				skippedHosts = append(skippedHosts, fmt.Sprintf("%s(%s)", asset.Host, ipInfo.IP))
				break
			}
		}
		if isExcluded {
			continue
		}

		filtered = append(filtered, asset)
	}

	if len(skippedHosts) > 0 {
		w.taskLog(taskId, LevelDebug, "ExcludeHosts: skipped targets: %v", skippedHosts)
	}

	return filtered
}
