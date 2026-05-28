package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/zeromicro/go-zero/core/logx"
)

// ==================== WebSocket Message Types ====================

const (
	WSTypeAuth           = "AUTH"            // 认证请求
	WSTypeAuthOK         = "AUTH_OK"         // 认证成功
	WSTypeAuthFail       = "AUTH_FAIL"       // 认证失败
	WSTypePing           = "PING"            // 心跳请求
	WSTypePong           = "PONG"            // 心跳响应
	WSTypeLog            = "LOG"             // 日志消息
	WSTypeLogBatch       = "LOG_BATCH"       // 批量日志消息
	WSTypeControl        = "CONTROL"         // 控制信号
	WSTypeTerminalOpen   = "TERMINAL_OPEN"   // 打开终端
	WSTypeTerminalClose  = "TERMINAL_CLOSE"  // 关闭终端
	WSTypeTerminalInput  = "TERMINAL_INPUT"  // 终端输入
	WSTypeTerminalOutput = "TERMINAL_OUTPUT" // 终端输出
	WSTypeTerminalResize = "TERMINAL_RESIZE" // 终端大小调整
	WSTypeFileList       = "FILE_LIST"       // 文件列表
	WSTypeFileUpload     = "FILE_UPLOAD"     // 文件上传
	WSTypeFileDownload   = "FILE_DOWNLOAD"   // 文件下载
	WSTypeFileDelete     = "FILE_DELETE"     // 文件删除
	WSTypeFileMkdir      = "FILE_MKDIR"      // 创建目录
	WSTypeWorkerInfo     = "WORKER_INFO"     // Worker信息
)

// WSMessage WebSocket消息结构
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WSAuthPayload 认证消息载荷
type WSAuthPayload struct {
	WorkerName string `json:"workerName"`
	InstallKey string `json:"installKey"`
}

// WSLogPayload 日志消息载荷
type WSLogPayload struct {
	TaskId    string `json:"taskId"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// WSLogBatchPayload 批量日志消息载荷
type WSLogBatchPayload struct {
	Logs []WSLogPayload `json:"logs"`
}

// WSControlPayload 控制信号载荷
type WSControlPayload struct {
	TaskId string `json:"taskId"`
	Action string `json:"action"` // STOP, PAUSE, RESUME
}

// ==================== WebSocket Client ====================

// WSClientConfig WebSocket客户端配�?
type WSClientConfig struct {
	ServerURL       string        // WebSocket服务器URL (e.g., ws://server:8888/api/v1/worker/ws)
	WorkerName      string        // Worker名称
	InstallKey      string        // 安装密钥
	ReconnectDelay  time.Duration // 初始重连延迟
	MaxReconnect    time.Duration // 最大重连延�?
	PingInterval    time.Duration // 心跳间隔
	WriteTimeout    time.Duration // 写超�?
	ReadTimeout     time.Duration // 读超�?
	LogBatchSize    int           // 日志批量发送大�?
	LogFlushTimeout time.Duration // 日志刷新超时
}

// DefaultWSClientConfig 默认配置
func DefaultWSClientConfig(serverURL, workerName, installKey string) *WSClientConfig {
	return &WSClientConfig{
		ServerURL:       serverURL,
		WorkerName:      workerName,
		InstallKey:      installKey,
		ReconnectDelay:  1 * time.Second,
		MaxReconnect:    30 * time.Second,
		PingInterval:    30 * time.Second,
		WriteTimeout:    10 * time.Second,
		ReadTimeout:     90 * time.Second,
		LogBatchSize:    50,
		LogFlushTimeout: 1 * time.Second,
	}
}

// ControlHandler 控制信号处理函数
type ControlHandler func(taskId, action string)

// WorkerInfoHandler Worker信息请求处理函数
type WorkerInfoHandler func() *WorkerInfoPayload

// FileOperationHandler 文件操作处理函数接口
type FileOperationHandler interface {
	ListDir(path string) ([]FileInfo, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
	DeleteFile(path string) error
	MakeDir(path string) error
}

// TerminalOperationHandler 终端操作处理函数接口
type TerminalOperationHandler interface {
	CreateSession(sessionId string) (*TerminalSession, error)
	CloseSession(sessionId string) error
	ExecuteCommand(ctx context.Context, sessionId, command string) error
	SendInput(sessionId string, data []byte) error
	ResizeTerminal(sessionId string, cols, rows int) error
	InterruptCommand(sessionId string) error
	IsCommandBlacklisted(command string) bool
}

// WorkerControlHandler Worker级别控制处理函数类型
type WorkerControlHandler func(action string, param string)

// WorkerWSClient Worker WebSocket客户�?
type WorkerWSClient struct {
	config               *WSClientConfig
	conn                 net.Conn
	connMu               sync.RWMutex
	connected            atomic.Bool
	authenticated        atomic.Bool
	closeChan            chan struct{}
	closeOnce            sync.Once
	sendChan             chan []byte
	logBuffer            []WSLogPayload
	logMu                sync.Mutex
	controlHandler       ControlHandler
	workerControlHandler WorkerControlHandler
	workerInfoHandler    WorkerInfoHandler
	fileHandler          FileOperationHandler
	terminalHandler      TerminalOperationHandler
	lastPong             time.Time
	pongMu               sync.RWMutex
	reconnecting         atomic.Bool
	readPaused           chan struct{} // 非 nil 时 readPump 暂停；关闭则恢复
	readPauseMu          sync.Mutex
	wg                   sync.WaitGroup
}

// NewWorkerWSClient 创建WebSocket客户�?
func NewWorkerWSClient(config *WSClientConfig) *WorkerWSClient {
	return &WorkerWSClient{
		config:    config,
		closeChan: make(chan struct{}),
		sendChan:  make(chan []byte, 4096),
		logBuffer: make([]WSLogPayload, 0, config.LogBatchSize),
		lastPong:  time.Now(),
	}
}

// SetControlHandler 设置控制信号处理函数
func (c *WorkerWSClient) SetControlHandler(handler ControlHandler) {
	c.controlHandler = handler
}

// SetWorkerControlHandler 设置Worker级别控制处理函数
func (c *WorkerWSClient) SetWorkerControlHandler(handler WorkerControlHandler) {
	c.workerControlHandler = handler
}

// SetWorkerInfoHandler 设置Worker信息请求处理函数
func (c *WorkerWSClient) SetWorkerInfoHandler(handler WorkerInfoHandler) {
	c.workerInfoHandler = handler
}

// SetFileHandler 设置文件操作处理函数
func (c *WorkerWSClient) SetFileHandler(handler FileOperationHandler) {
	c.fileHandler = handler
}

// SetTerminalHandler 设置终端操作处理函数
func (c *WorkerWSClient) SetTerminalHandler(handler TerminalOperationHandler) {
	c.terminalHandler = handler
}

// IsConnected 检查是否已连接
func (c *WorkerWSClient) IsConnected() bool {
	return c.connected.Load() && c.authenticated.Load()
}

// Connect 连接到WebSocket服务�?
func (c *WorkerWSClient) Connect(ctx context.Context) error {
	return c.connectWithRetry(ctx, false)
}

// connectWithRetry 带重试的连接
func (c *WorkerWSClient) connectWithRetry(ctx context.Context, isReconnect bool) error {
	backoff := c.config.ReconnectDelay
	attempt := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeChan:
			return fmt.Errorf("client closed")
		default:
		}

		err := c.doConnect(ctx)
		if err == nil {
			// 连接成功
			if isReconnect {
				logx.Info("[WSClient] Reconnected to server")
			} else {
				logx.Info("[WSClient] Connected to server")
			}
			return nil
		}

		attempt++
		logx.Infof("[WSClient] Connection attempt %d failed: %v, retrying in %v...", attempt, err, backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeChan:
			return fmt.Errorf("client closed")
		case <-time.After(backoff):
		}

		// 指数退�?
		backoff = time.Duration(float64(backoff) * 2)
		if backoff > c.config.MaxReconnect {
			backoff = c.config.MaxReconnect
		}
	}
}

// doConnect 执行单次连接
func (c *WorkerWSClient) doConnect(ctx context.Context) error {
	// 暂停 readPump，防止它与 authenticate() 竞争读同一连接
	unpause := c.pauseRead()
	defer unpause()

	// 解析WebSocket URL
	wsURL := c.buildWSURL()

	// 建立WebSocket连接
	conn, _, _, err := ws.Dial(ctx, wsURL)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
	c.connected.Store(true)

	// 发送认证消息
	if err := c.authenticate(); err != nil {
		conn.Close()
		c.connMu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.connMu.Unlock()
		c.connected.Store(false)
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.authenticated.Store(true)
	c.pongMu.Lock()
	c.lastPong = time.Now()
	c.pongMu.Unlock()

	return nil
}

// buildWSURL 构建WebSocket URL
func (c *WorkerWSClient) buildWSURL() string {
	serverURL := c.config.ServerURL

	// 如果已经是ws://或wss://开头，直接使用
	if strings.HasPrefix(serverURL, "ws://") || strings.HasPrefix(serverURL, "wss://") {
		return serverURL
	}

	// 将http://转换为ws://，https://转换为wss://
	if strings.HasPrefix(serverURL, "https://") {
		serverURL = "wss://" + strings.TrimPrefix(serverURL, "https://")
	} else if strings.HasPrefix(serverURL, "http://") {
		serverURL = "ws://" + strings.TrimPrefix(serverURL, "http://")
	} else {
		serverURL = "ws://" + serverURL
	}

	// 解析URL并添加路�?
	u, err := url.Parse(serverURL)
	if err != nil {
		return serverURL + "/api/v1/worker/ws"
	}

	// 如果没有路径或路径为/，添加WebSocket路径
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/v1/worker/ws"
	}

	return u.String()
}

// authenticate 发送认证消息并等待响应
func (c *WorkerWSClient) authenticate() error {
	// 构建认证消息
	authPayload := WSAuthPayload{
		WorkerName: c.config.WorkerName,
		InstallKey: c.config.InstallKey,
	}
	payloadData, _ := json.Marshal(authPayload)

	msg := WSMessage{
		Type:    WSTypeAuth,
		Payload: payloadData,
	}
	msgData, _ := json.Marshal(msg)

	// 发送认证消�?
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection is nil, may have been closed")
	}

	if err := wsutil.WriteClientMessage(conn, ws.OpText, msgData); err != nil {
		return fmt.Errorf("send auth message failed: %w", err)
	}

	// 等待认证响应（超�?0秒）
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		return fmt.Errorf("read auth response failed: %w", err)
	}

	var respMsg WSMessage
	if err := json.Unmarshal(data, &respMsg); err != nil {
		return fmt.Errorf("parse auth response failed: %w", err)
	}

	switch respMsg.Type {
	case WSTypeAuthOK:
		return nil
	case WSTypeAuthFail:
		var reason struct {
			Reason string `json:"reason"`
		}
		json.Unmarshal(respMsg.Payload, &reason)
		return fmt.Errorf("auth rejected: %s", reason.Reason)
	default:
		return fmt.Errorf("unexpected response type: %s", respMsg.Type)
	}
}

// Start 启动客户端（连接并启动读写协程）
func (c *WorkerWSClient) Start(ctx context.Context) error {
	// 连接服务�?
	if err := c.Connect(ctx); err != nil {
		return err
	}

	// 启动读取协程
	c.wg.Add(1)
	go c.readPump(ctx)

	// 启动写入协程
	c.wg.Add(1)
	go c.writePump(ctx)

	// 启动心跳协程
	c.wg.Add(1)
	go c.pingPump(ctx)

	// 启动日志刷新协程
	c.wg.Add(1)
	go c.logFlushPump(ctx)

	return nil
}

// Close 关闭客户�?
func (c *WorkerWSClient) Close() {
	c.closeOnce.Do(func() {
		close(c.closeChan)

		c.connMu.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil // 确保设为 nil，防止其�?goroutine 使用已关闭的连接
		}
		c.connMu.Unlock()

		c.connected.Store(false)
		c.authenticated.Store(false)
	})

	// 等待所有协程退�?
	c.wg.Wait()
}

// ==================== Read Pause Control ====================

// pauseRead 暂停 readPump，返回恢复函数
// 重连时调用，确保 readPump 不会与 authenticate() 竞争读同一连接
func (c *WorkerWSClient) pauseRead() (unpause func()) {
	c.readPauseMu.Lock()
	ch := make(chan struct{})
	c.readPaused = ch
	c.readPauseMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			c.readPauseMu.Lock()
			c.readPaused = nil
			c.readPauseMu.Unlock()
			close(ch)
		})
	}
}

// waitIfPaused 如果 readPump 被暂停则阻塞，直到恢复或 context/closeChan 关闭
func (c *WorkerWSClient) waitIfPaused(ctx context.Context) bool {
	c.readPauseMu.Lock()
	ch := c.readPaused
	c.readPauseMu.Unlock()

	if ch == nil {
		return true // 未暂停，继续
	}

	select {
	case <-ch:
		return true // 已恢复
	case <-ctx.Done():
		return false
	case <-c.closeChan:
		return false
	}
}

// ==================== Message Pumps ====================

// readPump 读取消息循环
func (c *WorkerWSClient) readPump(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeChan:
			return
		default:
		}

		// 重连期间暂停读取，避免与 authenticate() 竞争读同一连接
		if !c.waitIfPaused(ctx) {
			return
		}

		// 使用读锁保护整个读取操作，防止竞态条�?
		c.connMu.RLock()
		conn := c.conn
		if conn == nil {
			c.connMu.RUnlock()
			// 连接断开，等待重�?
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// 设置读取超时
		if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
			c.connMu.RUnlock()
			// 连接可能已关闭，触发重连
			if !c.handleReadError(ctx, err) {
				return
			}
			continue
		}

		data, _, err := wsutil.ReadServerData(conn)
		c.connMu.RUnlock()

		if err != nil {
			if !c.handleReadError(ctx, err) {
				return
			}
			continue
		}

		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			logx.Infof("[WSClient] Invalid message: %v", err)
			continue
		}

		// 路由消息
		c.handleMessage(&msg)
	}
}

// handleReadError 处理读取错误
func (c *WorkerWSClient) handleReadError(ctx context.Context, err error) bool {
	select {
	case <-c.closeChan:
		return false
	default:
	}

	logx.Infof("[WSClient] Read error: %v", err)

	// 关闭旧连�?
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	c.connected.Store(false)
	c.authenticated.Store(false)

	// 尝试重连
	if !c.reconnecting.CompareAndSwap(false, true) {
		// 已经在重连中，等待重连完�?
		for c.reconnecting.Load() {
			select {
			case <-c.closeChan:
				return false
			case <-ctx.Done():
				return false
			case <-time.After(100 * time.Millisecond):
				// 继续等待重连完成
			}
		}
		return true
	}

	// 使用独立�?context 进行重连，避免继承已取消的父 context
	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			reconnectCancel()
			c.reconnecting.Store(false)
		}()

		// 监听关闭信号
		go func() {
			select {
			case <-c.closeChan:
				reconnectCancel()
			case <-reconnectCtx.Done():
			}
		}()

		// 等待一小段时间再重连，避免立即重连
		select {
		case <-reconnectCtx.Done():
			return
		case <-time.After(time.Second):
		}

		if err := c.connectWithRetry(reconnectCtx, true); err != nil {
			logx.Infof("[WSClient] Reconnect failed: %v", err)
		}
	}()

	return true
}

// writePump 写入消息循环
func (c *WorkerWSClient) writePump(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeChan:
			return
		case data := <-c.sendChan:
			if !c.IsConnected() {
				// 未连接，丢弃消息
				continue
			}

			// 使用读锁保护整个写入操作
			c.connMu.RLock()
			conn := c.conn
			if conn == nil {
				c.connMu.RUnlock()
				continue
			}

			if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
				c.connMu.RUnlock()
				logx.Infof("[WSClient] SetWriteDeadline error: %v", err)
				c.connected.Store(false)
				continue
			}

			err := wsutil.WriteClientMessage(conn, ws.OpText, data)
			c.connMu.RUnlock()

			if err != nil {
				logx.Infof("[WSClient] Write error: %v", err)
				// 触发重连
				c.connected.Store(false)
			}
		}
	}
}

// pingPump 心跳循环
func (c *WorkerWSClient) pingPump(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	// 心跳超时阈值：2倍心跳间�?
	heartbeatTimeout := c.config.PingInterval * 2

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closeChan:
			return
		case <-ticker.C:
			if !c.IsConnected() {
				continue
			}

			// 检查是否超时未收到PONG
			c.pongMu.RLock()
			lastPong := c.lastPong
			c.pongMu.RUnlock()

			if time.Since(lastPong) > heartbeatTimeout {
				logx.Infof("[WSClient] Heartbeat timeout (no PONG for %v), triggering reconnect...", time.Since(lastPong))

				// 关闭当前连接并触发重�?
				c.connMu.Lock()
				if c.conn != nil {
					c.conn.Close()
					c.conn = nil
				}
				c.connMu.Unlock()

				c.connected.Store(false)
				c.authenticated.Store(false)

				// 触发重连（如果没有正在进行的重连�?
				if c.reconnecting.CompareAndSwap(false, true) {
					go func() {
						defer c.reconnecting.Store(false)

						// 使用独立�?context 进行重连
						reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
						defer reconnectCancel()

						// 监听关闭信号
						go func() {
							select {
							case <-c.closeChan:
								reconnectCancel()
							case <-reconnectCtx.Done():
							}
						}()

						time.Sleep(time.Second)
						if err := c.connectWithRetry(reconnectCtx, true); err != nil {
							logx.Infof("[WSClient] Reconnect from pingPump failed: %v", err)
						}
					}()
				}
				continue
			}

			// 发送PING
			c.sendMessage(&WSMessage{Type: WSTypePing})
		}
	}
}

// logFlushPump 日志刷新循环
func (c *WorkerWSClient) logFlushPump(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.LogFlushTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 退出前刷新剩余日志
			c.flushLogs()
			return
		case <-c.closeChan:
			c.flushLogs()
			return
		case <-ticker.C:
			c.flushLogs()
		}
	}
}

// ==================== Message Handling ====================

// handleMessage 处理接收到的消息
func (c *WorkerWSClient) handleMessage(msg *WSMessage) {
	switch msg.Type {
	case WSTypeAuthOK:
		// 认证成功（重连后可能收到�?
		c.authenticated.Store(true)
		logx.Info("[WSClient] Authentication successful (reconnected)")

	case WSTypeAuthFail:
		// 认证失败
		c.authenticated.Store(false)
		var reason struct {
			Reason string `json:"reason"`
		}
		json.Unmarshal(msg.Payload, &reason)
		logx.Infof("[WSClient] Authentication failed: %s", reason.Reason)

	case WSTypePing:
		// 收到服务器PING，回复PONG
		c.sendMessage(&WSMessage{Type: WSTypePong})
		c.pongMu.Lock()
		c.lastPong = time.Now()
		c.pongMu.Unlock()

	case WSTypePong:
		// 收到服务器PONG
		c.pongMu.Lock()
		c.lastPong = time.Now()
		c.pongMu.Unlock()

	case WSTypeControl:
		// 收到控制信号
		c.handleControl(msg.Payload)

	case WSTypeWorkerInfo:
		// 收到Worker信息请求
		c.handleWorkerInfoRequest(msg.Payload)

	case WSTypeFileList:
		// 收到文件列表请求
		c.handleFileListRequest(msg.Payload)

	case WSTypeFileUpload:
		// 收到文件上传请求
		c.handleFileUploadRequest(msg.Payload)

	case WSTypeFileDownload:
		// 收到文件下载请求
		c.handleFileDownloadRequest(msg.Payload)

	case WSTypeFileDelete:
		// 收到文件删除请求
		c.handleFileDeleteRequest(msg.Payload)

	case WSTypeFileMkdir:
		// 收到创建目录请求
		c.handleFileMkdirRequest(msg.Payload)

	case WSTypeTerminalOpen:
		// 收到打开终端请求
		c.handleTerminalOpenRequest(msg.Payload)

	case WSTypeTerminalClose:
		// 收到关闭终端请求
		c.handleTerminalCloseRequest(msg.Payload)

	case WSTypeTerminalInput:
		// 收到终端输入请求
		c.handleTerminalInputRequest(msg.Payload)

	case WSTypeTerminalResize:
		// 收到终端大小调整请求
		c.handleTerminalResizeRequest(msg.Payload)

	default:
		logx.Infof("[WSClient] Unknown message type: %s", msg.Type)
	}
}

// handleControl 处理控制信号
func (c *WorkerWSClient) handleControl(payload json.RawMessage) {
	// 先尝试解析为 Worker 级别控制命令
	var workerControl struct {
		Action      string `json:"action"`
		NewName     string `json:"newName,omitempty"`
		Concurrency int    `json:"concurrency,omitempty"`
	}
	if err := json.Unmarshal(payload, &workerControl); err == nil {
		logx.Infof("[WSClient] Parsed control action: '%s'", workerControl.Action)

		// 检查是否是 Worker 级别控制命令
		isWorkerControl := false
		switch workerControl.Action {
		case "WORKER_STOP":
			logx.Info("[WSClient] Executing WORKER_STOP command...")
			if c.workerControlHandler != nil {
				c.workerControlHandler("stop", "")
			} else {
				logx.Info("[WSClient] ERROR: workerControlHandler is nil!")
			}
			isWorkerControl = true
		case "WORKER_RESTART":
			logx.Info("[WSClient] Executing WORKER_RESTART command...")
			if c.workerControlHandler != nil {
				c.workerControlHandler("restart", "")
			} else {
				logx.Info("[WSClient] ERROR: workerControlHandler is nil!")
			}
			isWorkerControl = true
		case "WORKER_RENAME":
			logx.Infof("[WSClient] Executing WORKER_RENAME command, new name: %s", workerControl.NewName)
			if c.workerControlHandler != nil {
				c.workerControlHandler("rename", workerControl.NewName)
			}
			isWorkerControl = true
		case "WORKER_SET_CONCURRENCY":
			logx.Infof("[WSClient] Executing WORKER_SET_CONCURRENCY command, concurrency: %d", workerControl.Concurrency)
			if c.workerControlHandler != nil {
				c.workerControlHandler("setConcurrency", fmt.Sprintf("%d", workerControl.Concurrency))
			}
			isWorkerControl = true
		}

		if isWorkerControl {
			return
		}
	}

	// 解析为任务级别控制命�?
	var controlPayload WSControlPayload
	if err := json.Unmarshal(payload, &controlPayload); err != nil {
		logx.Infof("[WSClient] Invalid control payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received task control signal: taskId=%s, action=%s", controlPayload.TaskId, controlPayload.Action)

	if c.controlHandler != nil {
		c.controlHandler(controlPayload.TaskId, controlPayload.Action)
	}
}

// WSWorkerInfoRequest Worker信息请求载荷
type WSWorkerInfoRequest struct {
	RequestId string `json:"requestId"` // 请求ID，用于关联响�?
}

// WSWorkerInfoResponse Worker信息响应载荷
type WSWorkerInfoResponse struct {
	RequestId string             `json:"requestId"`
	Info      *WorkerInfoPayload `json:"info"`
	Error     string             `json:"error,omitempty"`
}

// handleWorkerInfoRequest 处理Worker信息请求
func (c *WorkerWSClient) handleWorkerInfoRequest(payload json.RawMessage) {
	var request WSWorkerInfoRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid worker info request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received worker info request: requestId=%s", request.RequestId)

	// 构建响应
	response := WSWorkerInfoResponse{
		RequestId: request.RequestId,
	}

	if c.workerInfoHandler != nil {
		response.Info = c.workerInfoHandler()
	} else {
		response.Error = "worker info handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeWorkerInfo,
		Payload: payloadData,
	})
}

// ==================== Send Methods ====================

// sendMessage 发送消息（内部方法�?
func (c *WorkerWSClient) sendMessage(msg *WSMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	select {
	case c.sendChan <- data:
		return nil
	case <-c.closeChan:
		return fmt.Errorf("client closed")
	default:
		return fmt.Errorf("send buffer full")
	}
}

// SendLog 发送单条日�?
func (c *WorkerWSClient) SendLog(taskId, level, message string) error {
	log := WSLogPayload{
		TaskId:    taskId,
		Level:     level,
		Message:   message,
		Timestamp: time.Now().UnixMilli(),
	}

	c.logMu.Lock()
	c.logBuffer = append(c.logBuffer, log)
	shouldFlush := len(c.logBuffer) >= c.config.LogBatchSize
	c.logMu.Unlock()

	if shouldFlush {
		c.flushLogs()
	}

	return nil
}

// SendLogImmediate 立即发送单条日志（不缓冲）
func (c *WorkerWSClient) SendLogImmediate(taskId, level, message string) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}

	payload := WSLogPayload{
		TaskId:    taskId,
		Level:     level,
		Message:   message,
		Timestamp: time.Now().UnixMilli(),
	}
	payloadData, _ := json.Marshal(payload)

	logx.Infof("[WSClient] SendLogImmediate: taskId=%s, level=%s, msg=%s", taskId, level, message)

	return c.sendMessage(&WSMessage{
		Type:    WSTypeLog,
		Payload: payloadData,
	})
}

// flushLogs 刷新日志缓冲�?
func (c *WorkerWSClient) flushLogs() {
	c.logMu.Lock()
	if len(c.logBuffer) == 0 {
		c.logMu.Unlock()
		return
	}

	logs := c.logBuffer
	c.logBuffer = make([]WSLogPayload, 0, c.config.LogBatchSize)
	c.logMu.Unlock()

	if !c.IsConnected() {
		// 未连接，输出到本地控制台
		logx.Infof("[WSClient] Not connected, flushing %d logs to console", len(logs))
		for _, log := range logs {
			logx.Infof("[%s] [%s] [Task:%s] %s",
				time.UnixMilli(log.Timestamp).Format("2006-01-02 15:04:05"),
				log.Level, log.TaskId, log.Message)
		}
		return
	}

	logx.Infof("[WSClient] Flushing %d logs to server", len(logs))

	// 发送批量日�?
	if len(logs) == 1 {
		// 单条日志直接发�?
		payloadData, _ := json.Marshal(logs[0])
		if err := c.sendMessage(&WSMessage{
			Type:    WSTypeLog,
			Payload: payloadData,
		}); err != nil {
			logx.Infof("[WSClient] Failed to send log: %v", err)
		}
	} else {
		// 多条日志批量发�?
		batchPayload := WSLogBatchPayload{Logs: logs}
		payloadData, _ := json.Marshal(batchPayload)
		if err := c.sendMessage(&WSMessage{
			Type:    WSTypeLogBatch,
			Payload: payloadData,
		}); err != nil {
			logx.Infof("[WSClient] Failed to send log batch: %v", err)
		}
	}
}

// ==================== Utility Methods ====================

// GetConn 获取底层连接（用于测试）
func (c *WorkerWSClient) GetConn() net.Conn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn
}

// WaitForConnection 等待连接建立
func (c *WorkerWSClient) WaitForConnection(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.IsConnected() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// ==================== File Operation Handlers ====================

// handleFileListRequest 处理文件列表请求
func (c *WorkerWSClient) handleFileListRequest(payload json.RawMessage) {
	var request FileListRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid file list request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received file list request: requestId=%s, path=%s", request.RequestId, request.Path)

	// 构建响应
	response := FileListResponse{
		RequestId: request.RequestId,
		Path:      request.Path,
	}

	if c.fileHandler != nil {
		files, err := c.fileHandler.ListDir(request.Path)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Files = files
		}
	} else {
		response.Error = "file handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeFileList,
		Payload: payloadData,
	})
}

// handleFileUploadRequest 处理文件上传请求
func (c *WorkerWSClient) handleFileUploadRequest(payload json.RawMessage) {
	var request FileUploadRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid file upload request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received file upload request: requestId=%s, path=%s", request.RequestId, request.Path)

	// 构建响应
	response := FileUploadResponse{
		RequestId: request.RequestId,
		Path:      request.Path,
	}

	if c.fileHandler != nil {
		// 解码Base64数据
		data, err := base64.StdEncoding.DecodeString(request.Data)
		if err != nil {
			response.Error = "invalid base64 data: " + err.Error()
		} else {
			err = c.fileHandler.WriteFile(request.Path, data)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.Success = true
			}
		}
	} else {
		response.Error = "file handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeFileUpload,
		Payload: payloadData,
	})
}

// handleFileDownloadRequest 处理文件下载请求
func (c *WorkerWSClient) handleFileDownloadRequest(payload json.RawMessage) {
	var request FileDownloadRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid file download request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received file download request: requestId=%s, path=%s", request.RequestId, request.Path)

	// 构建响应
	response := FileDownloadResponse{
		RequestId: request.RequestId,
		Path:      request.Path,
	}

	if c.fileHandler != nil {
		data, err := c.fileHandler.ReadFile(request.Path)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Data = base64.StdEncoding.EncodeToString(data)
			response.Size = int64(len(data))
		}
	} else {
		response.Error = "file handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeFileDownload,
		Payload: payloadData,
	})
}

// handleFileDeleteRequest 处理文件删除请求
func (c *WorkerWSClient) handleFileDeleteRequest(payload json.RawMessage) {
	var request FileDeleteRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid file delete request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received file delete request: requestId=%s, path=%s", request.RequestId, request.Path)

	// 构建响应
	response := FileDeleteResponse{
		RequestId: request.RequestId,
		Path:      request.Path,
	}

	if c.fileHandler != nil {
		err := c.fileHandler.DeleteFile(request.Path)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Success = true
		}
	} else {
		response.Error = "file handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeFileDelete,
		Payload: payloadData,
	})
}

// handleFileMkdirRequest 处理创建目录请求
func (c *WorkerWSClient) handleFileMkdirRequest(payload json.RawMessage) {
	var request FileMkdirRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid file mkdir request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received file mkdir request: requestId=%s, path=%s", request.RequestId, request.Path)

	// 构建响应
	response := FileMkdirResponse{
		RequestId: request.RequestId,
		Path:      request.Path,
	}

	if c.fileHandler != nil {
		err := c.fileHandler.MakeDir(request.Path)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Success = true
		}
	} else {
		response.Error = "file handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeFileMkdir,
		Payload: payloadData,
	})
}

// ==================== Terminal Operation Handlers ====================

// handleTerminalOpenRequest 处理打开终端请求
func (c *WorkerWSClient) handleTerminalOpenRequest(payload json.RawMessage) {
	var request TerminalOpenRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid terminal open request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received terminal open request: requestId=%s, sessionId=%s", request.RequestId, request.SessionId)

	// 构建响应
	response := TerminalOpenResponse{
		RequestId: request.RequestId,
		SessionId: request.SessionId,
	}

	if c.terminalHandler != nil {
		session, err := c.terminalHandler.CreateSession(request.SessionId)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Success = true
			// 如果指定了终端大小，设置�?
			if request.Cols > 0 && request.Rows > 0 {
				c.terminalHandler.ResizeTerminal(session.ID, request.Cols, request.Rows)
			}
		}
	} else {
		response.Error = "terminal handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeTerminalOpen,
		Payload: payloadData,
	})
}

// handleTerminalCloseRequest 处理关闭终端请求
func (c *WorkerWSClient) handleTerminalCloseRequest(payload json.RawMessage) {
	var request TerminalCloseRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid terminal close request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received terminal close request: requestId=%s, sessionId=%s", request.RequestId, request.SessionId)

	// 构建响应
	response := TerminalCloseResponse{
		RequestId: request.RequestId,
		SessionId: request.SessionId,
	}

	if c.terminalHandler != nil {
		err := c.terminalHandler.CloseSession(request.SessionId)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Success = true
		}
	} else {
		response.Error = "terminal handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeTerminalClose,
		Payload: payloadData,
	})
}

// handleTerminalInputRequest 处理终端输入请求
func (c *WorkerWSClient) handleTerminalInputRequest(payload json.RawMessage) {
	var request TerminalInputRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid terminal input request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received terminal input request: requestId=%s, sessionId=%s", request.RequestId, request.SessionId)

	// 构建响应
	response := TerminalInputResponse{
		RequestId: request.RequestId,
		SessionId: request.SessionId,
	}

	if c.terminalHandler != nil {
		// 如果有直接命令，执行命令
		if request.Command != "" {
			// 检查命令是否在黑名单中
			if c.terminalHandler.IsCommandBlacklisted(request.Command) {
				response.Error = "command is blacklisted"
			} else {
				err := c.terminalHandler.ExecuteCommand(context.Background(), request.SessionId, request.Command)
				if err != nil {
					response.Error = err.Error()
				} else {
					response.Success = true
				}
			}
		} else if request.Data != "" {
			// 解码Base64数据并发送到stdin
			data, err := DecodeTerminalInput(request.Data)
			if err != nil {
				response.Error = "invalid base64 data: " + err.Error()
			} else {
				// 检查是否是Ctrl+C (0x03)
				if len(data) == 1 && data[0] == 0x03 {
					err = c.terminalHandler.InterruptCommand(request.SessionId)
				} else {
					err = c.terminalHandler.SendInput(request.SessionId, data)
				}
				if err != nil {
					response.Error = err.Error()
				} else {
					response.Success = true
				}
			}
		} else {
			response.Error = "no command or data provided"
		}
	} else {
		response.Error = "terminal handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeTerminalInput,
		Payload: payloadData,
	})
}

// handleTerminalResizeRequest 处理终端大小调整请求
func (c *WorkerWSClient) handleTerminalResizeRequest(payload json.RawMessage) {
	var request TerminalResizeRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		logx.Infof("[WSClient] Invalid terminal resize request payload: %v", err)
		return
	}

	logx.Infof("[WSClient] Received terminal resize request: requestId=%s, sessionId=%s, cols=%d, rows=%d", request.RequestId, request.SessionId, request.Cols, request.Rows)

	// 构建响应
	response := TerminalResizeResponse{
		RequestId: request.RequestId,
		SessionId: request.SessionId,
	}

	if c.terminalHandler != nil {
		err := c.terminalHandler.ResizeTerminal(request.SessionId, request.Cols, request.Rows)
		if err != nil {
			response.Error = err.Error()
		} else {
			response.Success = true
		}
	} else {
		response.Error = "terminal handler not set"
	}

	// 发送响�?
	payloadData, _ := json.Marshal(response)
	c.sendMessage(&WSMessage{
		Type:    WSTypeTerminalResize,
		Payload: payloadData,
	})
}

// SendTerminalOutput 发送终端输�?
func (c *WorkerWSClient) SendTerminalOutput(sessionId string, data []byte) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}

	payload := TerminalOutputPayload{
		SessionId: sessionId,
		Data:      EncodeTerminalOutput(data),
	}
	payloadData, _ := json.Marshal(payload)

	return c.sendMessage(&WSMessage{
		Type:    WSTypeTerminalOutput,
		Payload: payloadData,
	})
}
