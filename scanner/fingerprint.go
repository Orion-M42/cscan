package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cscan/model"
	"cscan/pkg/utils"

	"github.com/chromedp/chromedp"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/zeromicro/go-zero/core/logx"
)

// chromedp 全局持久化分配器，避免每次截图创建/销毁 Chrome 进程
// 使用 context.Background() 确保不因外部 context 取消而触发 chromedp 内部的 close-of-closed-channel panic
var (
	globalAllocCtx    context.Context
	globalAllocCancel context.CancelFunc
	globalAllocOnce   sync.Once
)

func getGlobalAllocator() (context.Context, context.CancelFunc) {
	globalAllocOnce.Do(func() {
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", false),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-web-security", true),
			chromedp.Flag("disable-features", "VizDisplayCompositor"),
			chromedp.Flag("disable-background-timer-throttling", true),
			chromedp.Flag("disable-backgrounding-occluded-windows", true),
			chromedp.Flag("disable-renderer-backgrounding", true),
			chromedp.Flag("force-color-profile", "srgb"),
			chromedp.WindowSize(1920, 1080),
			chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
		)
		if chromePath := os.Getenv("CHROME_BIN"); chromePath != "" {
			opts = append(opts, chromedp.ExecPath(chromePath))
		}
		// 使用 Background context，不随任务取消而销毁分配器
		globalAllocCtx, globalAllocCancel = chromedp.NewExecAllocator(context.Background(), opts...)
	})
	return globalAllocCtx, globalAllocCancel
}

// FingerprintScanner 指纹扫描器
// 使用 assetMutex 保护对共享 asset 数据的并发访问
type FingerprintScanner struct {
	BaseScanner
	client                  *http.Client
	wappalyzerClient        *wappalyzer.Wappalyze
	customFingerprintEngine *CustomFingerprintEngine
	// assetMutex 保护 httpx 回调和主循环对同一 asset 的并发访问
	assetMutex sync.Mutex
	// httpxDone 标记 httpx 扫描是否完成，用于主循环等待
	httpxDone   bool
	httpxDoneMu sync.Mutex
}

// AppDetectionResult 应用检测结果，用于合并多个来源的识别结果
type AppDetectionResult struct {
	Name         string   // 应用名称
	OriginalName string   // 原始名称（可能包含版本号）
	Sources      []string // 检测来源：httpx, wappalyzer, custom
	CustomIDs    []string // 自定义指纹的ID列表
	ActiveIDs    []string // 主动指纹的ID列表
}

// NewFingerprintScanner 创建指纹扫描器
func NewFingerprintScanner() *FingerprintScanner {
	wappalyzerClient, _ := wappalyzer.New()
	return &FingerprintScanner{
		BaseScanner: BaseScanner{name: "fingerprint"},
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		wappalyzerClient: wappalyzerClient,
	}
}

// SetCustomFingerprintEngine 设置自定义指纹引擎
func (s *FingerprintScanner) SetCustomFingerprintEngine(engine *CustomFingerprintEngine) {
	s.customFingerprintEngine = engine
}

// FingerprintOptions 指纹识别选项
type FingerprintOptions struct {
	Enable        bool   `json:"enable"`
	Tool          string `json:"tool"`  // 探测工具: httpx, builtin (默认httpx)
	Httpx         bool   `json:"httpx"` // 已废弃，兼容旧配置
	Screenshot    bool   `json:"screenshot"`
	IconHash      bool   `json:"iconHash"`
	Wappalyzer    bool   `json:"wappalyzer"`
	CustomEngine  bool   `json:"customEngine"`  // 使用自定义指纹引擎
	ActiveScan    bool   `json:"activeScan"`    // 启用主动指纹扫描
	ActiveTimeout int    `json:"activeTimeout"` // 主动指纹单个请求超时时间(秒)，默认10秒
	Timeout       int    `json:"timeout"`       // 总超时时间(秒)，默认300秒
	TargetTimeout int    `json:"targetTimeout"` // 单个目标超时时间(秒)，默认30秒
	Concurrency   int    `json:"concurrency"`   // 并发数，默认10
}

// Validate 验证 FingerprintOptions 配置是否有效
// 实现 ScannerOptions 接口
func (o *FingerprintOptions) Validate() error {
	if o.Tool != "" && o.Tool != "httpx" && o.Tool != "builtin" {
		return fmt.Errorf("tool must be 'httpx' or 'builtin', got %s", o.Tool)
	}
	if o.ActiveTimeout < 0 {
		return fmt.Errorf("activeTimeout must be non-negative, got %d", o.ActiveTimeout)
	}
	if o.Timeout < 0 {
		return fmt.Errorf("timeout must be non-negative, got %d", o.Timeout)
	}
	if o.TargetTimeout < 0 {
		return fmt.Errorf("targetTimeout must be non-negative, got %d", o.TargetTimeout)
	}
	if o.Concurrency < 0 {
		return fmt.Errorf("concurrency must be non-negative, got %d", o.Concurrency)
	}
	return nil
}

// Scan 执行指纹识别
func (s *FingerprintScanner) Scan(ctx context.Context, config *ScanConfig) (*ScanResult, error) {
	// 解析配置 - 使用自适应参数
	adaptive := GetGlobalAdaptiveConfig()
	opts := &FingerprintOptions{
		Enable:        true,
		Tool:          "httpx", // 默认使用httpx
		IconHash:      true,
		Wappalyzer:    true,
		CustomEngine:  true, // 默认启用自定义指纹引擎
		Screenshot:    false,
		Timeout:       adaptive.FingerprintTimeout,     // 自适应: 低配600s, 中配300s, 高配300s
		TargetTimeout: adaptive.FingerprintTargetTmout, // 自适应: 低配60s, 中配90s, 高配90s
		Concurrency:   adaptive.FingerprintConcurrency, // 自适应: 低配3, 中配5, 高配5
	}
	if config.Options != nil {
		switch v := config.Options.(type) {
		case *FingerprintOptions:
			opts = v
		default:
			if data, err := json.Marshal(config.Options); err == nil {
				json.Unmarshal(data, opts)
			}
		}
	}

	// 兼容旧配置：如果Tool为空但Httpx为true，使用httpx
	if opts.Tool == "" {
		if opts.Httpx {
			opts.Tool = "httpx"
		} else {
			opts.Tool = "builtin"
		}
	}

	// 根据工具选择自动设置 Wappalyzer
	// httpx 自带技术检测，builtin 使用 wappalyzergo
	if opts.Tool == "builtin" {
		opts.Wappalyzer = true
	}

	// 设置默认值
	if opts.TargetTimeout <= 0 {
		opts.TargetTimeout = 30
	}

	// 限制最大并发数，避免过度并发
	if opts.Concurrency > 5 {
		opts.Concurrency = 5
	}

	// 日志辅助函数
	taskLog := func(level, format string, args ...interface{}) {
		if config.TaskLogger != nil {
			config.TaskLogger(level, format, args...)
		}
		logx.Infof(format, args...)
	}

	result := &ScanResult{
		WorkspaceId: config.WorkspaceId,
		MainTaskId:  config.MainTaskId,
		Assets:      make([]*Asset, 0),
	}

	// 使用传入的资产（worker层已过滤HTTP资产）
	httpAssets := config.Assets
	if len(httpAssets) == 0 {
		taskLog("INFO", "Fingerprint: no assets to scan, skipping")
		return result, nil
	}

	taskLog("INFO", "Fingerprint: scanning %d assets, tool=%s, timeout %ds/target", len(httpAssets), opts.Tool, opts.TargetTimeout)

	// 根据选择的工具执行扫描
	useHttpx := opts.Tool == "httpx"
	if useHttpx {
		// 使用httpx库进行扫描（不再依赖命令行工具）
		taskLog("DEBUG", "Using httpx library for fingerprint detection")
		s.runHttpxLib(ctx, httpAssets, opts, taskLog)
	} else {
		taskLog("DEBUG", "Using builtin method for fingerprint detection")
	}

	// 记录已处理的资产索引，用于超时时补充未处理的资产
	processedSet := make(map[int]bool)

	// 扫描每个目标
	for i, asset := range httpAssets {
		select {
		case <-ctx.Done():
			taskLog("WARN", "Fingerprint scan timeout after processing %d/%d assets, preserving httpx results for remaining assets", len(processedSet), len(httpAssets))
			// 超时时，将 httpx 已获取到基本信息但未进行补充扫描的资产也加入结果
			for j := i; j < len(httpAssets); j++ {
				remainAsset := httpAssets[j]
				if remainAsset.Title != "" || remainAsset.HttpStatus != "" || len(remainAsset.App) > 0 {
					taskLog("DEBUG", "Preserving httpx result for %s:%d (title=%s, apps=%d)", remainAsset.Host, remainAsset.Port, remainAsset.Title, len(remainAsset.App))
				}
				result.Assets = append(result.Assets, remainAsset)
				if config.OnAssetUpdated != nil {
					config.OnAssetUpdated(remainAsset)
				}
			}
			taskLog("INFO", "Fingerprint: total %d assets preserved after timeout", len(result.Assets))
			return result, nil
		default:
			// 如果使用httpx且已获取到基本信息，只执行附加功能
			if useHttpx && asset.Title != "" && asset.HttpStatus != "" {
				taskLog("INFO", "Fingerprint [%d/%d]: %s:%d", i+1, len(httpAssets), asset.Host, asset.Port)
				targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(opts.TargetTimeout)*time.Second)
				s.runAdditionalFingerprint(targetCtx, asset, opts, taskLog)
				if targetCtx.Err() == context.DeadlineExceeded {
					taskLog("WARN", "Fingerprint: %s:%d timeout", asset.Host, asset.Port)
				}
				targetCancel()
			} else {
				// 使用内置方法完整扫描
				taskLog("INFO", "Fingerprint [%d/%d]: %s:%d", i+1, len(httpAssets), asset.Host, asset.Port)
				targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(opts.TargetTimeout)*time.Second)
				s.fingerprint(targetCtx, asset, opts, taskLog)
				if targetCtx.Err() == context.DeadlineExceeded {
					taskLog("WARN", "Fingerprint: %s:%d timeout", asset.Host, asset.Port)
				}
				targetCancel()
			}
			processedSet[i] = true
			result.Assets = append(result.Assets, asset)

			// 触发流式更新回调
			if config.OnAssetUpdated != nil {
				config.OnAssetUpdated(asset)
			}
		}
	}

	// 确保所有已扫描的 HTTP 资产 IsHTTP 标记正确
	// 修复：httpx 等工具可能未正确设置 IsHTTP，导致下游模块（JSFinder/DirScan）跳过该资产
	for _, asset := range httpAssets {
		if asset.HttpStatus != "" || asset.Title != "" || asset.Service == "http" || asset.Service == "https" {
			asset.IsHTTP = true
		}
	}

	taskLog("INFO", "Fingerprint: completed passive scan, scanned %d assets", len(httpAssets))

	// 执行主动指纹扫描（如果启用）
	if opts.ActiveScan {
		if s.customFingerprintEngine != nil {
			activeCount := s.customFingerprintEngine.GetActiveFingerprintCount()
			taskLog("INFO", "Active fingerprint scan enabled, engine has %d active fingerprints", activeCount)
			if activeCount > 0 {
				s.RunActiveFingerprint(ctx, httpAssets, opts, taskLog)
			} else {
				taskLog("WARN", "Active fingerprint scan enabled but no active fingerprints loaded")
			}
		} else {
			taskLog("WARN", "Active fingerprint scan enabled but customFingerprintEngine is nil")
		}
	} else {
		taskLog("DEBUG", "Active fingerprint scan not enabled (activeScan=%v)", opts.ActiveScan)
	}

	return result, nil
}

// httpServiceConfig HTTP服务检测配置 - 消除特殊情况处理
var (
	defaultHttpServices = map[string]bool{
		"http": true, "https": true, "http-proxy": true,
		"https-alt": true, "http-alt": true, "ajp12": true, "esmagent": true,
	}
	nonHttpServices = map[string]bool{
		"ssh": true, "ftp": true, "smtp": true, "pop3": true, "imap": true,
		"mysql": true, "mssql": true, "oracle": true, "postgresql": true, "redis": true,
		"mongodb": true, "memcached": true, "elasticsearch": true,
		"dns": true, "snmp": true, "ldap": true, "smb": true, "netbios": true,
		"rdp": true, "vnc": true, "telnet": true, "rpc": true,
		"ntp": true, "tftp": true, "sip": true, "rtsp": true,
	}
	commonHttpPorts = map[int]bool{
		80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true,
		8081: true, 8082: true, 8083: true, 8084: true, 8085: true,
		9000: true, 9001: true, 9090: true, 9443: true,
		3000: true, 3001: true, 4000: true, 5000: true, 5001: true,
		7001: true, 7002: true, 8180: true,
		8280: true, 8380: true, 8480: true, 8580: true,
		10000: true, 10001: true, 10080: true, 10443: true,
		8800: true, 8880: true, 8881: true, 18080: true, 28080: true,
	}
)

// IsHttpAsset 判断资产是否为HTTP/HTTPS服务
// 重构：使用策略链模式消除多层if/else
func IsHttpAsset(asset *Asset) bool {
	// 策略链：按优先级依次检查
	checks := []func(*Asset) (isHttp bool, decided bool){
		checkByIsHTTPFlag,
		checkByGlobalChecker,
		checkByNonHttpPorts, // 新增：检查非HTTP端口（优先排除）
		checkByDefaultServices,
		checkByNonHttpServices,
		checkByCommonPorts,
		checkByEmptyService,
	}

	for _, check := range checks {
		if isHttp, decided := check(asset); decided {
			return isHttp
		}
	}
	return false
}

func checkByIsHTTPFlag(asset *Asset) (bool, bool) {
	if asset.IsHTTP {
		return true, true
	}
	return false, false
}

func checkByGlobalChecker(asset *Asset) (bool, bool) {
	if globalHttpServiceChecker == nil {
		return false, false
	}
	service := strings.ToLower(asset.Service)
	if isHttp, found := globalHttpServiceChecker.IsHttpService(service); found {
		return isHttp, true
	}
	return false, false
}

// checkByNonHttpPorts 检查是否在配置的非HTTP端口列表中
func checkByNonHttpPorts(asset *Asset) (bool, bool) {
	if globalHttpServiceChecker == nil {
		return false, false
	}
	if globalHttpServiceChecker.IsNonHttpPort(asset.Port) {
		return false, true // 明确排除
	}
	return false, false
}

func checkByDefaultServices(asset *Asset) (bool, bool) {
	service := strings.ToLower(asset.Service)
	if defaultHttpServices[service] {
		return true, true
	}
	return false, false
}

func checkByNonHttpServices(asset *Asset) (bool, bool) {
	service := strings.ToLower(asset.Service)
	if nonHttpServices[service] {
		return false, true
	}
	return false, false
}

func checkByCommonPorts(asset *Asset) (bool, bool) {
	if commonHttpPorts[asset.Port] {
		return true, true
	}
	return false, false
}

func checkByEmptyService(asset *Asset) (bool, bool) {
	if strings.ToLower(asset.Service) == "" {
		return true, true // 空服务名，让fingerprint函数去实际探测
	}

	// 如果全局检查器存在，检查服务名是否在配置中
	// 对于不在配置中的未知服务（如cbt），也尝试HTTP探测
	if globalHttpServiceChecker != nil {
		if _, found := globalHttpServiceChecker.IsHttpService(strings.ToLower(asset.Service)); !found {
			// 服务名不在配置中，尝试HTTP探测
			return true, true
		}
	}

	return false, false
}

// HttpServiceChecker HTTP服务检查器接口
type HttpServiceChecker interface {
	IsHttpService(serviceName string) (isHttp bool, found bool)
	IsHttpPort(port int) bool
	IsNonHttpPort(port int) bool
	CheckIsHttp(serviceName string, port int) bool
}

// 全局HTTP服务检查器
var globalHttpServiceChecker HttpServiceChecker

// SetHttpServiceChecker 设置全局HTTP服务检查器
func SetHttpServiceChecker(checker HttpServiceChecker) {
	globalHttpServiceChecker = checker
}

// GetHttpServiceChecker 获取全局HTTP服务检查器
func GetHttpServiceChecker() HttpServiceChecker {
	return globalHttpServiceChecker
}

// runAdditionalFingerprint 执行额外的指纹识别功能（httpx已执行后）
func (s *FingerprintScanner) runAdditionalFingerprint(ctx context.Context, asset *Asset, opts *FingerprintOptions, taskLog func(level, format string, args ...interface{})) {
	targetUrl := fmt.Sprintf("%s://%s:%d", asset.Service, asset.Host, asset.Port)
	if asset.Service == "" {
		if asset.Port == 443 || asset.Port == 8443 {
			targetUrl = fmt.Sprintf("https://%s:%d", asset.Host, asset.Port)
		} else {
			targetUrl = fmt.Sprintf("http://%s:%d", asset.Host, asset.Port)
		}
	}

	// 解析HTTP headers用于指纹识别
	var headers http.Header
	if asset.HttpHeader != "" {
		headers = parseHttpHeaders(asset.HttpHeader)
	}

	// 如果 httpx 没有获取到 body（可能是重定向等原因），使用内置方法重新获取
	var bodyBytes []byte
	if asset.HttpBody == "" || asset.Title == "" {
		if taskLog != nil {
			taskLog("DEBUG", "httpx didn't get body/title for %s:%d, fetching with builtin client", asset.Host, asset.Port)
		} else {
			logx.Debugf("httpx didn't get body/title for %s:%d, fetching with builtin client", asset.Host, asset.Port)
		}
		resp, err := s.client.Get(targetUrl)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			bodyBytes = body
			if asset.HttpBody == "" {
				if len(body) > 50*1024 {
					asset.HttpBody = string(body[:50*1024]) + "\n...[truncated]"
				} else {
					asset.HttpBody = string(body)
				}
			}
			if asset.Title == "" {
				asset.Title = extractTitle(string(body))
			}
			if asset.Server == "" {
				asset.Server = resp.Header.Get("Server")
			}
			if headers == nil {
				headers = resp.Header
			}
			// 更新状态码为最终响应的状态码
			asset.HttpStatus = fmt.Sprintf("%d", resp.StatusCode)
			// 更新HttpHeader为实际响应的header
			if asset.HttpHeader == "" {
				asset.HttpHeader = formatHeadersWithStatus(resp.Header, resp.StatusCode, resp.Proto)
			}
		}
	} else {
		bodyBytes = []byte(asset.HttpBody)
	}

	// 收集所有指纹识别结果，用于智能合并
	appResults := make(map[string]*AppDetectionResult)

	mergeExistingAppDetections(appResults, asset.App)
	// 如果启用Wappalyzer，进行检测（httpx模式下通常不需要，但保留兼容性）
	if opts.Wappalyzer && s.wappalyzerClient != nil {
		apps := s.wappalyzerClient.Fingerprint(headers, []byte(asset.HttpBody))
		if taskLog != nil {
			taskLog("DEBUG", "Wappalyzer detected apps for %s:%d: %v", asset.Host, asset.Port, apps)
		} else {
			logx.Debugf("Wappalyzer detected apps for %s:%d: %v", asset.Host, asset.Port, apps)
		}

		for app := range apps {
			appNameLower := strings.ToLower(app)
			if result, exists := appResults[appNameLower]; exists {
				result.Sources = append(result.Sources, "wappalyzer")
			} else {
				appResults[appNameLower] = &AppDetectionResult{
					Name:         app,
					OriginalName: app,
					Sources:      []string{"wappalyzer"},
				}
			}
			if taskLog != nil {
				taskLog("INFO", "发现应用指纹: %s:%d -> %s (来源: wappalyzer)", asset.Host, asset.Port, app)
			} else {
				logx.Infof("发现应用指纹: %s:%d -> %s (来源: wappalyzer)", asset.Host, asset.Port, app)
			}
		}
	}

	// 获取 IconHash 和 MMH3 hash（用于自定义指纹匹配）
	var faviconMMH3Hash string
	if opts.IconHash || opts.CustomEngine {
		// 保存 httpx 可能已获取的 IconData 作为回退
		existingIconData := asset.IconData

		// 传入 HTML body 用于解析 <link rel="icon"> 标签发现自定义favicon路径
		iconHash, iconData := s.getIconHashWithData(targetUrl, asset.HttpBody)
		if len(iconData) > 0 {
			// 内置获取成功，使用内置数据
			asset.IconData = iconData
			faviconMMH3Hash = CalculateMMH3Hash(iconData)
			if asset.IconHash == "" && iconHash != "" {
				asset.IconHash = iconHash
			}
		} else if len(existingIconData) > 0 {
			// 内置获取失败，回退到 httpx 已获取的数据
			faviconMMH3Hash = CalculateMMH3Hash(existingIconData)
		}
	}

	// 如果启用自定义指纹引擎，使用自定义格式的规则进行识别
	if opts.CustomEngine && s.customFingerprintEngine != nil {
		fpCount := s.customFingerprintEngine.GetFingerprintCount()
		// 使用原始字节数据进行GBK编码匹配
		if len(bodyBytes) == 0 {
			bodyBytes = []byte(asset.HttpBody)
		}
		// 从header字符串中提取所有Set-Cookie值
		var cookies string
		if headers != nil {
			cookies = headers.Get("Set-Cookie")
			if cookies == "" {
				cookies = headers.Get("set-cookie")
			}
		}
		if cookies == "" && asset.HttpHeader != "" {
			cookies = extractCookiesFromHeader(asset.HttpHeader)
		}
		fpData := &FingerprintData{
			Title:        asset.Title,
			Body:         asset.HttpBody,
			BodyBytes:    bodyBytes,
			Headers:      headers,
			HeaderString: asset.HttpHeader,
			Server:       asset.Server,
			URL:          targetUrl,
			FaviconHash:  faviconMMH3Hash,
			Cookies:      cookies,
		}
		customApps := s.customFingerprintEngine.MatchWithId(fpData)
		logx.Debugf("Custom fingerprint engine (loaded %d fingerprints) detected apps for %s:%d: %v", fpCount, asset.Host, asset.Port, customApps)

		for _, customApp := range customApps {
			mergeFingerprintDetection(appResults, customApp)
			if taskLog != nil {
				taskLog("INFO", "发现应用指纹: %s:%d -> %s (来源: %s)", asset.Host, asset.Port, customApp.Name, customApp.Source)
			} else {
				logx.Infof("发现应用指纹: %s:%d -> %s (来源: %s)", asset.Host, asset.Port, customApp.Name, customApp.Source)
			}
		}
	}

	// 重新构建asset.App列表，使用智能合并的结果
	asset.App = make([]string, 0, len(appResults))
	for _, result := range appResults {
		formattedApp := formatAppWithSources(result)
		asset.App = append(asset.App, formattedApp)
	}

	// 截图功能：如果 httpx 没有获取到截图，使用内置方法补充
	if opts.Screenshot && asset.Screenshot == "" {
		screenshot := s.takeScreenshot(ctx, targetUrl)
		if screenshot != "" {
			asset.Screenshot = screenshot
			logx.Debugf("Screenshot captured for %s:%d using builtin method", asset.Host, asset.Port)
		}
	}
}

// getIconHashWithData 获取favicon的hash值和原始数据
// htmlBody: 可选的HTML body内容，用于解析 <link rel="icon"> 标签发现自定义favicon路径
func (s *FingerprintScanner) getIconHashWithData(baseUrl string, htmlBody string) (string, []byte) {
	// 构建favicon候选路径列表
	faviconPaths := []string{}

	// 1. 先从HTML中解析 <link rel="icon"> 标签获取自定义favicon路径
	if htmlBody != "" {
		parsedPaths := parseFaviconFromHTML(htmlBody, baseUrl)
		faviconPaths = append(faviconPaths, parsedPaths...)
	}

	// 2. 追加常见的favicon路径作为回退
	faviconPaths = append(faviconPaths,
		"/favicon.ico",
		"/favicon.png",
		"/static/favicon.ico",
		"/assets/favicon.ico",
	)

	for _, path := range faviconPaths {
		match, hash, data := func(p string) (bool, string, []byte) {
			var iconUrl string
			if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
				// 已经是完整URL
				iconUrl = p
			} else {
				iconUrl = baseUrl + p
			}

			resp, err := s.client.Get(iconUrl)
			if err != nil {
				return false, "", nil
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				return false, "", nil
			}

			iconData, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

			if readErr != nil || len(iconData) == 0 {
				return false, "", nil
			}

			// 验证是否为有效的图片数据（过滤HTML错误页等非图片响应）
			if !isImageData(iconData) {
				return false, "", nil
			}

			// 计算MMH3 hash（Shodan风格）- 与 asset.IconHash 和指纹匹配使用的格式一致
			return true, CalculateMMH3Hash(iconData), iconData
		}(path)

		if match {
			return hash, data
		}
	}

	return "", nil
}

// parseFaviconFromHTML 从HTML内容中解析favicon路径
// 支持 <link rel="icon" href="..."> 和 <link rel="shortcut icon" href="...">
func parseFaviconFromHTML(htmlBody string, _ string) []string {
	var paths []string
	seen := make(map[string]bool)

	// 匹配 <link> 标签中包含 rel="icon" 或 rel="shortcut icon" 的 href
	// 支持单引号和双引号，支持属性顺序不同
	linkRe := regexp.MustCompile(`(?i)<link[^>]*\brel\s*=\s*["'](?:shortcut\s+)?icon["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*/?>`)
	matches := linkRe.FindAllStringSubmatch(htmlBody, -1)

	// 也匹配 href 在 rel 之前的情况
	linkRe2 := regexp.MustCompile(`(?i)<link[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["'](?:shortcut\s+)?icon["'][^>]*/?>`)
	matches = append(matches, linkRe2.FindAllStringSubmatch(htmlBody, -1)...)

	// 也匹配 apple-touch-icon
	linkRe3 := regexp.MustCompile(`(?i)<link[^>]*\brel\s*=\s*["']apple-touch-icon(?:-precomposed)?["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*/?>`)
	matches = append(matches, linkRe3.FindAllStringSubmatch(htmlBody, -1)...)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		href := strings.TrimSpace(m[1])
		if href == "" || seen[href] {
			continue
		}
		seen[href] = true

		// 处理相对路径
		if strings.HasPrefix(href, "//") {
			// 协议相对URL
			href = "https:" + href
		} else if strings.HasPrefix(href, "/") {
			// 绝对路径 - 将在调用方拼接baseUrl
			// 保持原样，调用方会处理
		} else if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
			// 相对路径
			href = "/" + href
		}

		paths = append(paths, href)
	}

	return paths
}

// fingerprint 识别单个资产指纹
func (s *FingerprintScanner) fingerprint(ctx context.Context, asset *Asset, opts *FingerprintOptions, taskLog func(level, format string, args ...interface{})) {
	// 检查上下文是否已取消
	if ctx.Err() != nil {
		return
	}

	// 尝试HTTP和HTTPS
	schemes := []string{"http", "https"}
	if asset.Port == 443 || asset.Port == 8443 || asset.Port == 9443 {
		schemes = []string{"https", "http"}
	}

	var httpDetected bool
	for _, scheme := range schemes {
		// 检查上下文是否已取消
		if ctx.Err() != nil {
			return
		}

		targetUrl := fmt.Sprintf("%s://%s:%d", scheme, asset.Host, asset.Port)
		resp, err := s.client.Get(targetUrl)
		if err != nil {
			continue
		}

		// 验证是否为有效的HTTP响应
		if !isValidHttpResponse(resp) {
			resp.Body.Close()
			continue
		}

		httpDetected = true

		// 读取响应体（保留原始字节用于GBK编码匹配）
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 限制1MB
		resp.Body.Close()

		// 提取信息
		asset.HttpStatus = fmt.Sprintf("%d", resp.StatusCode)
		asset.HttpHeader = formatHeadersWithStatus(resp.Header, resp.StatusCode, resp.Proto)
		// 限制HttpBody大小为50KB
		if len(body) > 50*1024 {
			asset.HttpBody = string(body[:50*1024]) + "\n...[truncated]"
		} else {
			asset.HttpBody = string(body)
		}
		asset.Title = extractTitle(string(body))
		asset.Server = resp.Header.Get("Server")
		asset.Service = scheme

		// 获取Icon Hash和原始数据
		var faviconMMH3Hash string
		if opts.IconHash {
			iconHash, iconData := s.getIconHashWithData(targetUrl, asset.HttpBody)
			if iconHash != "" {
				asset.IconHash = iconHash // getIconHashWithData 返回 MMH3 hash
			}
			// 计算MMH3 hash用于ARL格式指纹匹配
			if len(iconData) > 0 {
				faviconMMH3Hash = CalculateMMH3Hash(iconData)
				// 保存 icon 图片数据
				asset.IconData = iconData
			}
		}

		// 使用wappalyzergo识别应用指纹
		var appResults = make(map[string]*AppDetectionResult)
		if opts.Wappalyzer && s.wappalyzerClient != nil {
			apps := s.identifyWithWappalyzer(resp.Header, body)
			for _, app := range apps {
				appNameLower := strings.ToLower(app)
				appResults[appNameLower] = &AppDetectionResult{
					Name:         app,
					OriginalName: app,
					Sources:      []string{"wappalyzer"},
				}
			}
		}

		// 使用自定义指纹引擎
		if opts.CustomEngine && s.customFingerprintEngine != nil {
			fpCount := s.customFingerprintEngine.GetFingerprintCount()
			fpData := &FingerprintData{
				Title:        asset.Title,
				Body:         asset.HttpBody,
				BodyBytes:    body, // 原始字节用于GBK编码匹配
				Headers:      resp.Header,
				HeaderString: asset.HttpHeader, // 原始header字符串
				Server:       asset.Server,
				URL:          targetUrl,
				FaviconHash:  faviconMMH3Hash,
				Cookies:      resp.Header.Get("Set-Cookie"),
			}
			customApps := s.customFingerprintEngine.MatchWithId(fpData)
			if taskLog != nil {
				taskLog("DEBUG", "Custom fingerprint engine (loaded %d fingerprints) detected apps for %s:%d: %v", fpCount, asset.Host, asset.Port, customApps)
			} else {
				logx.Debugf("Custom fingerprint engine (loaded %d fingerprints) detected apps for %s:%d: %v", fpCount, asset.Host, asset.Port, customApps)
			}

			for _, customApp := range customApps {
				mergeFingerprintDetection(appResults, customApp)
				if taskLog != nil {
					taskLog("INFO", "发现应用指纹: %s:%d -> %s (来源: %s)", asset.Host, asset.Port, customApp.Name, customApp.Source)
				} else {
					logx.Infof("发现应用指纹: %s:%d -> %s (来源: %s)", asset.Host, asset.Port, customApp.Name, customApp.Source)
				}
			}
		}

		// 构建最终的应用列表
		for _, result := range appResults {
			formattedApp := formatAppWithSources(result)
			asset.App = append(asset.App, formattedApp)
		}

		// 截图
		if opts.Screenshot {
			screenshot := s.takeScreenshot(ctx, targetUrl)
			if taskLog != nil {
				taskLog("INFO", "takeScreenshot截图: targetUrl:%s ->screenshot)", targetUrl)
			} else {
				logx.Infof("takeScreenshot截图: targetUrl:%s ->screenshot)", targetUrl)
			}
			if screenshot != "" {
				asset.Screenshot = screenshot
			}
		}

		break
	}

	// 如果HTTP探测失败，标记为非HTTP服务
	if !httpDetected && asset.Service == "" {
		if taskLog != nil {
			taskLog("DEBUG", "HTTP probe failed for %s:%d, marking as non-http", asset.Host, asset.Port)
		} else {
			logx.Debugf("HTTP probe failed for %s:%d, marking as non-http", asset.Host, asset.Port)
		}
		asset.Service = "unknown"
	}
}

// isValidHttpResponse 验证响应是否为有效的HTTP响应
func isValidHttpResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	// 检查状态码是否在有效范围内
	if resp.StatusCode < 100 || resp.StatusCode >= 600 {
		return false
	}

	// 检查是否有HTTP特征的响应头
	// 有效的HTTP服务通常会返回以下头之一
	httpHeaders := []string{
		"Content-Type",
		"Server",
		"Date",
		"Content-Length",
		"Transfer-Encoding",
		"Connection",
		"Set-Cookie",
		"X-Powered-By",
	}

	for _, header := range httpHeaders {
		if resp.Header.Get(header) != "" {
			return true
		}
	}

	// 如果状态码是常见的HTTP状态码，也认为是有效的
	validStatusCodes := map[int]bool{
		200: true, 201: true, 204: true, 206: true,
		301: true, 302: true, 303: true, 304: true, 307: true, 308: true,
		400: true, 401: true, 403: true, 404: true, 405: true, 500: true, 502: true, 503: true,
	}

	return validStatusCodes[resp.StatusCode]
}

// runHttpx 使用httpx进行批量探测
func (s *FingerprintScanner) runHttpx(ctx context.Context, assets []*Asset, opts *FingerprintOptions) {
	if len(assets) == 0 {
		return
	}

	// 构建目标列表
	var targets []string
	targetMap := make(map[string]*Asset)
	for _, asset := range assets {
		target := fmt.Sprintf("%s:%d", asset.Host, asset.Port)
		targets = append(targets, target)
		targetMap[target] = asset
	}

	// 构建httpx命令
	args := []string{
		"-silent",
		"-json",
		"-title",
		"-status-code",
		"-tech-detect",
		"-favicon",
		"-server",
		"-content-type",
		"-irh",                // include response header
		"-irr",                // include request/response (包含body)
		"-follow-redirects",   // 跟随重定向
		"-max-redirects", "5", // 最大重定向次数
	}
	if opts.Screenshot {
		args = append(args, "-screenshot", "-system-chrome")
	}

	logx.Infof("Executing command: httpx %s", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, "httpx", args...)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		logx.Errorf("httpx start error: %v", err)
		return
	}

	// 写入目标
	go func() {
		for _, target := range targets {
			stdin.Write([]byte(target + "\n"))
		}
		stdin.Close()
	}()

	// 解析输出
	decoder := json.NewDecoder(stdout)
	for decoder.More() {
		var result HttpxResult
		if err := decoder.Decode(&result); err != nil {
			continue
		}

		// 优先使用input字段匹配原始目标，避免重定向导致的匹配问题
		var asset *Asset
		var key string

		// 首先尝试使用input字段匹配
		if result.Input != "" {
			key = result.Input
			asset = targetMap[key]
		}

		// 如果input匹配失败，尝试从URL解析
		if asset == nil {
			if u, err := url.Parse(result.URL); err == nil {
				host := u.Hostname()
				port := u.Port()
				if port == "" {
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				key = fmt.Sprintf("%s:%s", host, port)
				asset = targetMap[key]
			}
		}

		if asset != nil {
			// 从URL获取scheme
			scheme := "http"
			if u, err := url.Parse(result.URL); err == nil {
				scheme = u.Scheme
			}
			asset.Title = result.Title
			asset.HttpStatus = fmt.Sprintf("%d", result.StatusCode)
			asset.Service = scheme
			if len(result.Technologies) > 0 {
				// 为httpx识别的应用添加来源标识
				for _, tech := range result.Technologies {
					asset.App = append(asset.App, tech+"[httpx]")
				}
			}
			if result.FaviconHash != "" {
				asset.IconHash = result.FaviconHash
			}
			if result.ScreenshotPath != "" {
				// 读取截图文件并转换为base64
				asset.Screenshot = readScreenshotAsBase64(result.ScreenshotPath)
			}
			// 填充Server字段
			if result.ServerHeader != "" {
				asset.Server = result.ServerHeader
			} else if result.WebServer != "" {
				asset.Server = result.WebServer
			}
			// 填充HttpHeader字段
			// 优先从Response字段提取完整header（包含所有Set-Cookie）
			if result.Response != "" {
				asset.HttpHeader = extractHeadersFromResponse(result.Response)
			}
			// 如果Response为空，使用ResponseHeader map，并添加状态行
			if asset.HttpHeader == "" && len(result.ResponseHeader) > 0 {
				asset.HttpHeader = formatHttpxHeadersWithStatus(result.ResponseHeader, result.StatusCode)
			}
			// 填充HttpBody字段
			bodyContent := result.ResponseBody
			asset.HttpBody = bodyContent
			logx.Debugf("Matched httpx result for %s: title=%s, status=%d", key, result.Title, result.StatusCode)
		}
	}

	cmd.Wait()
}

// HttpxResult httpx JSON输出结构
type HttpxResult struct {
	URL            string            `json:"url"`
	Input          string            `json:"input"`
	Title          string            `json:"title"`
	StatusCode     int               `json:"status_code"`
	Technologies   []string          `json:"tech"`
	FaviconHash    string            `json:"favicon_hash"`
	ScreenshotPath string            `json:"screenshot_path"`
	WebServer      string            `json:"webserver"`
	ContentLength  int               `json:"content_length"`
	ResponseHeader map[string]string `json:"header"`
	ServerHeader   string            `json:"server"`
	ContentType    string            `json:"content_type"`
	ResponseBody   string            `json:"body"`
	Response       string            `json:"response"` // httpx -include-response 输出的字段名
}

// checkHttpxInstalled 检查httpx是否安装
func checkHttpxInstalled() bool {
	cmd := exec.Command("httpx", "-version")
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), "Version")
}

// identifyWithWappalyzer 使用wappalyzergo识别应用
func (s *FingerprintScanner) identifyWithWappalyzer(headers http.Header, body []byte) []string {
	if s.wappalyzerClient == nil {
		return nil
	}

	fingerprints := s.wappalyzerClient.Fingerprint(headers, body)
	apps := make([]string, 0, len(fingerprints))
	for app := range fingerprints {
		apps = append(apps, app)
	}
	return apps
}

// getIconHash 获取favicon的hash值
func (s *FingerprintScanner) getIconHash(baseUrl string) string {
	// 尝试常见的favicon路径
	faviconPaths := []string{
		"/favicon.ico",
		"/favicon.png",
		"/static/favicon.ico",
		"/assets/favicon.ico",
	}

	for _, path := range faviconPaths {
		match, hash := func(p string) (bool, string) {
			iconUrl := baseUrl + p
			resp, err := s.client.Get(iconUrl)
			if err != nil {
				return false, ""
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				return false, ""
			}

			// 读取icon内容
			iconData, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

			if err != nil || len(iconData) == 0 {
				return false, ""
			}

			// 计算MMH3 hash (Shodan风格)
			return true, CalculateMMH3Hash(iconData)
		}(path)

		if match {
			return hash
		}
	}

	return ""
}

// takeScreenshot 使用chromedp截图
func (s *FingerprintScanner) takeScreenshot(ctx context.Context, targetUrl string) string {
	if ctx.Err() != nil {
		return ""
	}

	// 使用全局持久化分配器，避免每次截图创建/销毁 Chrome 进程
	// 分配器基于 context.Background()，不会因父 context 取消而触发 chromedp 的 close-of-closed-channel panic
	allocCtx, _ := getGlobalAllocator()

	screenshotCtx, cancel := context.WithTimeout(allocCtx, 45*time.Second)
	defer cancel()

	taskCtx, taskCancel := chromedp.NewContext(screenshotCtx,
		chromedp.WithErrorf(func(format string, args ...interface{}) {
			msg := fmt.Sprintf(format, args...)
			if !strings.Contains(msg, "CookiePartitionKey") {
				logx.Errorf(format, args...)
			}
		}),
	)
	defer taskCancel()

	var buf []byte
	var pageHeight int64

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetUrl),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			time.Sleep(3 * time.Second)
			return nil
		}),
		chromedp.Evaluate(`document.body.scrollHeight`, &pageHeight),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if pageHeight < 1080 {
				pageHeight = 1080
			}
			return chromedp.EmulateViewport(1920, pageHeight).Do(ctx)
		}),
		chromedp.Evaluate(`window.scrollTo(0, 0)`, nil),
		chromedp.Sleep(2*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		logx.Errorf("Screenshot failed for %s: %v", targetUrl, err)
		err = chromedp.Run(taskCtx,
			chromedp.Navigate(targetUrl),
			chromedp.Sleep(5*time.Second),
			chromedp.CaptureScreenshot(&buf),
		)
		if err != nil {
			logx.Errorf("Fallback screenshot also failed for %s: %v", targetUrl, err)
			return ""
		}
	}

	logx.Infof("完成使用chromedp截图: %s", targetUrl)
	if len(buf) > 0 {
		return base64.StdEncoding.EncodeToString(buf)
	}
	return ""
}

// extractTitle 提取网页标题
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// 限制长度
		if len(title) > 100 {
			title = title[:100]
		}
		return title
	}
	return ""
}

// formatHeaders 格式化响应头
func formatHeaders(headers http.Header) string {
	var sb strings.Builder
	for key, values := range headers {
		for _, value := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	return sb.String()
}

// formatHeadersWithStatus 格式化响应头，包含HTTP状态行
func formatHeadersWithStatus(headers http.Header, statusCode int, proto string) string {
	var sb strings.Builder
	// 添加HTTP状态行
	if proto == "" {
		proto = "HTTP/1.1"
	}
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}
	sb.WriteString(fmt.Sprintf("%s %d %s\n", proto, statusCode, statusText))
	// 添加headers
	for key, values := range headers {
		for _, value := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	return sb.String()
}

// formatHttpxHeaders 格式化httpx返回的响应头
func formatHttpxHeaders(headers map[string]string) string {
	var sb strings.Builder
	for key, value := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}
	return sb.String()
}

// formatHttpxHeadersWithStatus 格式化httpx返回的响应头
func formatHttpxHeadersWithStatus(headers map[string]string, _ int) string {
	var sb strings.Builder
	// 添加headers（不添加状态行，因为无法获取实际的协议版本）
	for key, value := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}
	return sb.String()
}

// extractHeadersFromResponse 从完整HTTP响应中提取header部分
func extractHeadersFromResponse(response string) string {
	// HTTP响应格式: 状态行 + headers + 空行 + body
	// 找到header和body的分隔（空行）
	idx := strings.Index(response, "\r\n\r\n")
	if idx == -1 {
		idx = strings.Index(response, "\n\n")
	}
	if idx == -1 {
		// 没有找到分隔，可能整个都是header
		return response
	}
	return response[:idx]
}

// parseHttpHeaders 解析HTTP headers字符串为http.Header
func parseHttpHeaders(headerStr string) http.Header {
	headers := make(http.Header)
	lines := strings.Split(headerStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers.Add(key, value)
		}
	}
	return headers
}

// extractCookiesFromHeader 从header字符串中提取所有Set-Cookie值
func extractCookiesFromHeader(headerStr string) string {
	var cookies []string
	lines := strings.Split(headerStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 不区分大小写匹配 Set-Cookie, set-cookie, set_cookie
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "set-cookie:") || strings.HasPrefix(lowerLine, "set_cookie:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cookies = append(cookies, strings.TrimSpace(parts[1]))
			}
		}
	}
	return strings.Join(cookies, "; ")
}

// readScreenshotAsBase64 读取截图文件并返回base64编码
func readScreenshotAsBase64(filePath string) string {
	if filePath == "" {
		return ""
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		logx.Errorf("Failed to read screenshot file %s: %v", filePath, err)
		return ""
	}
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

// containsAppName 检查应用列表中是否包含指定应用名（忽略来源标识）
func containsAppName(apps []string, appName string) bool {
	appNameLower := strings.ToLower(appName)
	for _, app := range apps {
		// 移除来源标识后比较
		name := app
		if idx := strings.Index(app, "["); idx > 0 {
			name = app[:idx]
		}
		if strings.ToLower(name) == appNameLower {
			return true
		}
	}
	return false
}

// findAppIndex 查找应用在列表中的索引，匹配应用名和指定来源标识
// 支持匹配带版本号的应用名，如 "Nginx:1.24.0" 匹配 "nginx"
func findAppIndex(apps []string, appName string, source string) int {
	appNameLower := strings.ToLower(appName)
	for i, app := range apps {
		// 检查是否包含指定来源标识
		if !strings.Contains(app, source) {
			continue
		}
		// 移除来源标识后获取应用名
		name := app
		if idx := strings.Index(app, "["); idx > 0 {
			name = app[:idx]
		}
		// 移除版本号（格式如 Nginx:1.24.0）
		if colonIdx := strings.Index(name, ":"); colonIdx > 0 {
			name = name[:colonIdx]
		}
		if strings.ToLower(name) == appNameLower {
			return i
		}
	}
	return -1
}

// extractAppName 从应用字符串中提取应用名称（移除来源标识）
func extractAppName(app string) string {
	if idx := strings.Index(app, "["); idx > 0 {
		return strings.TrimSpace(app[:idx])
	}
	return app
}

func mergeExistingAppDetections(appResults map[string]*AppDetectionResult, apps []string) {
	for _, app := range apps {
		result := parseAppDetection(app)
		if result == nil {
			continue
		}
		mergeAppDetectionResult(appResults, result)
	}
}

func parseAppDetection(app string) *AppDetectionResult {
	app = strings.TrimSpace(app)
	if app == "" {
		return nil
	}
	name := extractAppName(app)
	if colonIdx := strings.Index(name, ":"); colonIdx > 0 {
		name = name[:colonIdx]
	}
	result := &AppDetectionResult{Name: name, OriginalName: name}
	left := strings.LastIndex(app, "[")
	right := strings.LastIndex(app, "]")
	if left < 0 || right <= left {
		result.Sources = []string{"httpx"}
		return result
	}
	for _, sourcePart := range strings.Split(app[left+1:right], "+") {
		source, id := parseSourcePart(sourcePart)
		if source == "" {
			continue
		}
		result.Sources = append(result.Sources, source)
		switch source {
		case "custom":
			if id != "" {
				result.CustomIDs = append(result.CustomIDs, id)
			}
		case "active":
			if id != "" {
				result.ActiveIDs = append(result.ActiveIDs, id)
			}
		}
	}
	return result
}

func parseSourcePart(part string) (string, string) {
	part = strings.TrimSpace(part)
	if part == "" {
		return "", ""
	}
	if open := strings.Index(part, "("); open > 0 && strings.HasSuffix(part, ")") {
		return part[:open], part[open+1 : len(part)-1]
	}
	return part, ""
}

func mergeAppDetectionResult(appResults map[string]*AppDetectionResult, incoming *AppDetectionResult) {
	key := strings.ToLower(incoming.Name)
	if existing, ok := appResults[key]; ok {
		existing.Sources = append(existing.Sources, incoming.Sources...)
		existing.CustomIDs = append(existing.CustomIDs, incoming.CustomIDs...)
		existing.ActiveIDs = append(existing.ActiveIDs, incoming.ActiveIDs...)
		if existing.OriginalName == "" {
			existing.OriginalName = incoming.OriginalName
		}
		return
	}
	appResults[key] = incoming
}

func mergeFingerprintDetection(appResults map[string]*AppDetectionResult, matched MatchedFingerprint) {
	source := matched.Source
	if source == "" {
		source = "custom"
	}
	incoming := &AppDetectionResult{
		Name:         matched.Name,
		OriginalName: matched.Name,
		Sources:      []string{source},
		CustomIDs:    sourceIDs(matched, "custom"),
		ActiveIDs:    sourceIDs(matched, "active"),
	}
	mergeAppDetectionResult(appResults, incoming)
}

func sourceIDs(matched MatchedFingerprint, source string) []string {
	if matched.Source != source || matched.Id == "" {
		return nil
	}
	return []string{matched.Id}
}

// formatAppWithSources 根据检测来源格式化应用名称
func formatAppWithSources(result *AppDetectionResult) string {
	if len(result.Sources) == 0 {
		return result.OriginalName
	}

	// 使用原始名称（可能包含版本号）
	appName := result.OriginalName
	if appName == "" {
		appName = result.Name
	}

	// 如果应用名称仍为空，跳过
	if appName == "" {
		return ""
	}

	// 移除现有的来源标识
	if idx := strings.Index(appName, "["); idx > 0 {
		appName = strings.TrimSpace(appName[:idx])
	}

	// 去重并排序来源
	sources := utils.UniqueStrings(result.Sources)

	orderedSources := orderFingerprintSources(sources)
	sourceStr := fmt.Sprintf("[%s]", strings.Join(formatFingerprintSources(orderedSources, result), "+"))

	return appName + sourceStr
}

func orderFingerprintSources(sources []string) []string {
	orderedSources := make([]string, 0, len(sources))
	for _, source := range []string{"httpx", "wappalyzer", "custom", "active"} {
		for _, s := range sources {
			if s == source {
				orderedSources = append(orderedSources, s)
				break
			}
		}
	}
	return orderedSources
}

func formatFingerprintSources(sources []string, result *AppDetectionResult) []string {
	formatted := make([]string, 0, len(sources))
	for _, source := range sources {
		switch source {
		case "custom":
			formatted = append(formatted, formatSourceWithIDs("custom", result.CustomIDs))
		case "active":
			formatted = append(formatted, formatSourceWithIDs("active", result.ActiveIDs))
		default:
			formatted = append(formatted, source)
		}
	}
	return formatted
}

func formatSourceWithIDs(source string, ids []string) string {
	ids = utils.UniqueStrings(ids)
	if len(ids) == 0 {
		return source
	}
	return fmt.Sprintf("%s(%s)", source, strings.Join(ids, ","))
}

// containsString 检查字符串切片是否包含指定字符串
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func mergeActiveFingerprintApp(asset *Asset, fp *model.Fingerprint) {
	appResults := make(map[string]*AppDetectionResult)
	mergeExistingAppDetections(appResults, asset.App)
	mergeAppDetectionResult(appResults, &AppDetectionResult{
		Name:         fp.Name,
		OriginalName: fp.Name,
		Sources:      []string{"active"},
		ActiveIDs:    []string{fp.Id.Hex()},
	})
	asset.App = make([]string, 0, len(appResults))
	for _, result := range appResults {
		asset.App = append(asset.App, formatAppWithSources(result))
	}
}

// ==================== Active Fingerprint Scanning ====================

// ActiveFingerprintResult 主动指纹扫描结果
type ActiveFingerprintResult struct {
	URL           string // 完整URL（包含路径）
	Path          string // 探测路径
	Fingerprint   string // 匹配到的指纹名称
	FingerprintID string // 指纹ID
	StatusCode    int    // HTTP状态码
	Title         string // 页面标题
}

// RunActiveFingerprint 执行主动指纹扫描
// 参考 Slack 项目的 ActiveFingerScan 实现
func (s *FingerprintScanner) RunActiveFingerprint(ctx context.Context, assets []*Asset, opts *FingerprintOptions, taskLog func(level, format string, args ...interface{})) {
	if s.customFingerprintEngine == nil {
		if taskLog != nil {
			taskLog("INFO", "Active fingerprint: no custom engine configured, skipping")
		}
		logx.Info("Active fingerprint: no custom engine configured, skipping")
		return
	}

	activeCount := s.customFingerprintEngine.GetActiveFingerprintCount()
	if activeCount == 0 {
		if taskLog != nil {
			taskLog("INFO", "Active fingerprint: no active fingerprints loaded, skipping")
		}
		logx.Info("Active fingerprint: no active fingerprints loaded, skipping")
		return
	}

	// 过滤出存活的HTTP资产
	aliveAssets := make([]*Asset, 0)
	for _, asset := range assets {
		if asset.HttpStatus != "" && asset.HttpStatus != "0" {
			aliveAssets = append(aliveAssets, asset)
		}
	}

	if len(aliveAssets) == 0 {
		if taskLog != nil {
			taskLog("INFO", "Active fingerprint: no alive HTTP assets found, skipping")
		}
		logx.Info("Active fingerprint: no alive HTTP assets found, skipping")
		return
	}

	logx.Infof("Active fingerprint: scanning %d assets with %d active fingerprints", len(aliveAssets), activeCount)
	if taskLog != nil {
		taskLog("INFO", "Active fingerprint: scanning %d assets with %d active fingerprints", len(aliveAssets), activeCount)
	}

	// 设置主动指纹超时
	activeTimeout := 10 * time.Second
	if opts.ActiveTimeout > 0 {
		activeTimeout = time.Duration(opts.ActiveTimeout) * time.Second
	}

	// 记录已访问的URL，避免重复扫描
	visited := make(map[string]bool)
	var visitedMu sync.Mutex

	// 记录每个目标的超时次数，超过阈值则跳过
	timeoutCounter := make(map[string]int)
	var timeoutMu sync.Mutex
	const maxTimeoutCount = 15

	// 并发控制
	concurrency := 10
	if opts.Concurrency > 0 {
		concurrency = opts.Concurrency
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// 获取主动指纹列表
	activeFingerprints := s.customFingerprintEngine.GetActiveFingerprints()

	// 调试：检查主动指纹是否有匹配规则
	fingerprintsWithRule := 0
	fingerprintsWithoutRule := 0
	for _, fp := range activeFingerprints {
		hasRule := fp.Rule != "" || len(fp.HTML) > 0 || len(fp.Headers) > 0 || len(fp.Scripts) > 0
		if hasRule {
			fingerprintsWithRule++
			if taskLog != nil {
				taskLog("DEBUG", "Active fingerprint '%s' has rule: %s, paths: %v", fp.Name, fp.Rule, fp.ActivePaths)
			} else {
				logx.Debugf("Active fingerprint '%s' has rule: %s, paths: %v", fp.Name, fp.Rule, fp.ActivePaths)
			}
		} else {
			fingerprintsWithoutRule++
			if taskLog != nil {
				taskLog("DEBUG", "Active fingerprint '%s' has NO rule, paths: %v", fp.Name, fp.ActivePaths)
			} else {
				logx.Debugf("Active fingerprint '%s' has NO rule, paths: %v", fp.Name, fp.ActivePaths)
			}
		}
	}
	if taskLog != nil {
		taskLog("DEBUG", "Active fingerprints: %d with rules, %d without rules", fingerprintsWithRule, fingerprintsWithoutRule)
	}

	// 请求计数器
	var requestCount int32
	var successCount int32
	var failCount int32

	for _, asset := range aliveAssets {
		// 构建基础URL
		scheme := asset.Service
		if scheme == "" {
			if asset.Port == 443 || asset.Port == 8443 {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		baseURL := fmt.Sprintf("%s://%s:%d", scheme, asset.Host, asset.Port)

		for _, fp := range activeFingerprints {
			if !fp.Enabled || len(fp.ActivePaths) == 0 {
				continue
			}

			for _, path := range fp.ActivePaths {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// 检查是否超过超时阈值
				timeoutMu.Lock()
				if timeoutCounter[baseURL] >= maxTimeoutCount {
					timeoutMu.Unlock()
					continue
				}
				timeoutMu.Unlock()

				// 构建完整URL
				fullURL := baseURL + path

				// 去重检查
				visitedMu.Lock()
				if visited[fullURL] {
					visitedMu.Unlock()
					continue
				}
				visited[fullURL] = true
				visitedMu.Unlock()

				wg.Add(1)
				sem <- struct{}{}

				go func(asset *Asset, fp *model.Fingerprint, fullURL, path, baseURL string) {
					defer wg.Done()
					defer func() { <-sem }()

					// 增加请求计数
					atomic.AddInt32(&requestCount, 1)

					// 创建带超时的请求
					reqCtx, cancel := context.WithTimeout(ctx, activeTimeout)
					defer cancel()

					// 发起请求
					req, err := http.NewRequestWithContext(reqCtx, "GET", fullURL, nil)
					if err != nil {
						atomic.AddInt32(&failCount, 1)
						if taskLog != nil {
							taskLog("DEBUG", "Active fingerprint request create failed: %s, error: %v", fullURL, err)
						} else {
							logx.Debugf("Active fingerprint request create failed: %s, error: %v", fullURL, err)
						}
						return
					}

					resp, err := s.client.Do(req)
					if err != nil {
						// 记录超时
						timeoutMu.Lock()
						timeoutCounter[baseURL]++
						timeoutMu.Unlock()
						atomic.AddInt32(&failCount, 1)
						if taskLog != nil {
							taskLog("DEBUG", "Active fingerprint request failed: %s, error: %v", fullURL, err)
						} else {
							logx.Debugf("Active fingerprint request failed: %s, error: %v", fullURL, err)
						}
						return
					}
					defer resp.Body.Close()

					atomic.AddInt32(&successCount, 1)

					// 读取响应体
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

					// 构建指纹匹配数据
					fpData := &FingerprintData{
						Title:        extractTitle(string(body)),
						Body:         string(body),
						BodyBytes:    body,
						Headers:      resp.Header,
						HeaderString: formatHeaders(resp.Header),
						Server:       resp.Header.Get("Server"),
						URL:          fullURL,
						Cookies:      resp.Header.Get("Set-Cookie"),
					}

					// 调试：记录请求结果
					if taskLog != nil {
						taskLog("DEBUG", "Active fingerprint request: %s, status=%d, bodyLen=%d, title=%s", fullURL, resp.StatusCode, len(body), fpData.Title)
					} else {
						logx.Debugf("Active fingerprint request: %s, status=%d, bodyLen=%d, title=%s", fullURL, resp.StatusCode, len(body), fpData.Title)
					}

					// 匹配指纹
					if s.customFingerprintEngine.MatchActiveFingerprint(fp, fpData) {
						// 404页面通常不算匹配成功（除非是特定指纹如ThinkPHP）
						if resp.StatusCode == 404 && !strings.Contains(strings.ToLower(fp.Name), "thinkphp") {
							if taskLog != nil {
								taskLog("DEBUG", "Active fingerprint '%s' matched but status is 404, skipping", fp.Name)
							} else {
								logx.Debugf("Active fingerprint '%s' matched but status is 404, skipping", fp.Name)
							}
							return
						}

						if taskLog != nil {
							taskLog("DEBUG", "Active fingerprint matched: %s -> %s (path: %s)", baseURL, fp.Name, path)
							taskLog("INFO", "Active fingerprint: %s -> %s", fullURL, fp.Name)
						} else {
							logx.Debugf("Active fingerprint matched: %s -> %s (path: %s)", baseURL, fp.Name, path)
						}
						mergeActiveFingerprintApp(asset, fp)
					}
				}(asset, fp, fullURL, path, baseURL)
			}
		}
	}

	wg.Wait()
	logx.Infof("Active fingerprint: scan completed, requests=%d, success=%d, fail=%d", requestCount, successCount, failCount)
	if taskLog != nil {
		taskLog("INFO", "Active fingerprint: scan completed, requests=%d, success=%d, fail=%d", requestCount, successCount, failCount)
	}
}
