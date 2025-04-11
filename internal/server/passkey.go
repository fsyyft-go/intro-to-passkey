// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"

	kitlog "github.com/fsyyft-go/kit/log"

	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	apppasskey "github.com/fsyyft-go/intro-to-passkey/internal/server/passkey"
	appweb "github.com/fsyyft-go/intro-to-passkey/web"
)

// RegisterRequest 定义了用户注册请求的数据结构。
// 该结构体用于接收客户端发送的注册请求数据。
type RegisterRequest struct {
	Username string `json:"username"` // 用户名，用于标识用户身份
}

// Session 用于存储注册会话数据。
// 该结构体用于在注册过程中临时存储会话相关信息。
type Session struct {
	Data interface{} // 会话数据，可以是任意类型
}

// passkeyServer 是 Passkey 认证服务器的核心实现结构体。
// 它负责处理所有与 Passkey 认证相关的 HTTP 请求，并管理认证流程。
type passkeyServer struct {
	logger   kitlog.Logger            // 日志记录器，用于记录服务器运行时的日志信息
	conf     *appconf.Config          // 服务器配置信息
	webauthn *webauthn.WebAuthn       // WebAuthn 实例，用于处理认证相关操作
	userDB   map[string]webauthn.User // 用户数据库，存储所有注册用户信息
	sessions map[string]*Session      // 会话存储，用于管理注册会话
	mu       sync.RWMutex             // 互斥锁，用于保护并发访问
}

// newPasskeyServer 创建一个新的 Passkey 服务器实例。
// 参数：
//   - logger：用于记录服务器日志的日志记录器
//   - conf：服务器的配置信息
//
// 返回值：
//   - http.Handler：实现了 HTTP 请求处理接口的 Passkey 服务器实例
func newPasskeyServer(logger kitlog.Logger, conf *appconf.Config) http.Handler {
	h := &passkeyServer{
		logger:   logger,
		conf:     conf,
		userDB:   make(map[string]webauthn.User),
		sessions: make(map[string]*Session),
	}

	// webauthn.Config 配置详解：
	//
	// RPID（Relying Party ID）：
	// - 定义了信赖方的标识符，通常是网站的域名
	// - 必须是当前网站的有效域名或其顶级域名
	// - 在开发环境可以使用 localhost
	// - 生产环境必须使用实际的域名
	// - 注意：必须是所有 RPOrigins 的有效后缀
	// - 技术规范：
	//   * 不能包含端口号
	//   * 不能包含协议前缀（如 http:// 或 https://）
	//   * 不能包含路径
	//   * 不能使用 IP 地址（包括 127.0.0.1）
	// - 示例：
	//   * 开发环境：localhost
	//   * 生产环境：example.com
	//
	// RPDisplayName：
	// - 在用户进行认证操作时显示给用户看的应用名称
	// - 应该使用清晰、友好的名称，提升用户体验
	// - 建议使用公司或产品的正式名称
	// - 注意：这个名称会显示在用户的认证设备上
	// - 技术要求：
	//   * 长度建议不超过 64 个字符
	//   * 支持 Unicode 字符
	//   * 避免使用特殊字符和 Emoji
	// - 示例：
	//   * "My Company Login"
	//   * "Secure Banking Portal"
	//   * "企业管理系统"
	//
	// RPOrigins：
	// - 定义了允许使用该 WebAuthn 认证的源地址列表
	// - 必须包含完整的 URL（包括协议、域名和端口）
	// - 开发环境可以使用 http，生产环境必须使用 https
	// - 支持多域名场景，所有域名必须共享同一个 RPID 后缀
	// - 技术要求：
	//   * 每个 Origin 必须是完整的 URL
	//   * 必须包含协议（http/https）
	//   * 可以包含端口号
	//   * 不能包含路径部分
	//   * 必须与实际服务的域名完全匹配
	// - 示例：
	//   * 开发环境：["http://localhost:8080"]
	//   * 生产环境：["https://app.example.com", "https://auth.example.com"]
	//
	// RPTopOrigins：
	// - 定义了允许的顶级源地址列表
	// - 用于 WebAuthn Level 3 规范中的顶级源验证
	// - 与 RPTopOriginVerificationMode 配合使用
	// - 技术要求：
	//   * 格式要求与 RPOrigins 相同
	//   * 在使用 TopOriginImplicitVerificationMode 时必须配置
	// - 示例：
	//   * ["https://top.example.com"]
	//
	// RPTopOriginVerificationMode：
	// - 配置顶级源验证模式
	// - 用于控制如何验证顶级源
	// - 可选值：
	//   * TopOriginDefaultVerificationMode：默认模式，当前等同于 Ignore 模式
	//   * TopOriginIgnoreVerificationMode：忽略顶级源验证
	//   * TopOriginImplicitVerificationMode：隐式验证模式，需要配置 RPTopOrigins
	//
	// AttestationPreference：
	// - 设置证明（attestation）首选项
	// - 控制如何处理认证器的证明信息
	// - 可选值：
	//   * none：不需要证明信息
	//   * indirect：允许间接证明
	//   * direct：要求直接证明
	// - 建议：
	//   * 一般场景使用 none 即可
	//   * 高安全性要求场景可使用 direct
	//
	// AuthenticatorSelection：
	// - 配置认证器选择条件
	// - 控制哪些类型的认证器可以注册
	// - 主要参数：
	//   * authenticatorAttachment：认证器连接方式（platform/cross-platform）
	//   * requireResidentKey：是否要求驻留密钥
	//   * userVerification：用户验证要求（required/preferred/discouraged）
	// - 示例：
	//   * 仅允许平台认证器：
	//     authenticatorAttachment: platform
	//   * 要求生物识别：
	//     userVerification: required
	//
	// Debug：
	// - 启用调试选项
	// - 开发环境建议：true
	// - 生产环境建议：false
	// - 启用后会输出更多日志信息
	//
	// EncodeUserIDAsString：
	// - 控制用户 ID 的编码方式
	// - 当设置为 true 时：
	//   * user.id 在注册时会被编码为原始 UTF8 字符串
	//   * 适用于仅使用可打印 ASCII 字符的场景
	// - 当设置为 false 时：
	//   * 使用默认的字节编码
	// - 建议：除非特殊需求，保持默认值 false
	//
	// Timeouts：
	// - 配置各种操作的超时时间
	// - 包含两个主要配置：
	//   * Login：登录相关超时设置
	//   * Registration：注册相关超时设置
	// - 每个配置包含：
	//   * Enforce：是否在服务端强制执行超时
	//   * Timeout：标准超时时间
	//   * TimeoutUVD：用户验证被设置为 discouraged 时的超时时间
	// - 建议值：
	//   * Timeout：30-60 秒
	//   * TimeoutUVD：120 秒
	//
	// MDS（Metadata Service）：
	// - 配置元数据服务提供者
	// - 用于验证认证器的元数据
	// - 可以配置为：
	//   * nil：不使用元数据验证
	//   * FIDO MDS：使用 FIDO 联盟的元数据服务
	//   * 自定义实现：实现 metadata.Provider 接口
	//
	// 安全建议：
	// 1. 生产环境配置：
	//    - 必须使用 HTTPS
	//    - 使用实际域名替换 localhost
	//    - 确保所有域名都有有效的 SSL 证书
	//    - 定期更新 SSL 证书
	//    - 使用强制 HTTPS 跳转
	//
	// 2. 多域名处理：
	//    - RPID 设置为所有域名的共同后缀
	//    - 在 RPOrigins 中列出所有允许的域名
	//    - 确保所有域名都属于同一组织
	//    - 实施严格的 CSP 策略
	//    - 配置正确的 CORS 策略
	//
	// 3. 配置管理：
	//    - 使用环境变量或配置文件管理这些值
	//    - 不同环境（开发、测试、生产）使用不同配置
	//    - 定期检查和更新证书
	//    - 使用配置版本控制
	//    - 实施配置更改审计
	//
	// 4. 错误处理：
	//    - 添加域名验证逻辑
	//    - 实现优雅的错误提示
	//    - 记录详细的错误日志
	//    - 实现自动化配置测试
	//    - 监控证书过期时间
	//
	// 5. 安全性增强：
	//    - 启用证书透明度监控
	//    - 配置 HSTS 策略
	//    - 实施双因素认证
	//    - 定期进行安全审计
	//    - 监控异常访问模式
	//
	// 6. 超时处理：
	//    - 根据业务需求调整超时时间
	//    - 考虑网络延迟因素
	//    - 实现超时重试机制
	//    - 提供清晰的用户反馈
	//    - 记录超时事件日志
	//
	// 7. 认证器选择：
	//    - 根据安全需求选择合适的认证器类型
	//    - 考虑用户设备兼容性
	//    - 提供降级认证方案
	//    - 实现认证器健康检查
	//    - 监控认证失败率
	h.webauthn, _ = webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Passkey Demo",
		RPOrigins: []string{
			"http://localhost:44444",
			"http://127.0.0.1:44444",
			"https://local.ppno.net:44444",
		},
	})

	return h
}

// ServeHTTP 实现了 http.Handler 接口，处理所有进入的 HTTP 请求。
// 当请求访问根路径（"/"）或 "index.html" 时，将返回主页面。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//   - r：包含 HTTP 请求信息的 Request 对象
func (s *passkeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/" || path == "/index.html":
		if err := s.serveIndexHTML(w); err != nil {
			s.logger.Error("服务主页失败", "error", err)
			http.Error(w, "服务主页失败", http.StatusInternalServerError)
		}
	case strings.HasPrefix(path, "/api/register/begin"):
		s.handleBeginRegistration(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveIndexHTML 处理主页请求，返回 index.html 文件内容。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//
// 返回值：
//   - error：可能发生的错误
func (s *passkeyServer) serveIndexHTML(w http.ResponseWriter) error {
	f, err := appweb.StaticFiles.Open("static/index.html")
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			s.logger.Error("关闭文件失败", "error", err)
		}
	}()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = io.Copy(w, f)
	return err
}

// handleBeginRegistration 处理用户注册请求。
// 该函数负责验证用户信息、创建新用户、生成注册选项并设置会话。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//   - r：包含 HTTP 请求信息的 Request 对象
func (s *passkeyServer) handleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:44444")
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:44444")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("解析请求数据失败", "error", err)
		http.Error(w, "无法解析请求数据", http.StatusBadRequest)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("关闭请求体失败", "error", err)
		}
	}()

	username := req.Username
	if username == "" {
		s.logger.Error("用户名为空")
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.userDB[username]; exists {
		s.logger.Error("用户已存在", "username", username)
		http.Error(w, "用户已存在", http.StatusBadRequest)
		return
	}

	user := apppasskey.NewUser([]byte(username), username, username)

	options, sessionData, err := s.webauthn.BeginRegistration(user)
	if err != nil {
		s.logger.Error("开始注册失败", "error", err, "username", username)
		http.Error(w, "开始注册失败", http.StatusInternalServerError)
		return
	}

	sessionID := username
	s.sessions[sessionID] = &Session{Data: sessionData}
	s.userDB[username] = user

	http.SetCookie(w, &http.Cookie{
		Name:     "registration_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	if err := json.NewEncoder(w).Encode(options); err != nil {
		s.logger.Error("编码响应失败", "error", err, "username", username)
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}

	s.logger.Info("注册开始成功", "username", username)
}
