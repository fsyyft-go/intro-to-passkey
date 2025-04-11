// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package passkey 的 server.go 文件实现了 WebAuthn 认证服务器。
// 提供了用户注册、登录认证等核心功能的 HTTP 接口实现。
package passkey

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	kitlog "github.com/fsyyft-go/kit/log"

	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	appweb "github.com/fsyyft-go/intro-to-passkey/web"
)

// Cookie 名称常量定义。
const (
	// cookienamereg 用于存储注册会话的 Cookie 名称。
	cookienamereg = "registration_session"
	// cookienamelogin 用于存储登录会话的 Cookie 名称。
	cookienamelogin = "login_session"
)

// Request 定义了用户注册和登录请求的数据结构。
type Request struct {
	// Username 是用户的登录名。
	// 在注册时用作唯一标识，在登录时用于查找用户。
	Username string `json:"username"`
}

// Server 是 Passkey 认证服务器的核心实现。
// 负责处理用户注册、认证等所有 WebAuthn 相关的 HTTP 请求。
type Server struct {
	logger   kitlog.Logger                   // 结构化日志记录器。
	conf     *appconf.Config                 // 服务器配置对象。
	webauthn *webauthn.WebAuthn              // WebAuthn 协议处理器。
	userDB   map[string]webauthn.User        // 内存中的用户数据存储。
	sessions map[string]webauthn.SessionData // 认证会话数据存储。
	mu       sync.RWMutex                    // 用于保护并发访问的互斥锁。
}

// New 创建并初始化一个新的 Passkey 服务器实例。
//
// 参数：
//   - logger：结构化日志记录器，用于服务器运行时的日志记录
//   - conf：服务器配置对象，包含所有必要的配置参数
//
// 返回：
//   - http.Handler：配置完成的 HTTP 请求处理器
func New(logger kitlog.Logger, conf *appconf.Config) http.Handler {
	// 创建服务器实例并初始化基本字段。
	h := &Server{
		logger:   logger,
		conf:     conf,
		userDB:   make(map[string]webauthn.User),
		sessions: make(map[string]webauthn.SessionData),
	}

	// 初始化 WebAuthn 配置。
	h.webauthn, _ = webauthn.New(&webauthn.Config{
		RPID:          "localhost",    // 信赖方标识符。
		RPDisplayName: "Passkey Demo", // 信赖方显示名称。
		RPOrigins: []string{ // 允许的源地址列表。
			"http://localhost:44444",
			"http://127.0.0.1:44444",
			"https://local.ppno.net:44444",
		},
	})

	return h
}

// ServeHTTP 实现了 http.Handler 接口，处理所有 WebAuthn 相关的 HTTP 请求。
// 根据请求路径将请求分发到相应的处理函数。
//
// 参数：
//   - w：HTTP 响应写入器
//   - r：HTTP 请求对象
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 获取请求路径并进行路由分发。
	path := r.URL.Path
	switch {
	case path == "/" || path == "/index.html":
		// 处理主页请求。
		if err := s.serveIndexHTML(w); err != nil {
			s.logger.Error("服务主页失败", "error", err)
			http.Error(w, "服务主页失败", http.StatusInternalServerError)
		}
	case strings.HasPrefix(path, "/api/register/begin"):
		// 处理注册流程的开始请求。
		s.handleBeginRegistration(w, r)
	case strings.HasPrefix(path, "/api/register/finish"):
		// 处理注册流程的完成请求。
		s.handleFinishRegistration(w, r)
	case strings.HasPrefix(path, "/api/login/begin"):
		// 处理登录流程的开始请求。
		s.handleBeginLogin(w, r)
	case strings.HasPrefix(path, "/api/login/finish"):
		// 处理登录流程的完成请求。
		s.handleFinishLogin(w, r)
	default:
		// 处理未知路径的请求。
		http.NotFound(w, r)
	}
}

// serveIndexHTML 处理主页请求，返回静态 HTML 文件。
//
// 参数：
//   - w：HTTP 响应写入器
//
// 返回：
//   - error：文件处理过程中可能发生的错误
func (s *Server) serveIndexHTML(w http.ResponseWriter) error {
	// 打开静态 HTML 文件。
	f, err := appweb.StaticFiles.Open("static/index.html")
	if err != nil {
		return err
	}
	// 确保文件最终被关闭。
	defer func() {
		if err := f.Close(); err != nil {
			s.logger.Error("关闭文件失败", "error", err)
		}
	}()

	// 设置正确的内容类型。
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 将文件内容写入响应。
	_, err = io.Copy(w, f)
	return err
}

// handleBeginRegistration 处理用户注册流程的开始阶段。
// 验证用户信息，创建注册会话，并返回客户端所需的注册选项。
//
// 参数：
//   - w：HTTP 响应写入器
//   - r：HTTP 请求对象
func (s *Server) handleBeginRegistration(w http.ResponseWriter, r *http.Request) {
	// 解析请求体中的用户信息。
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("解析请求数据失败", "error", err)
		http.Error(w, "无法解析请求数据", http.StatusBadRequest)
		return
	}
	// 确保请求体被正确关闭。
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("关闭请求体失败", "error", err)
		}
	}()

	// 验证用户名的有效性。
	username := req.Username
	if username == "" {
		s.logger.Warn("用户名为空")
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}

	// 使用互斥锁保护并发访问。
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查用户是否已存在且已注册凭证。
	if user, exists := s.userDB[username]; exists {
		if nil != user.WebAuthnCredentials() && len(user.WebAuthnCredentials()) > 0 {
			s.logger.Warn("用户已存在", "username", username)
			http.Error(w, "用户已存在", http.StatusBadRequest)
			return
		}
	}

	// 创建新用户实例。
	user := NewUser([]byte(username), username, username)

	// 开始 WebAuthn 注册流程。
	options, sessionData, err := s.webauthn.BeginRegistration(user,
		// 配置支持的凭证参数。
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgES256, // 支持 ECDSA P-256。
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgEdDSA, // 支持 EdDSA。
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgRS256, // 支持 RSA PKCS#1。
			},
		}),
		// 配置支持的证明格式。
		webauthn.WithAttestationFormats([]protocol.AttestationFormat{
			protocol.AttestationFormatNone, // 支持无证明格式。
		}),
	)
	if err != nil {
		s.logger.Error("开始注册失败", "error", err, "username", username)
		http.Error(w, "开始注册失败", http.StatusInternalServerError)
		return
	}

	// 保存会话数据。
	sessionID := username
	s.sessions[sessionID] = *sessionData
	s.userDB[username] = user

	// 设置会话 cookie。
	http.SetCookie(w, &http.Cookie{
		Name:     cookienamereg,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// 将注册选项编码为 JSON 并发送响应。
	if err := json.NewEncoder(w).Encode(options); err != nil {
		s.logger.Error("编码响应失败", "error", err, "username", username)
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}

	s.logger.Info("注册开始成功", "username", username)
}

// handleFinishRegistration 处理完成注册请求。
// 该函数负责验证注册凭证并完成用户注册流程。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//   - r：包含 HTTP 请求信息的 Request 对象
func (s *Server) handleFinishRegistration(w http.ResponseWriter, r *http.Request) {
	// 获取会话 cookie。
	cookie, err := r.Cookie(cookienamereg)
	if err != nil {
		s.logger.Warn("获取会话 ID 失败", "error", err)
		http.Error(w, "获取会话 ID 失败", http.StatusBadRequest)
		return
	}

	// 获取会话 ID。
	sessionID := cookie.Value
	s.mu.Lock()
	defer s.mu.Unlock()

	// 获取会话数据。
	sessionData, ok := s.sessions[sessionID]
	if !ok {
		s.logger.Warn("会话 ID 不存在", "sessionID", sessionID)
		http.Error(w, "会话 ID 不存在", http.StatusBadRequest)
		return
	}

	// 获取用户信息。
	user, ok := s.userDB[string(sessionData.UserID)]
	if !ok {
		s.logger.Warn("用户不存在", "userID", sessionData.UserID)
		http.Error(w, "用户不存在", http.StatusBadRequest)
		return
	}

	// 完成注册流程。
	credential, err := s.webauthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		s.logger.Warn("注册完成失败", "error", err)
		http.Error(w, "注册完成失败", http.StatusInternalServerError)
		return
	}

	// 将凭证添加到用户的凭证列表中。
	user.(*User).AddCredential(*credential)

	s.logger.Info("注册完成成功", "username", user.WebAuthnName())

	// 删除会话数据。
	delete(s.sessions, sessionID)

	// 设置会话 cookie。
	http.SetCookie(w, &http.Cookie{
		Name:     cookienamereg,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func (s *Server) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	// 解析请求体。
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("解析请求数据失败", "error", err)
		http.Error(w, "无法解析请求数据", http.StatusBadRequest)
		return
	}
	// 确保请求体被关闭。
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("关闭请求体失败", "error", err)
		}
	}()

	// 验证用户名。
	username := req.Username
	if username == "" {
		s.logger.Warn("用户名为空")
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}

	// 加锁保护并发访问。
	s.mu.Lock()
	defer s.mu.Unlock()

	var user webauthn.User

	// 检查用户是否已存在。
	if u, exists := s.userDB[username]; !exists {
		s.logger.Warn("用户不存在", "username", username)
		http.Error(w, "用户不存在", http.StatusBadRequest)
		return
	} else {
		user = u
	}

	options, sessionData, err := s.webauthn.BeginLogin(user)
	if err != nil {
		s.logger.Error("开始登录失败", "error", err, "username", username)
		http.Error(w, "开始登录失败", http.StatusInternalServerError)
		return
	}

	// 保存会话数据。
	sessionID := username
	s.sessions[sessionID] = *sessionData

	// 设置会话 cookie。
	http.SetCookie(w, &http.Cookie{
		Name:     cookienamelogin,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	// 将注册选项编码为 JSON 并发送响应。
	if err := json.NewEncoder(w).Encode(options); err != nil {
		s.logger.Error("编码响应失败", "error", err, "username", username)
		http.Error(w, "编码响应失败", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	// 获取会话 cookie。
	cookie, err := r.Cookie(cookienamelogin)
	if err != nil {
		s.logger.Warn("获取会话 ID 失败", "error", err)
		http.Error(w, "获取会话 ID 失败", http.StatusBadRequest)
		return
	}

	// 获取会话 ID。
	sessionID := cookie.Value
	s.mu.Lock()
	defer s.mu.Unlock()

	// 获取会话数据。
	sessionData, ok := s.sessions[sessionID]
	if !ok {
		s.logger.Warn("会话 ID 不存在", "sessionID", sessionID)
		http.Error(w, "会话 ID 不存在", http.StatusBadRequest)
		return
	}

	// 获取用户信息。
	user, ok := s.userDB[string(sessionData.UserID)]
	if !ok {
		s.logger.Warn("用户不存在", "userID", sessionData.UserID)
		http.Error(w, "用户不存在", http.StatusBadRequest)
		return
	}

	// 完成登录流程。
	_, err = s.webauthn.FinishLogin(user, sessionData, r)
	if err != nil {
		s.logger.Warn("登录完成失败", "error", err)
		http.Error(w, "登录完成失败", http.StatusInternalServerError)
		return
	}

	// 删除会话数据。
	delete(s.sessions, sessionID)

	// 设置会话 cookie。
	http.SetCookie(w, &http.Cookie{
		Name:     cookienamelogin,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}
