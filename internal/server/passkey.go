// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"

	kitlog "github.com/fsyyft-go/kit/log"

	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	appweb "github.com/fsyyft-go/intro-to-passkey/web"
)

// RegisterRequest 定义了用户注册请求的数据结构。
// 该结构体用于接收客户端发送的注册请求数据。
type RegisterRequest struct {
	Username string `json:"username"` // 用户名，用于标识用户身份
}

// User 实现了 webauthn.User 接口，用于存储用户信息和凭证。
// 该结构体包含了 WebAuthn 认证所需的所有用户相关数据。
type User struct {
	ID          []byte                // 用户唯一标识符
	Name        string                // 用户名
	DisplayName string                // 用户显示名称
	Credentials []webauthn.Credential // 用户凭证列表
}

// Session 用于存储注册会话数据。
// 该结构体用于在注册过程中临时存储会话相关信息。
type Session struct {
	Data interface{} // 会话数据，可以是任意类型
}

// passkeyServer 是 Passkey 认证服务器的核心实现结构体。
// 它负责处理所有与 Passkey 认证相关的 HTTP 请求，并管理认证流程。
type passkeyServer struct {
	logger   kitlog.Logger       // 日志记录器，用于记录服务器运行时的日志信息
	conf     *appconf.Config     // 服务器配置信息
	webauthn *webauthn.WebAuthn  // WebAuthn 实例，用于处理认证相关操作
	userDB   map[string]*User    // 用户数据库，存储所有注册用户信息
	sessions map[string]*Session // 会话存储，用于管理注册会话
	mu       sync.RWMutex        // 互斥锁，用于保护并发访问
}

// WebAuthnID 实现 webauthn.User 接口，返回用户的唯一标识符。
// 返回值：用户 ID 的字节数组表示。
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName 实现 webauthn.User 接口，返回用户名。
// 返回值：用户名字符串。
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName 实现 webauthn.User 接口，返回用户显示名称。
// 返回值：用户显示名称字符串。
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials 实现 webauthn.User 接口，返回用户凭证列表。
// 返回值：用户凭证数组。
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon 实现 webauthn.User 接口，返回用户图标 URL。
// 返回值：空字符串，表示不使用用户图标。
func (u *User) WebAuthnIcon() string {
	return ""
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
		userDB:   make(map[string]*User),
		sessions: make(map[string]*Session),
	}

	h.webauthn, _ = webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Passkey Demo",
		RPOrigins:     []string{"http://localhost:44444", "http://127.0.0.1:44444"},
	})

	return h
}

// ServeHTTP 实现了 http.Handler 接口，处理所有进入的 HTTP 请求。
// 当请求访问根路径（"/"）或 "index.html" 时，将返回主页面。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//   - r：包含 HTTP 请求信息的 Request 对象
func (s *passkeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		if err := s.serveIndexHTML(w); err != nil {
			s.logger.Error("failed to serve index.html", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	case "/api/register/begin":
		s.handleBeginRegistration(w, r)
	}
}

// serveIndexHTML 处理对 index.html 的请求。
// 它从嵌入的文件系统中读取 index.html 文件并将其发送给客户端。
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter
//
// 返回值：
//   - error：如果在处理过程中发生错误，返回相应的错误信息
func (s *passkeyServer) serveIndexHTML(w http.ResponseWriter) error {
	f, err := appweb.StaticFiles.Open("static/index.html")
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			s.logger.Error("failed to close index.html", "error", err)
		}
	}()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, err = io.Copy(w, f)
	return err
}

// handleBeginRegistration 处理用户注册的初始请求。
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
	defer r.Body.Close()

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

	user := &User{
		ID:          []byte(username),
		Name:        username,
		DisplayName: username,
		Credentials: make([]webauthn.Credential, 0),
	}

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
