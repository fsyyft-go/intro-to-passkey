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

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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

// passkeyServer 是 Passkey 认证服务器的核心实现结构体。
// 它负责处理所有与 Passkey 认证相关的 HTTP 请求，并管理认证流程。
type passkeyServer struct {
	logger   kitlog.Logger                   // 日志记录器，用于记录服务器运行时的日志信息。
	conf     *appconf.Config                 // 服务器配置信息。
	webauthn *webauthn.WebAuthn              // WebAuthn 实例，用于处理认证相关操作。
	userDB   map[string]webauthn.User        // 用户数据库，存储所有注册用户信息。
	sessions map[string]webauthn.SessionData // 会话存储，用于管理注册会话。
	mu       sync.RWMutex                    // 互斥锁，用于保护并发访问。
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
		sessions: make(map[string]webauthn.SessionData),
	}

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

	options, sessionData, err := s.webauthn.BeginRegistration(user,
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgES256,
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgEdDSA,
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgRS256,
			},
		}),
		webauthn.WithAttestationFormats([]protocol.AttestationFormat{
			protocol.AttestationFormatNone,
		}),
	)
	if err != nil {
		s.logger.Error("开始注册失败", "error", err, "username", username)
		http.Error(w, "开始注册失败", http.StatusInternalServerError)
		return
	}

	sessionID := username
	s.sessions[sessionID] = *sessionData
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
