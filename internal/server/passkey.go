// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package server

import (
	"io"
	"net/http"

	kitlog "github.com/fsyyft-go/kit/log"

	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	appweb "github.com/fsyyft-go/intro-to-passkey/web"
)

type (
	// passkeyServer 是 Passkey 认证服务器的核心实现结构体。
	// 它负责处理所有与 Passkey 认证相关的 HTTP 请求，并管理认证流程。
	passkeyServer struct {
		// logger 用于记录服务器运行时的日志信息。
		logger kitlog.Logger
		// conf 存储服务器的配置信息。
		conf *appconf.Config
	}
)

// newPasskeyServer 创建一个新的 Passkey 服务器实例。
// 参数：
//   - logger：用于记录服务器日志的日志记录器。
//   - conf：服务器的配置信息。
//
// 返回值：
//   - http.Handler：实现了 HTTP 请求处理接口的 Passkey 服务器实例。
func newPasskeyServer(logger kitlog.Logger, conf *appconf.Config) http.Handler {
	h := &passkeyServer{
		logger: logger,
		conf:   conf,
	}

	return h
}

// ServeHTTP 实现了 http.Handler 接口，处理所有进入的 HTTP 请求。
// 当请求访问根路径（"/"）或 "index.html" 时，将返回主页面。
//
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter。
//   - r：包含 HTTP 请求信息的 Request 对象。
func (s *passkeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 处理对根路径和 index.html 的请求。
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		if err := s.serveIndexHTML(w); err != nil {
			// 如果在处理过程中发生错误，记录错误并返回 500 状态码。
			s.logger.Error("failed to serve index.html", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
}

// serveIndexHTML 处理对 index.html 的请求。
// 它从嵌入的文件系统中读取 index.html 文件并将其发送给客户端。
//
// 参数：
//   - w：用于写入 HTTP 响应的 ResponseWriter。
//
// 返回值：
//   - error：如果在处理过程中发生错误，返回相应的错误信息。
func (s *passkeyServer) serveIndexHTML(w http.ResponseWriter) error {
	// 从嵌入的文件系统中读取 index.html 文件。
	f, err := appweb.StaticFiles.Open("static/index.html")
	if err != nil {
		return err
	}
	defer func() {
		// 确保文件在函数返回时被关闭。
		if err := f.Close(); err != nil {
			s.logger.Error("failed to close index.html", "error", err)
		}
	}()

	// 设置响应的 Content-Type 头部为 HTML。
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 将文件内容复制到 HTTP 响应中。
	_, err = io.Copy(w, f)
	return err
}
