// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package server

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/http"

	kitkratosmiddlewarevalidate "github.com/fsyyft-go/kit/kratos/middleware/validate"
	kitkratostransporthttp "github.com/fsyyft-go/kit/kratos/transport/http"
	kitlog "github.com/fsyyft-go/kit/log"
	kitruntime "github.com/fsyyft-go/kit/runtime"

	apphelloworldv1 "github.com/fsyyft-go/intro-to-passkey/api/helloworld/v1"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

var (
	_ WebServer = (*webServer)(nil)
)

type (
	// WebServer 定义了 Web 服务器的接口。
	WebServer interface {
		kitruntime.Runner    // 继承 Runner 接口，提供 Start 和 Stop 方法。
		Engine() *gin.Engine // 返回 Gin 引擎实例，允许外部访问和配置。
	}

	// webServer 实现了 WebServer 接口，提供 Web 服务器功能。
	webServer struct {
		// 日志记录器。
		logger kitlog.Logger
		// 应用配置。
		conf *appconf.Config
		// Gin 引擎，用于处理 HTTP 请求。
		engine *gin.Engine
	}
)

// NewWebServer 创建并配置一个新的 Web 服务器实例。
//
// 参数：
//   - logger：日志记录器，用于服务日志记录。
//   - conf：服务配置信息。
//   - greeter：问候服务的 HTTP 处理器。
//
// 返回：
//   - WebServer：配置好的 Web 服务器实例。
//   - func()：清理函数。
//   - error：初始化过程中可能发生的错误。
func NewWebServer(logger kitlog.Logger, conf *appconf.Config,
	greeter apphelloworldv1.GreeterHTTPServer,
) (WebServer, func(), error) {
	var err error

	// 创建带有领域驱动设计和模块标记的日志记录器。
	l := logger.WithField("ddd", "server").WithField("module", "web")

	webServer := &webServer{
		logger: l,
		conf:   conf,
	}

	server := http.NewServer(
		http.Middleware(
			recovery.Recovery(),
			kitkratosmiddlewarevalidate.Validator(kitkratosmiddlewarevalidate.WithValidateCallback(webServer.validateCallback)),
		),
	)

	apphelloworldv1.RegisterGreeterHTTPServer(server, greeter)

	// 初始化 Gin 引擎，并配置默认中间件。
	webServer.engine = gin.Default()
	// 将 Kratos HTTP 服务解析到 Gin 引擎中。
	kitkratostransporthttp.Parse(server, webServer.engine)

	var cleanup = func() {}

	return webServer, cleanup, err
}

// Start 实现启动 Web 服务器的功能。
// 使用 Gin 引擎监听指定端口。
//
// 参数：
//   - ctx：上下文信息（当前未使用）。
//
// 返回值：
//   - error：启动过程中可能发生的错误。
func (s *webServer) Start(_ context.Context) error {
	// 使用 Gin 引擎在配置的端口上启动 HTTP 服务。
	return s.engine.Run(s.conf.GetServer().GetHttp().GetAddr())
}

// Stop 实现停止 Web 服务器的功能。
//
// 参数：
//   - ctx：上下文信息（当前未使用）。
//
// 返回值：
//   - error：停止过程中可能发生的错误。
func (s *webServer) Stop(_ context.Context) error {
	panic("unimplemented")
}

// Engine 返回 Gin 引擎实例。
//
// 返回值：
//   - *gin.Engine：配置好的 Gin 引擎实例。
func (s *webServer) Engine() *gin.Engine {
	panic("unimplemented")
}

// validateCallback 处理请求验证失败的回调函数。
// 记录请求和验证错误，并返回标准化的错误响应。
//
// 参数：
//   - ctx：上下文信息（当前未使用）。
//   - req：原始请求。
//   - errValidate：验证过程中产生的错误。
//
// 返回值：
//   - interface{}：处理后的请求（本实现中返回 nil）。
//   - error：格式化后的错误信息。
func (s *webServer) validateCallback(_ context.Context, req interface{}, errValidate error) (interface{}, error) {
	// 记录请求和验证错误信息。
	s.logger.WithField("req", req).WithField("errValidate", errValidate).Info("validateCallback")
	// 返回标准化的错误响应。
	return nil, errors.BadRequest("VALIDATOR", "请求参数错误，详见日志")
}
