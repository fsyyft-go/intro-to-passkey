// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package server 的 web.go 文件实现了基于 Gin 框架的 Web 服务器。
// 提供了 HTTP 请求处理、中间件集成、路由配置等核心功能。
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
	apppasskey "github.com/fsyyft-go/intro-to-passkey/internal/server/passkey"
)

var (
	// 确保 webServer 实现了 WebServer 接口。
	_ WebServer = (*webServer)(nil)
)

type (
	// WebServer 定义了 Web 服务器的接口规范。
	// 继承了 kitruntime.Runner 接口，提供服务生命周期管理功能。
	WebServer interface {
		kitruntime.Runner    // 提供 Start 和 Stop 方法。
		Engine() *gin.Engine // 返回 Gin 引擎实例，用于外部路由和中间件配置。
	}

	// webServer 是 WebServer 接口的具体实现。
	// 整合了日志、配置和 HTTP 引擎等核心组件。
	webServer struct {
		logger kitlog.Logger   // 结构化日志记录器。
		conf   *appconf.Config // 应用程序配置对象。
		engine *gin.Engine     // Gin Web 框架的引擎实例。
	}
)

// NewWebServer 创建并初始化一个新的 Web 服务器实例。
//
// 参数：
//   - logger：结构化日志记录器，用于服务运行时的日志记录
//   - conf：应用程序配置对象，包含服务器和其他组件的配置信息
//   - greeter：问候服务的 HTTP 处理器，实现了 gRPC 生成的服务接口
//
// 返回：
//   - WebServer：已配置的 Web 服务器实例
//   - func()：资源清理函数，用于服务关闭时的清理工作
//   - error：初始化过程中可能发生的错误
func NewWebServer(logger kitlog.Logger, conf *appconf.Config,
	greeter apphelloworldv1.GreeterHTTPServer,
) (WebServer, func(), error) {
	var err error

	// 创建带有 DDD 和模块标记的结构化日志记录器。
	l := logger.WithField("ddd", "server").WithField("module", "web")

	webServer := &webServer{
		logger: l,
		conf:   conf,
	}

	// 创建 Kratos HTTP 服务器，配置中间件。
	server := http.NewServer(
		http.Middleware(
			recovery.Recovery(), // 异常恢复中间件。
			kitkratosmiddlewarevalidate.Validator(kitkratosmiddlewarevalidate.WithValidateCallback(webServer.validateCallback)), // 请求验证中间件。
		),
	)

	// 注册 gRPC 生成的 HTTP 服务处理器。
	apphelloworldv1.RegisterGreeterHTTPServer(server, greeter)

	// 初始化 Gin 引擎并配置默认中间件。
	webServer.engine = gin.Default()
	// 将 Kratos HTTP 服务解析并集成到 Gin 引擎中。
	kitkratostransporthttp.Parse(server, webServer.engine)

	// 创建 Passkey 认证服务器并配置路由。
	ps := apppasskey.New(logger, conf)
	// 配置主页路由。
	webServer.engine.GET("/", gin.HandlerFunc(func(c *gin.Context) {
		ps.ServeHTTP(c.Writer, c.Request)
	}))
	// 配置注册接口路由。
	webServer.engine.POST("/api/register/*path", gin.HandlerFunc(func(c *gin.Context) {
		ps.ServeHTTP(c.Writer, c.Request)
	}))
	// 配置登录接口路由。
	webServer.engine.POST("/api/login/*path", gin.HandlerFunc(func(c *gin.Context) {
		ps.ServeHTTP(c.Writer, c.Request)
	}))

	var cleanup = func() {}

	return webServer, cleanup, err
}

// Start 启动 Web 服务器。
// 实现了 kitruntime.Runner 接口的 Start 方法。
//
// 参数：
//   - ctx：上下文对象，用于控制服务器的生命周期
//
// 返回：
//   - error：服务器启动过程中可能发生的错误
func (s *webServer) Start(_ context.Context) error {
	// 使用配置的地址启动 HTTP 服务器。
	return s.engine.Run(s.conf.GetServer().GetHttp().GetAddr())
}

// Stop 停止 Web 服务器。
// 实现了 kitruntime.Runner 接口的 Stop 方法。
//
// 参数：
//   - ctx：上下文对象，用于控制关闭过程
//
// 返回：
//   - error：服务器停止过程中可能发生的错误
func (s *webServer) Stop(_ context.Context) error {
	return nil
}

// Engine 返回 Gin 引擎实例。
// 允许外部代码访问和配置 Gin 引擎。
//
// 返回：
//   - *gin.Engine：当前服务器使用的 Gin 引擎实例
func (s *webServer) Engine() *gin.Engine {
	return s.engine
}

// validateCallback 是请求参数验证失败时的回调处理函数。
// 实现了统一的验证错误处理和日志记录。
//
// 参数：
//   - ctx：请求上下文
//   - req：原始请求对象
//   - errValidate：验证过程中产生的错误
//
// 返回：
//   - interface{}：处理后的请求对象（本实现中返回 nil）
//   - error：格式化后的错误信息
func (s *webServer) validateCallback(_ context.Context, req interface{}, errValidate error) (interface{}, error) {
	// 记录验证失败的请求信息。
	s.logger.WithField("req", req).WithField("errValidate", errValidate).Info("validateCallback")
	// 返回标准化的错误响应。
	return nil, errors.BadRequest("VALIDATOR", "请求参数错误，详见日志")
}
