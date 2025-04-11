// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

//go:build wireinject
// +build wireinject

// Package web 的 wire.go 文件定义了依赖注入的配置。
// 该文件使用 Wire 框架自动生成依赖注入代码，实现了各个组件之间的依赖关系管理。
package web

import (
	"github.com/google/wire"

	// 模板：下面这条导入，应用时需要修改。
	appbiz "github.com/fsyyft-go/intro-to-passkey/internal/biz"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	appdata "github.com/fsyyft-go/intro-to-passkey/internal/data"
	appserver "github.com/fsyyft-go/intro-to-passkey/internal/server"
	appservice "github.com/fsyyft-go/intro-to-passkey/internal/service"
)

// wireWeb 是 Wire 框架的注入器函数，用于构建完整的 Web 服务实例。
// 该函数通过 Wire 工具在编译时生成具体的依赖注入代码。
//
// 参数：
//   - conf: 应用程序配置对象
//
// 返回：
//   - appserver.WebServer: 完整配置的 Web 服务实例
//   - func(): 清理函数，用于释放资源
//   - error: 初始化过程中的错误信息
func wireWeb(conf *appconf.Config) (appserver.WebServer, func(), error) {
	// wire.Build 声明了完整的依赖关系图。
	// 在编译时，Wire 工具会将此 panic 调用替换为实际的依赖注入实现代码。
	// 如果 make generate 无法生成代码，可以使用 wire ./internal/app/web 命令查看详细错误信息。
	panic(wire.Build(
		ProviderSet,
		appserver.ProviderSet,
		appservice.ProviderSet,
		appbiz.ProviderSet,
		appdata.ProviderSet,
	))
}
