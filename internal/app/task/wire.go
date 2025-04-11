// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

//go:build wireinject
// +build wireinject

package task

import (
	"github.com/google/wire"

	// 模板：下面这条导入，应用时需要修改。
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	apptask "github.com/fsyyft-go/intro-to-passkey/internal/task"
)

func wireTask(cfg *appconf.Config) (apptask.Hello, func(), error) {
	// wire.Build 函数用于声明依赖关系图，将所有组件连接在一起。
	// panic 调用会在编译时被 wire 工具替换为实际的依赖注入代码。
	// make generate 如果无法生成时，可以尝试使用 wire ./internal/app/task 生成，可以看到更加详细的错误处理。
	panic(wire.Build(
		ProviderSet,
		apptask.ProviderSet,
	))
}
