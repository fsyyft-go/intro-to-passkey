// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package main 实现了 Web 服务的入口程序。
// 该程序负责启动 Web 服务，通过依赖注入的方式初始化并运行服务。
package main

import (
	appweb "github.com/fsyyft-go/intro-to-passkey/internal/app/web"
)

// main 是程序的入口函数。
// 为了确保依赖注入的正确性，这里只包含最基本的服务启动逻辑，具体的初始化过程由 appweb.Run 函数处理。
func main() {
	// 应用程序入口。
	// 测试过在某些情况下，使用 wire 生成代码时，会报错，可能是因为这时 main 包的原因，所以这里只包含入口。
	appweb.Run()
}
