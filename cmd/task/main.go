// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package main 实现了任务执行器的入口程序。
// 该程序负责初始化配置、依赖注入，并启动任务执行器。
package main

import (
	apptask "github.com/fsyyft-go/intro-to-passkey/internal/app/task"
)

func main() {
	// 应用程序入口。
	// 测试过在某些情况下，使用 wire 生成代码时，会报错，可能是因为这时 main 包的原因，所以这里只包含入口。
	apptask.Run()
}
