// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package web 提供了 Web 应用程序的核心功能实现。
// 包括配置管理、服务生命周期管理、依赖注入以及信号处理等功能。
package web

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/wire"

	// 模板：下面这条导入，应用时需要修改。
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
	applog "github.com/fsyyft-go/intro-to-passkey/internal/log"
)

// ProviderSet 是 Wire 框架的依赖注入提供者集合。
// 它定义了创建应用实例所需的所有依赖关系，包括日志记录器等核心组件。
var ProviderSet = wire.NewSet(
	applog.NewLogger,
)

// Run 启动并运行 Web 服务。
// 该函数完成以下任务：
//   - 解析命令行参数，获取配置文件路径
//   - 加载并解析配置文件
//   - 设置系统信号处理，支持优雅关闭
//   - 通过依赖注入初始化服务组件
//   - 启动 Web 服务并监控其运行状态
func Run() {
	// 定义配置文件路径的命令行参数。
	var configPath string

	// 注册命令行参数，设置默认配置文件路径为 configs/config.yaml。
	flag.StringVar(&configPath, "config", "configs/config.yaml", "配置文件路径")
	flag.Parse()

	// 从指定路径加载配置文件。
	cfg, err := appconf.LoadConfig(configPath)
	if nil != err {
		fmt.Printf("加载配置文件失败：%v", err)
		return
	}

	// 创建带取消功能的上下文，用于优雅关闭。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建系统信号监听通道。
	signalChan := make(chan os.Signal, 1)
	// 注册 SIGINT 和 SIGTERM 信号的处理。
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动独立的 goroutine 处理系统信号。
	go func() {
		sig := <-signalChan
		fmt.Printf("接收到系统信号：%v\n", sig)
		cancel() // 触发上下文取消，开始优雅关闭流程。
	}()

	// 使用 Wire 框架生成的 wireWeb 函数初始化服务实例。
	if task, cleanup, err := wireWeb(cfg); nil != err {
		fmt.Printf("初始化服务失败：%v", err)
		cleanup() // 发生错误时，调用清理函数释放已分配的资源。
	} else {
		// 启动 Web 服务并等待其运行完成。
		_ = task.Start(ctx)
	}
}
