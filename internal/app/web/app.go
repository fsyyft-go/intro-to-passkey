// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package web 提供了 Web 应用程序的入口点和运行时管理，包括配置加载、服务启动和信号处理。
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

// ProviderSet 是 wire 的依赖注入提供者集合。
// 包含了创建应用实例所需的所有依赖。
var ProviderSet = wire.NewSet(
	applog.NewLogger,
)

// Run 启动并运行任务执行器。
// 该函数负责：
//   - 解析命令行参数
//   - 加载配置文件
//   - 设置信号处理
//   - 初始化并启动服务
func Run() {
	// 定义配置文件路径变量，默认为"configs/config.yaml"。
	var configPath string

	// 注册命令行参数，用于指定配置文件路径。
	flag.StringVar(&configPath, "config", "configs/config.yaml", "配置文件路径")
	flag.Parse()

	// 从指定路径加载配置文件。
	cfg, err := appconf.LoadConfig(configPath)
	if nil != err {
		fmt.Printf("加载配置文件失败：%v", err)
		return
	}

	// 增加监听操作系统信号，以优雅地关闭服务器。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建信号通道。
	signalChan := make(chan os.Signal, 1)
	// 监听 SIGINT 和 SIGTERM 信号。
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// 在单独的 goroutine 中处理信号。
	go func() {
		sig := <-signalChan
		fmt.Printf("接收到系统信号: %v\n", sig)
		cancel() // 取消上下文。
	}()

	// 通过 Wire 框架生成的 wireServer 函数初始化服务。
	// 该函数会自动注入所有依赖项并返回配置好的 Web 服务器实例。
	if task, cleanup, err := wireWeb(cfg); nil != err {
		fmt.Printf("初始化失败：%v", err)
		// 调用清理函数释放已分配的资源。
		cleanup()
	} else {
		// 启动 Web 服务器。
		_ = task.Start(ctx)
	}
}
