// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package log

import (
	"fmt"
	"os"
	"strings"
	"sync"

	kitlog "github.com/fsyyft-go/kit/log"

	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

var (
	// logger 是全局共享的日志记录器实例。
	logger kitlog.Logger
	// loggerLocker 是用于保护 logger 变量的读写锁，确保并发安全。
	loggerLocker sync.RWMutex = sync.RWMutex{}
)

// NewLogger 创建并初始化一个日志记录器实例。
// 该函数使用单例模式确保只创建一个全局日志记录器。
//
// 参数：
//   - cfg *conf.Config：应用程序配置对象，包含日志相关设置。
//
// 返回值：
//   - log.Logger：初始化后的日志记录器实例。
//   - func()：清理函数，用于在初始化失败时进行资源释放。
//   - error：初始化过程中可能发生的错误。
func NewLogger(cfg *appconf.Config) (kitlog.Logger, func(), error) {
	var err error

	// 检查日志记录器是否已经初始化
	if nil == logger {
		// 加锁以防止并发初始化
		loggerLocker.Lock()
		defer loggerLocker.Unlock()

		// 双重检查锁定模式，确保日志记录器仅初始化一次。
		if nil == logger {
			// 使用配置创建新的日志记录器。
			if l, errNew := kitlog.NewLogger(
				kitlog.WithLogType(kitlog.LogType(cfg.Log.Type)),
				kitlog.WithOutput(cfg.Log.Output),
			); nil != err {
				err = errNew
			} else {
				// 设置日志级别。
				if level, err := kitlog.ParseLevel(cfg.Log.Level); nil != err {
					l.WithField("error", err).Error("解析日志级别失败")
				} else {
					l.SetLevel(level)
					// 获取 hostname 的短形式，例如 a.b.com 则是只返回 a。
					hostname, err := os.Hostname()
					if nil != err {
						hostname = "unknown"
					} else {
						hostname = strings.Split(hostname, ".")[0]
					}
					// 添加进程 ID 字段、主机名字段，方便调试。
					l = l.WithField("pid", os.Getpid()).WithField("hn", hostname)

					l.WithField("log_level", level).Info("设置日志级别")
				}

				// 更新全局日志记录器。
				logger = l
			}
		}
	}

	return logger, cleanupLogger, err
}

// cleanupLogger 清理日志记录器资源并记录初始化失败信息。
// 该函数在初始化出错时由 Wire 框架调用。
func cleanupLogger() {
	if nil != logger {
		// 如果日志记录器已初始化，使用它记录警告信息。
		logger.Warn("初始化失败")
		logger = nil
	} else {
		// 日志记录器未初始化，使用标准输出
		fmt.Println("初始化失败")
	}
}
