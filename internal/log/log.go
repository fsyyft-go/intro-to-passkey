// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package log 提供了应用程序的日志功能和依赖注入设置。
package log

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是日志模块的依赖注入提供者集合。
	ProviderSet = wire.NewSet(
		NewLogger,
	)
)
