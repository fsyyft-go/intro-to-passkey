// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package server 提供了 Web 服务器的核心实现。
// 包括 HTTP 服务器的配置、路由管理、中间件集成以及依赖注入设置。
package server

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是服务器层的依赖注入提供者集合。
	// 包含了创建和配置 Web 服务器所需的所有组件。
	ProviderSet = wire.NewSet(
		NewWebServer,
	)
)
