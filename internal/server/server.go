// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package server 提供了 HTTP 服务器的实现和配置，包括路由处理和中间件设置。
package server

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是服务器层的依赖注入提供者集合。
	ProviderSet = wire.NewSet(
		NewWebServer,
	)
)
