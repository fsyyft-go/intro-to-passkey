// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package biz 定义了业务逻辑层。
// 包含业务逻辑的定义和实现。
package biz

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是业务层的依赖注入提供者集合。
	ProviderSet = wire.NewSet(
		NewGreeterUsecase,
	)
)
