// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package service 实现了应用程序的业务服务层，包括问候服务等具体功能的实现。
package service

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是服务层的依赖注入提供者集合。
	ProviderSet = wire.NewSet(
		NewGreeterService,
	)
)
