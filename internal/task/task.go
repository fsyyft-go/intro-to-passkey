// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package task

import (
	"github.com/google/wire"
)

var (
	// ProviderSet 是 wire 的依赖注入提供者集合。
	// 包含了创建任务实例所需的所有依赖。
	ProviderSet = wire.NewSet(NewHello)
)
