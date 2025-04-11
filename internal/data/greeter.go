// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package data

import (
	"context"

	kitlog "github.com/fsyyft-go/kit/log"

	appbiz "github.com/fsyyft-go/intro-to-passkey/internal/biz"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

// greeterRepo 实现了 appbiz.GreeterRepo 接口，提供 Greeter 相关的数据访问操作。
type greeterRepo struct {
	// log 用于记录日志信息。
	log kitlog.Logger
	// conf 存储应用配置信息。
	conf *appconf.Config
	// data 提供数据层公共依赖。
	data Data
}

// NewGreeterRepo 创建一个新的 GreeterRepo 实例。
//
// 参数：
//   - logger：日志记录器，用于记录操作日志。
//   - conf：应用配置信息。
//   - data：数据层公共依赖。
//
// 返回：
//   - GreeterRepo 接口实现。
func NewGreeterRepo(logger kitlog.Logger, conf *appconf.Config, data Data) appbiz.GreeterRepo {
	return &greeterRepo{
		log:  logger,
		conf: conf,
		data: data,
	}
}

// Save 保存一个 Greeter 实体，返回保存后的实体和可能的错误。
//
// 参数：
//   - ctx：上下文信息（当前未使用）。
//   - g：需要保存的 Greeter 实体。
//
// 返回：
//   - 保存后的 Greeter 实体。
//   - 可能发生的错误。
func (r *greeterRepo) Save(_ context.Context, g *appbiz.Greeter) (*appbiz.Greeter, error) {
	return g, nil
}

// Update 更新一个 Greeter 实体，返回更新后的实体和可能的错误。
//
// 参数：
//   - ctx：上下文信息（当前未使用）。
//   - g：需要更新的 Greeter 实体。
//
// 返回：
//   - 更新后的 Greeter 实体。
//   - 可能发生的错误。
func (r *greeterRepo) Update(_ context.Context, g *appbiz.Greeter) (*appbiz.Greeter, error) {
	return g, nil
}

// FindByID 根据 ID 查找 Greeter 实体，返回查找到的实体和可能的错误。
//
// 参数：
//   - ctx：上下文信息。
//   - id：Greeter 实体的唯一标识。
//
// 返回：
//   - 查找到的 Greeter 实体。
//   - 可能发生的错误。
func (r *greeterRepo) FindByID(context.Context, int64) (*appbiz.Greeter, error) {
	return nil, nil
}

// ListByHello 根据 hello 字段查找 Greeter 实体列表，返回查找到的实体列表和可能的错误。
//
// 参数：
//   - ctx：上下文信息。
//   - hello：查询条件。
//
// 返回：
//   - Greeter 实体列表。
//   - 可能发生的错误。
func (r *greeterRepo) ListByHello(context.Context, string) ([]*appbiz.Greeter, error) {
	return nil, nil
}

// ListAll 获取所有 Greeter 实体列表，返回实体列表和可能的错误。
//
// 参数：
//   - ctx：上下文信息。
//
// 返回：
//   - 所有 Greeter 实体列表。
//   - 可能发生的错误。
func (r *greeterRepo) ListAll(context.Context) ([]*appbiz.Greeter, error) {
	return nil, nil
}
