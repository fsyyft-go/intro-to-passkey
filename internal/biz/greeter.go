// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package biz

import (
	"context"

	"github.com/go-kratos/kratos/v2/errors"

	kitlog "github.com/fsyyft-go/kit/log"

	apphelloworldv1 "github.com/fsyyft-go/intro-to-passkey/api/helloworld/v1"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

// 定义系统错误码。
var (
	// ErrUserNotFound 表示用户未找到的错误，使用 NotFound 错误类型，错误原因为 USER_NOT_FOUND。
	ErrUserNotFound = errors.NotFound(apphelloworldv1.ErrorReason_USER_NOT_FOUND.String(), "user not found")
)

// 定义 Greeter 相关的类型。
type (
	// GreeterRepo 定义了 Greeter 仓储接口。
	// 该接口提供了对 Greeter 实体的基础操作方法，包括保存、更新、查询等功能。
	GreeterRepo interface {
		// Save 保存一个 Greeter 实体，返回保存后的实体和可能的错误。
		Save(context.Context, *Greeter) (*Greeter, error)
		// Update 更新一个 Greeter 实体，返回更新后的实体和可能的错误。
		Update(context.Context, *Greeter) (*Greeter, error)
		// FindByID 根据 ID 查找 Greeter 实体，返回查找到的实体和可能的错误。
		FindByID(context.Context, int64) (*Greeter, error)
		// ListByHello 根据 hello 字段查找 Greeter 实体列表，返回查找到的实体列表和可能的错误。
		ListByHello(context.Context, string) ([]*Greeter, error)
		// ListAll 获取所有 Greeter 实体列表，返回实体列表和可能的错误。
		ListAll(context.Context) ([]*Greeter, error)
	}

	// Greeter 定义了问候实体结构。
	Greeter struct {
		// Hello 表示问候语内容。
		Hello string
	}

	// GreeterUsecase 定义了 Greeter 用例接口。
	// 该接口提供了 Greeter 相关的业务操作方法。
	GreeterUsecase interface {
		// CreateGreeter 创建一个新的 Greeter 实体，返回创建后的实体和可能的错误。
		CreateGreeter(context.Context, *Greeter) (*Greeter, error)
	}

	// greeterUsecase 实现了 GreeterUsecase 接口。
	greeterUsecase struct {
		// logger 用于日志记录。
		logger kitlog.Logger
		// conf 存储应用配置信息。
		conf *appconf.Config
		// repo 提供数据访问能力。
		repo GreeterRepo
	}
)

// NewGreeterUsecase 创建一个新的 Greeter 用例实例。
// 参数：
//   - logger：日志记录器
//   - conf：应用配置
//   - repo：Greeter 仓储接口实现
//
// 返回：
//   - GreeterUsecase 接口实现
func NewGreeterUsecase(logger kitlog.Logger, conf *appconf.Config, repo GreeterRepo) GreeterUsecase {
	return &greeterUsecase{
		logger: logger,
		conf:   conf,
		repo:   repo,
	}
}

// CreateGreeter 实现了创建 Greeter 实体的业务逻辑。
// 参数：
//   - ctx：上下文信息
//   - g：待创建的 Greeter 实体
//
// 返回：
//   - 创建成功的 Greeter 实体
//   - 可能的错误信息
func (u *greeterUsecase) CreateGreeter(ctx context.Context, g *Greeter) (*Greeter, error) {
	// 记录调试日志。
	u.logger.Debug("CreateGreeter: %v", g.Hello)

	// 调用仓储层保存实体。
	return u.repo.Save(ctx, g)
}
