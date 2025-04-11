// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package service

import (
	"context"
	"fmt"

	kitlog "github.com/fsyyft-go/kit/log"

	apphelloworldv1 "github.com/fsyyft-go/intro-to-passkey/api/helloworld/v1"
	appbiz "github.com/fsyyft-go/intro-to-passkey/internal/biz"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

type (
	// greeterService 实现了 GreeterHTTPServer 接口，提供问候服务。
	greeterService struct {
		// logger 用于服务日志记录。
		logger kitlog.Logger
		// conf 存储服务配置信息。
		conf *appconf.Config
		// uc 用于处理问候相关的业务逻辑。
		uc appbiz.GreeterUsecase
	}
)

// NewGreeterService 创建一个新的 GreeterHTTPServer 服务实例。
//
// 参数：
//   - logger：日志记录器，用于服务日志记录。
//   - conf：服务配置信息。
//   - uc：问候用例的业务逻辑实现。
//
// 返回：
//   - app_helloworld_v1.GreeterHTTPServer：问候服务的实现实例。
func NewGreeterService(logger kitlog.Logger, conf *appconf.Config, uc appbiz.GreeterUsecase) apphelloworldv1.GreeterHTTPServer {
	return &greeterService{
		logger: logger,
		conf:   conf,
		uc:     uc,
	}
}

// SayHello 发送问候消息。
//
// 参数：
//   - ctx：上下文信息。
//   - in：包含问候请求的参数。
//
// 返回：
//   - *app_helloworld_v1.HelloReply：问候响应。
//   - error：可能发生的错误。
func (s *greeterService) SayHello(ctx context.Context, in *apphelloworldv1.HelloRequest) (*apphelloworldv1.HelloReply, error) {
	g, err := s.uc.CreateGreeter(ctx, &appbiz.Greeter{
		Hello: in.Name,
	})
	if nil != err {
		return nil, err
	}
	return &apphelloworldv1.HelloReply{
		Message: fmt.Sprintf("Hello %s", g.Hello),
	}, nil
}
