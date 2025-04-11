// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package service

import (
	"context"

	kitlog "github.com/fsyyft-go/kit/log"

	appuser "github.com/fsyyft-go/intro-to-passkey/api/user/v1"
	appconf "github.com/fsyyft-go/intro-to-passkey/internal/conf"
)

type (
	// userService 实现了 UserHTTPServer 接口，提供用户服务。
	userService struct {
		// logger 用于服务日志记录。
		logger kitlog.Logger
		// conf 存储服务配置信息。
		conf *appconf.Config
	}
)

// NewUserService 创建一个新的 UserHTTPServer 服务实例。
//
// 参数：
//   - logger：日志记录器，用于服务日志记录。
//   - conf：服务配置信息。
//
// 返回：
//   - app_user_v1.UserHTTPServer：用户服务的实现实例。
func NewUserService(logger kitlog.Logger, conf *appconf.Config) appuser.UserHTTPServer {
	return &userService{
		logger: logger,
		conf:   conf,
	}
}

// Register 实现用户注册功能。
func (s *userService) Register(ctx context.Context, in *appuser.RegisterRequest) (*appuser.RegisterResponse, error) {
	return nil, nil
}

// Login 实现用户登录功能。
func (s *userService) Login(ctx context.Context, in *appuser.LoginRequest) (*appuser.LoginResponse, error) {
	return nil, nil
}

// ChangePassword 实现用户密码修改功能。
func (s *userService) ChangePassword(ctx context.Context, in *appuser.ChangePasswordRequest) (*appuser.ChangePasswordResponse, error) {
	return nil, nil
}

// Logout 实现用户登出功能。
func (s *userService) Logout(ctx context.Context, in *appuser.LogoutRequest) (*appuser.LogoutResponse, error) {
	return nil, nil
}
