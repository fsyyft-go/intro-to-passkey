// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package conf 提供配置文件的加载和解析功能。
// 支持从 YAML 文件中读取配置，并转换为对应的结构体。
package conf

import (
	"fmt"
	"path/filepath"

	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"

	kit_kratos_config "github.com/fsyyft-go/kit/kratos/config"
)

var (
	// ErrInvalidPath 表示提供的路径无效，可能包含非法字符或存在路径穿越尝试。
	ErrInvalidPath = fmt.Errorf("无效的路径：路径包含非法字符或存在路径穿越尝试")
)

// LoadConfig 从指定路径加载配置文件并解析为 Config 结构体。
//
// 参数：
//   - path string：配置文件的路径。
//
// 返回值：
//   - *Config：解析后的配置对象指针。
//   - error：加载或解析过程中可能发生的错误。
func LoadConfig(path string) (*Config, error) {
	// 检查并规范化配置文件路径。
	cleanPath, err := checkPath(path)
	if nil != err {
		return nil, err
	}

	// 创建配置管理器实例。
	c := config.New(
		// 设置配置源为文件源，指定配置文件路径。
		config.WithSource(
			file.NewSource(cleanPath),
		),
		// 设置自定义解码器，支持特殊格式处理（如 base64 解码）。
		config.WithDecoder(kit_kratos_config.NewDecoder().Decode),
	)

	// 加载配置，如果出错则返回错误。
	if err := c.Load(); nil != err {
		return nil, err
	}

	// 将配置数据解析到 Config 结构体中。
	var cfg Config
	if err := c.Scan(&cfg); nil != err {
		return nil, err
	}

	return &cfg, nil
}

// checkPath 检查并规范化配置文件路径。
//
// 参数：
//   - path string：需要检查的文件路径。
//
// 返回值：
//   - string：规范化后的绝对路径。
//   - error：路径处理过程中可能发生的错误。
func checkPath(path string) (string, error) {
	// 如果路径不是绝对路径，则转换为绝对路径。
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if nil != err {
			return "", err
		}
		path = absPath
	}

	// 规范化路径，移除冗余的分隔符和相对路径引用。
	cleanPath := filepath.Clean(path)
	// 检查清理后的路径是否与原路径一致，防止路径穿越攻击。
	if cleanPath != path {
		return "", ErrInvalidPath
	}

	return cleanPath, nil
}
