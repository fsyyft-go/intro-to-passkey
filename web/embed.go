// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package web

import (
	"embed"
)

// 注意：Go embed 指令必须使用绝对路径（相对于包含 go.mod 的项目根目录）。
// 这就是为什么我们把这个文件放在 web 目录下，而不是其他地方。
// 如果我们把这个文件放在其他目录，比如 internal/server 中，那么 embed 路径会变得很复杂，
// 并且可能需要使用 ../.. 这样的路径，这在 Go embed 中是不支持的。

//go:embed static/index.html
var StaticFiles embed.FS
