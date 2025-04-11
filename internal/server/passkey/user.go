// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package passkey 的 user.go 文件实现了 WebAuthn 用户管理功能。
// 提供了用户信息存储、凭证管理等核心功能。
package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	// 确保 User 结构体实现了 webauthn.User 接口。
	_ webauthn.User = (*User)(nil)
)

// User 实现了 webauthn.User 接口，提供 WebAuthn 认证所需的用户信息管理功能。
// 该结构体负责存储用户的基本信息和认证凭证。
type User struct {
	// ID 是用户的唯一标识符。
	// 在 WebAuthn 流程中用于区分不同用户。
	ID []byte `json:"id"`

	// Name 是用户的登录名。
	// 用于用户登录和显示，应确保在系统内唯一。
	Name string `json:"name"`

	// DisplayName 是用户的显示名称。
	// 在认证界面上展示给用户看的友好名称。
	DisplayName string `json:"displayName"`

	// Credentials 存储用户的认证凭证列表。
	// 每个凭证对应一个已注册的认证器。
	Credentials []webauthn.Credential `json:"credentials"`
}

// WebAuthnID 实现 webauthn.User 接口，返回用户的唯一标识符。
// 该标识符在 WebAuthn 认证流程中用于唯一标识用户。
//
// 返回：
//   - []byte：用户 ID 的字节数组表示
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName 实现 webauthn.User 接口，返回用户的登录名。
// 该名称用于用户登录和系统内部标识。
//
// 返回：
//   - string：用户的登录名
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName 实现 webauthn.User 接口，返回用户的显示名称。
// 该名称用于在认证界面上向用户展示。
//
// 返回：
//   - string：用户的显示名称
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials 实现 webauthn.User 接口，返回用户的认证凭证列表。
// 这些凭证用于验证用户的身份。
//
// 返回：
//   - []webauthn.Credential：用户注册的所有认证凭证
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon 实现 webauthn.User 接口，返回用户的图标 URL。
// 本实现不使用用户图标，始终返回空字符串。
//
// 返回：
//   - string：空字符串，表示不使用用户图标
func (u *User) WebAuthnIcon() string {
	return ""
}

// AddCredential 向用户添加一个新的认证凭证。
// 在用户成功注册新的认证器后调用此方法。
//
// 参数：
//   - cred：要添加的认证凭证
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// NewUser 创建一个新的用户实例。
// 用于在用户首次注册时创建用户记录。
//
// 参数：
//   - id：用户的唯一标识符
//   - name：用户的登录名
//   - displayName：用户的显示名称
//
// 返回：
//   - webauthn.User：实现了 webauthn.User 接口的用户实例
func NewUser(id []byte, name, displayName string) webauthn.User {
	return &User{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: make([]webauthn.Credential, 0),
	}
}
