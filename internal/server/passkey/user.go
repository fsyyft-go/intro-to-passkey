// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	_ webauthn.User = (*User)(nil)
)

// User 实现了 webauthn.User 接口，用于存储用户信息和凭证。
// 该结构体包含了 WebAuthn 认证所需的所有用户相关数据。
type (
	User struct {
		ID          []byte                `json:"id"`          // 用户唯一标识符。
		Name        string                `json:"name"`        // 用户名。
		DisplayName string                `json:"displayName"` // 用户显示名称。
		Credentials []webauthn.Credential `json:"credentials"` // 用户凭证列表。
	}
)

// WebAuthnID 实现 webauthn.User 接口，返回用户的唯一标识符。
// 返回值：用户 ID 的字节数组表示。
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName 实现 webauthn.User 接口，返回用户名。
// 返回值：用户名字符串。
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName 实现 webauthn.User 接口，返回用户显示名称。
// 返回值：用户显示名称字符串。
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials 实现 webauthn.User 接口，返回用户凭证列表。
// 返回值：用户凭证数组。
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon 实现 webauthn.User 接口，返回用户图标 URL。
// 返回值：空字符串，表示不使用用户图标。
func (u *User) WebAuthnIcon() string {
	return ""
}

// AddCredential 添加一个新的凭证到用户的凭证列表中。
// 参数：
//   - cred：要添加的凭证。
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// NewUser 创建一个新的 User 实例。
// 参数：
//   - id：用户唯一标识符。
//   - name：用户名。
//   - displayName：用户显示名称。
//
// 返回值：
//   - *User：新创建的 User 实例。
func NewUser(id []byte, name, displayName string) webauthn.User {
	return &User{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		Credentials: make([]webauthn.Credential, 0),
	}
}
