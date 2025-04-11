// Copyright 2025 fsyyft-go
//
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Package passkey 实现了 WebAuthn（Web Authentication）的核心功能。
// 本包提供了基于 FIDO2 标准的无密码认证解决方案。
package passkey

/*
WebAuthn 配置详解：

RPID（Relying Party ID）：
- 定义了信赖方的标识符，通常是网站的域名
- 必须是当前网站的有效域名或其顶级域名
- 在开发环境可以使用 localhost
- 生产环境必须使用实际的域名
- 注意：必须是所有 RPOrigins 的有效后缀
- 技术规范：
  * 不能包含端口号
  * 不能包含协议前缀（如 http:// 或 https://）
  * 不能包含路径
  * 不能使用 IP 地址（包括 127.0.0.1）
- 示例：
  * 开发环境：localhost
  * 生产环境：example.com

RPDisplayName：
- 在用户进行认证操作时显示给用户看的应用名称
- 应该使用清晰、友好的名称，提升用户体验
- 建议使用公司或产品的正式名称
- 注意：这个名称会显示在用户的认证设备上
- 技术要求：
  * 长度建议不超过 64 个字符
  * 支持 Unicode 字符
  * 避免使用特殊字符和 Emoji
- 示例：
  * "My Company Login"
  * "Secure Banking Portal"
  * "企业管理系统"

RPOrigins：
- 定义了允许使用该 WebAuthn 认证的源地址列表
- 必须包含完整的 URL（包括协议、域名和端口）
- 开发环境可以使用 http，生产环境必须使用 https
- 支持多域名场景，所有域名必须共享同一个 RPID 后缀
- 技术要求：
  * 每个 Origin 必须是完整的 URL
  * 必须包含协议（http/https）
  * 可以包含端口号
  * 不能包含路径部分
  * 必须与实际服务的域名完全匹配
- 示例：
  * 开发环境：["http://localhost:8080"]
  * 生产环境：["https://app.example.com", "https://auth.example.com"]

RPTopOrigins：
- 定义了允许的顶级源地址列表
- 用于 WebAuthn Level 3 规范中的顶级源验证
- 与 RPTopOriginVerificationMode 配合使用
- 技术要求：
  * 格式要求与 RPOrigins 相同
  * 在使用 TopOriginImplicitVerificationMode 时必须配置
- 示例：
  * ["https://top.example.com"]

RPTopOriginVerificationMode：
- 配置顶级源验证模式
- 用于控制如何验证顶级源
- 可选值：
  * TopOriginDefaultVerificationMode：默认模式，当前等同于 Ignore 模式
  * TopOriginIgnoreVerificationMode：忽略顶级源验证
  * TopOriginImplicitVerificationMode：隐式验证模式，需要配置 RPTopOrigins

AttestationPreference：
- 设置证明（attestation）首选项
- 控制如何处理认证器的证明信息
- 可选值：
  * none：不需要证明信息
  * indirect：允许间接证明
  * direct：要求直接证明
- 建议：
  * 一般场景使用 none 即可
  * 高安全性要求场景可使用 direct

AuthenticatorSelection：
- 配置认证器选择条件
- 控制哪些类型的认证器可以注册
- 主要参数：
  * authenticatorAttachment：认证器连接方式（platform/cross-platform）
  * requireResidentKey：是否要求驻留密钥
  * userVerification：用户验证要求（required/preferred/discouraged）
- 示例：
  * 仅允许平台认证器：
    authenticatorAttachment: platform
  * 要求生物识别：
    userVerification: required

Debug：
- 启用调试选项
- 开发环境建议：true
- 生产环境建议：false
- 启用后会输出更多日志信息

EncodeUserIDAsString：
- 控制用户 ID 的编码方式
- 当设置为 true 时：
  * user.id 在注册时会被编码为原始 UTF8 字符串
  * 适用于仅使用可打印 ASCII 字符的场景
- 当设置为 false 时：
  * 使用默认的字节编码
- 建议：除非特殊需求，保持默认值 false

Timeouts：
- 配置各种操作的超时时间
- 包含两个主要配置：
  * Login：登录相关超时设置
  * Registration：注册相关超时设置
- 每个配置包含：
  * Enforce：是否在服务端强制执行超时
  * Timeout：标准超时时间
  * TimeoutUVD：用户验证被设置为 discouraged 时的超时时间
- 建议值：
  * Timeout：30-60 秒
  * TimeoutUVD：120 秒

MDS（Metadata Service）：
- 配置元数据服务提供者
- 用于验证认证器的元数据
- 可以配置为：
  * nil：不使用元数据验证
  * FIDO MDS：使用 FIDO 联盟的元数据服务
  * 自定义实现：实现 metadata.Provider 接口

安全建议：
1. 生产环境配置：
   - 必须使用 HTTPS
   - 使用实际域名替换 localhost
   - 确保所有域名都有有效的 SSL 证书
   - 定期更新 SSL 证书
   - 使用强制 HTTPS 跳转

2. 多域名处理：
   - RPID 设置为所有域名的共同后缀
   - 在 RPOrigins 中列出所有允许的域名
   - 确保所有域名都属于同一组织
   - 实施严格的 CSP 策略
   - 配置正确的 CORS 策略

3. 配置管理：
   - 使用环境变量或配置文件管理这些值
   - 不同环境（开发、测试、生产）使用不同配置
   - 定期检查和更新证书
   - 使用配置版本控制
   - 实施配置更改审计

4. 错误处理：
   - 添加域名验证逻辑
   - 实现优雅的错误提示
   - 记录详细的错误日志
   - 实现自动化配置测试
   - 监控证书过期时间

5. 安全性增强：
   - 启用证书透明度监控
   - 配置 HSTS 策略
   - 实施双因素认证
   - 定期进行安全审计
   - 监控异常访问模式

6. 超时处理：
   - 根据业务需求调整超时时间
   - 考虑网络延迟因素
   - 实现超时重试机制
   - 提供清晰的用户反馈
   - 记录超时事件日志

7. 认证器选择：
   - 根据安全需求选择合适的认证器类型
   - 考虑用户设备兼容性
   - 提供降级认证方案
   - 实现认证器健康检查
   - 监控认证失败率

PublicKeyCredentialCreationOptions 结构体详解：

RelyingParty（信赖方实体）：
- 类型：RelyingPartyEntity
- 描述：代表网站/应用的身份信息
- 子字段：
  * ID：信赖方的标识符（必填）
  * Name：显示名称（必填）
  * Icon：图标 URL（可选）
- 建议值：
  * ID：使用域名，如 "example.com"
  * Name：使用公司/产品名称，如 "示例公司"
- 注意事项：
  * ID 必须是有效的域名
  * 不要在 ID 中包含协议、端口或路径
  * Name 应该简洁明了

User（用户实体）：
- 类型：UserEntity
- 描述：代表要注册的用户信息
- 子字段：
  * ID：用户的唯一标识符（必填）
  * Name：用户名（必填）
  * DisplayName：显示名称（必填）
  * Icon：用户头像 URL（可选）
- 建议值：
  * ID：使用随机生成的 UUID 或数据库 ID
  * Name：用户的登录名或邮箱
  * DisplayName：用户的真实姓名或昵称
- 注意事项：
  * ID 在系统中必须唯一
  * ID 建议使用不可预测的值
  * 注意个人信息保护

Challenge（挑战）：
- 类型：URLEncodedBase64
- 描述：服务器生成的随机挑战值
- 建议值：
  * 至少 16 字节的随机数
  * 使用加密安全的随机数生成器
- 注意事项：
  * 每次注册必须使用新的挑战值
  * 不要重复使用挑战值
  * 注意存储和验证机制

Parameters（参数列表）：
- 类型：[]CredentialParameter
- 描述：支持的加密算法列表
- 子字段：
  * Type：凭证类型（通常是 "public-key"）
  * Algorithm：支持的算法标识符
- 建议值：
  * 优先使用 ES256（-7）
  * 其次是 RS256（-257）
  * 可选 EdDSA（-8）
- 注意事项：
  * 按优先级排序
  * 考虑设备兼容性
  * 至少提供一个算法

Timeout（超时时间）：
- 类型：int
- 描述：操作超时时间（毫秒）
- 建议值：
  * 标准验证：30000-60000（30-60秒）
  * 生物识别：120000（120秒）
- 注意事项：
  * 考虑用户操作时间
  * 考虑网络延迟
  * 不要设置过短

CredentialExcludeList（排除凭证列表）：
- 类型：[]CredentialDescriptor
- 描述：不允许注册的凭证列表
- 子字段：
  * Type：凭证类型
  * ID：凭证标识符
  * Transports：传输方式
- 建议值：
  * 用户已注册的凭证列表
- 注意事项：
  * 防止重复注册
  * 定期清理无效凭证

AuthenticatorSelection（认证器选择）：
- 类型：AuthenticatorSelection
- 描述：认证器的选择条件
- 子字段：
  * AuthenticatorAttachment：认证器附加类型
  * RequireResidentKey：是否要求驻留密钥
  * ResidentKey：驻留密钥要求
  * UserVerification：用户验证要求
- 建议值：
  * 平台认证器：{"authenticatorAttachment": "platform"}
  * 跨平台认证器：{"authenticatorAttachment": "cross-platform"}
  * 生物识别：{"userVerification": "required"}
- 注意事项：
  * 根据安全需求选择
  * 考虑用户体验
  * 提供合适的降级方案

Hints（提示）：
- 类型：[]PublicKeyCredentialHints
- 描述：WebAuthn Level 3 的认证器提示
- 可选值：
  * "security-key"：安全密钥
  * "client-device"：客户端设备
  * "hybrid"：混合模式
- 建议值：
  * 根据场景选择合适的提示
- 注意事项：
  * 仅 Level 3 支持
  * 提供清晰的用户指引

Attestation（认证声明）：
- 类型：ConveyancePreference
- 描述：认证声明的首选项
- 可选值：
  * "none"：不需要认证声明
  * "indirect"：间接认证声明
  * "direct"：直接认证声明
  * "enterprise"：企业认证声明
- 建议值：
  * 一般场景：none
  * 高安全性要求：direct
- 注意事项：
  * 考虑隐私影响
  * 权衡安全性和用户体验

AttestationFormats（认证格式）：
- 类型：[]AttestationFormat
- 描述：支持的认证格式列表
- 可选值：
  * "packed"：通用格式
  * "tpm"：TPM 格式
  * "android-key"：Android 密钥格式
  * "android-safetynet"：Android SafetyNet 格式
  * "fido-u2f"：FIDO U2F 格式
  * "apple"：Apple 格式
  * "none"：无格式
- 建议值：
  * 支持多种格式以提高兼容性
- 注意事项：
  * 验证支持的格式
  * 考虑设备兼容性

Extensions（扩展）：
- 类型：AuthenticationExtensions
- 描述：认证扩展数据
- 常用扩展：
  * appid：用于 FIDO U2F 兼容
  * credProps：凭证属性
  * largeBlob：大型 Blob 存储
- 建议值：
  * 根据需求选择合适的扩展
- 注意事项：
  * 确保客户端支持
  * 注意兼容性问题
  * 不要过度使用扩展

标准默认配置参考：
1. 基础安全级别（适用于普通网站）：
```json
{
  "rp": {
    "name": "示例网站",
    "id": "example.com"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },  // ES256
    { "type": "public-key", "alg": -257 } // RS256
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "preferred",
    "residentKey": "preferred"
  },
  "timeout": 60000,
  "attestation": "none"
}
```

2. 高安全级别（适用于金融、企业应用）：
```json
{
  "rp": {
    "name": "安全应用",
    "id": "secure.example.com"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -8 },   // EdDSA
    { "type": "public-key", "alg": -7 },   // ES256
    { "type": "public-key", "alg": -257 }  // RS256
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "cross-platform",
    "userVerification": "required",
    "residentKey": "required"
  },
  "timeout": 120000,
  "attestation": "direct"
}
```

主流网站配置参考：

1. Google 配置示例：
```json
{
  "rp": {
    "name": "Google",
    "id": "google.com"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "userVerification": "preferred"
  },
  "attestation": "none",
  "extensions": {
    "credProps": true,
    "googleCredentialType": true
  }
}
```

2. GitHub 配置示例：
```json
{
  "rp": {
    "name": "GitHub",
    "id": "github.com"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "cross-platform",
    "residentKey": "discouraged",
    "userVerification": "preferred"
  },
  "attestation": "none",
  "extensions": {
    "credProps": true
  }
}
```

3. Microsoft 配置示例：
```json
{
  "rp": {
    "name": "Microsoft Account",
    "id": "microsoft.com"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "required",
    "userVerification": "required"
  },
  "attestation": "none",
  "extensions": {
    "credProps": true,
    "hmacCreateSecret": true
  }
}
```

配置特点分析：
1. 算法选择：
   - 主流网站普遍支持 ES256(-7) 和 RS256(-257)
   - 新系统开始采用 EdDSA(-8)
   - 按兼容性顺序排列算法

2. 认证器选择：
   - Google/Microsoft 偏好平台认证器（platform）
   - GitHub 偏好跨平台认证器（cross-platform）
   - 用户验证（userVerification）多采用 "preferred"

3. 安全策略：
   - 主流网站普遍使用 "none" 认证声明
   - 驻留密钥（residentKey）策略不同
   - 超时时间通常在 60000ms 左右

4. 扩展使用：
   - credProps 是最常用的扩展
   - 各平台可能有特定扩展
   - 扩展使用遵循最小必要原则
*/
