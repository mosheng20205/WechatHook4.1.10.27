# 微信登录信息/个人资料逆向与实现笔记（4.1.10.27）

> 适用目标：微信 `4.1.10.27` 的 `Weixin.dll`。本文记录当前项目获取当前登录账号资料的对象来源、字段布局、HTTP 行为和版本迁移方法。

## 1. 对外接口

```http
POST http://127.0.0.1:30001/GetSelfProfile
```

不需要请求体。接口返回 JSON，并设置 `application/json; charset=utf-8`。

当前运行时已经验证可以返回：

- `wxid`
- `alias`
- `nickname`
- `phone`
- `profile_account_id`
- `profile_nickname`
- `profile_phone`
- `profile_object`
- `profile_read_ok`

可选字段 `area`、`signinfo`、`avatar`、`small_avatar`、`sex` 在当前实现中保留，但没有使用未经验证的内存偏移填充，可能为空。

## 2. 个人资料对象来源

当前对象捕获链路为：

```text
Weixin.dll + 0x410C0（管理器 Getter）
  -> 管理器 vtable + 0x60（Profile Getter）
  -> Hook_ProfileGetter(manager, out_object)
  -> g_ProfileObject
```

辅助观察点：

- 字段读取函数：`Weixin.dll + 0x1B0270`。
- 两个资料容器观察点：`Weixin.dll + 0x212F830`、`Weixin.dll + 0x212FC00`。
- 这些观察 Hook 只记录对象、描述符和返回值，不能把观察到的描述符地址直接当作字段编号。

`Hook_ProfileGetter` 必须先调用原函数，再从 `out_object` 取得对象地址。登录状态变为未登录时，`SetMirroredLoginState()` 会清空 `g_ProfileObject`，避免继续访问已释放对象。

## 3. 已验证的字段布局

在微信 `4.1.10.27` 中，`g_ProfileObject` 的资料子结构位于：

```text
fields = ProfileObject + 0x40
```

当前已通过真实接口返回结果验证的内嵌字符串位置：

| 子结构偏移 | 当前含义 | 返回字段 |
| ---: | --- | --- |
| `fields + 0x28` | 当前账号标识候选 | `wxid`、`profile_account_id` |
| `fields + 0x48` | 昵称 | `nickname`、`profile_nickname` |
| `fields + 0x68` | 手机号 | `phone`、`profile_phone` |

读取器使用安全拷贝和长度限制：最多读取固定小缓冲区，遇到访问异常、空字符串或未终止字符串时返回失败。`profile_read_ok` 只有这些运行时字段至少一个成功读取时才为 `true`。

当前代码将运行时账号标识同时作为 `SelfInfo.wxid` 和 `SelfInfo.alias` 的候选值；这不是说两个业务字段在内存中必然相同。若新版本能从已验证对象中读取真正 alias，应单独替换 alias 填充逻辑。

## 4. 未登录行为和缓存规则

当 `g_IsLogin == 0` 时，`/GetSelfProfile` 返回空资料：

- `profile_read_ok = false`
- `profile_object = 0`
- `wxid`、`alias`、`nickname`、`phone` 等字符串为空

接口不会返回上一账号的 `SelfInfo` 缓存，避免退出登录或切换账号后泄露旧资料。资料对象指针也不会在注销后继续使用。

## 5. 运行时验证方法

登录后执行：

```powershell
$profile = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:30001/GetSelfProfile
$profile | ConvertTo-Json -Depth 5
```

必须同时检查：

1. `/QueryDB/status` 的 `IsLogin = 1`。
2. `profile_read_ok = true`。
3. `wxid`、`nickname`、`phone` 与微信当前账号界面一致。
4. `profile_object` 非零且来自本次登录会话。

退出登录后再次调用，必须看到 `profile_read_ok = false` 和空资料；重启微信并登录另一个账号时，资料必须替换而不是沿用上一账号。

## 6. 新版本迁移规则

1. 先在 IDA 中重新定位管理器 Getter、Profile Getter 和字段读取函数。
2. 在已登录状态下只做对象地址和调用计数观察，不要直接读取未知偏移。
3. 通过两个账号或账号切换验证 `ProfileObject` 是否随会话变化。
4. 逐个验证账号标识、昵称、手机号的字符串布局、编码和长度。
5. 只有字段在运行时与界面/接口结果一致后，才能更新 `fields + 0x28/+0x48/+0x68`。
6. 任何地区、签名、头像、性别等扩展字段都必须单独验证，不能从联系人表或旧版本结构推断为当前账号资料。

## 7. 与 SQLite 的边界

当前 `/GetSelfProfile` 的核心四个字段来自微信内存中的登录资料对象。SQLite 只适合联系人和历史记录查询，不应在 HTTP 线程直接访问微信内部连接，也不能用 SQLite 查询结果替代登录资料对象的安全验证。
