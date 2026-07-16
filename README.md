# WeChat-Hook 4.1.10.27

适用于微信 PC `4.1.10.27` 的 Hook 项目，提供联系人查询、实时文本消息接收、文本发送、自动回复和运行状态诊断等 HTTP 接口。

微信 4.1.10.27 下载地址：<https://pan.xunlei.com/s/VOxe0zLuEvSwlE86aYZcNCmSA1?pwd=vkkf>

> 偏移仅适用于微信 `4.1.10.27`。升级微信前必须重新验证偏移并完成真实进程回归测试。

## 已验证能力

- `/GetContacts`：返回联系人全量快照，包含昵称、别名、头像、拼音等 Contact 表字段。
- `/GetContact`：按 wxid 查询单个联系人；不存在时安全返回 `404`。
- `/GetSelfProfile`：返回当前账号的 wxid、别名、昵称和手机号。
- 实时普通文本接收：提取发送者 wxid、接收者 wxid 和正文。
- `/SendTextMsg`：完成登录保护、发送请求入队和异步发送。
- 好友和群聊自动回复：均已完成真实消息端到端验证。
- `/QueryDB/status`：返回登录状态、消息观察、联系人和自动回复诊断计数。
- `/QueryDB/GetAllDBName`：返回 SQLite Hook 捕获的联系人数据库，不扫描进程内存。

联系人全量接口已在真实微信进程中验证：返回 `count = 66`、`complete = true`，66 条记录均包含 `nick_name` 和 `big_head_url`；微信主进程保持响应，未出现崩溃或异常内存增长。

## 编译与启动

编译以下项目：

- `x64_Version_dll.vcxproj`
- `launcher/WeChatHookLauncher.vcxproj`

然后启动微信并注入 DLL：

```powershell
.\launcher\bin\WeChatHookLauncher.exe --start
```

启动器会加载 `version.dll`，HTTP 服务默认监听 `127.0.0.1:30001`。

## HTTP 接口

```http
GET  http://127.0.0.1:30001/
GET  http://127.0.0.1:30001/QueryDB/status
GET  http://127.0.0.1:30001/GetContacts
POST http://127.0.0.1:30001/GetContacts
POST http://127.0.0.1:30001/GetContact
POST http://127.0.0.1:30001/GetSelfProfile
POST http://127.0.0.1:30001/SendTextMsg
POST http://127.0.0.1:30001/AutoReply/config
POST http://127.0.0.1:30001/QueryDB/GetAllDBName
POST http://127.0.0.1:30001/QueryDB/execute
POST http://127.0.0.1:30001/SendImgMsg
POST http://127.0.0.1:30001/ForwardXMLMsg
POST http://127.0.0.1:30001/Decode_Pic
```

### 获取全部联系人

`/GetContacts` 支持 GET 和 POST。POST 可传入分页参数；默认 `offset = 0`、`limit = 4096`，单次 `limit` 最大为 4096。

```powershell
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/GetContacts' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"offset":0,"limit":100}'
```

响应示例：

```json
{
  "status": 0,
  "contacts": [
    {
      "username": "wxid_example",
      "nick_name": "示例昵称",
      "alias": "example",
      "big_head_url": "https://wx.qlogo.cn/...",
      "small_head_url": "https://wx.qlogo.cn/...",
      "quan_pin": "shilinicheng"
    }
  ],
  "offset": 0,
  "limit": 100,
  "count": 66,
  "complete": true,
  "source": "wechat-contact-response-cache"
}
```

实现要点：

- 首次请求会把 `SELECT * FROM Contact` 只读查询排队到微信自己的 SQLite 工作线程。
- HTTP 线程不会直接调用微信内部 SQLite 句柄。
- 查询结果会合并进有界联系人缓存，退出登录时清空，切换账号后重新回填。
- SQLite 线程未及时认领查询时，首次响应可能为 `complete: false`；后续请求会自动重试。
- `count` 包含好友、群聊、公众号/服务号和陌生人等 Contact 全表条目，不等同于纯好友数量。

部分大小写不敏感的 JSON 解析器可能把数据库原字段 `UserName` 和快照补充字段 `username` 视为重复键。这是解析器限制，建议使用大小写敏感的 JSON 解析器。

详细实现和真机验证记录见 [GET_CONTACTS_NOTES.md](GET_CONTACTS_NOTES.md)。

### 获取单个联系人

```powershell
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/GetContact' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"wxid":"wxid_example"}'
```

该接口已验证可返回 `username`、`nick_name`、`alias`、`big_head_url`、`small_head_url`、`quan_pin` 等完整行数据。不存在的 wxid 返回 HTTP `404`，不会崩溃。

### 自动回复

`/AutoReply/config` 已验证参数校验和启停逻辑。群聊自动回复默认关闭，可显式开启：

```powershell
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/AutoReply/config' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"enabled":true,"group_enabled":true}'
```

接收 Hook 只负责解析消息并入队；自动回复由独立工作线程调用发送接口，避免在消息 Hook 内重入微信发送逻辑。

真实验证结果：

- 好友消息：`AutoReplyCandidates=1`、`AutoReplyFriendCandidates=1`、`AutoReplyQueued=1`、`AutoReplySent=1`、`AutoReplyFailed=0`。
- 群聊消息：`AutoReplyGroupCandidates=1`、`AutoReplyQueued=1`、`AutoReplySent=1`、`AutoReplyFailed=0`。

`/SendTextMsg` 返回本地入队结果，不等同于微信服务端送达回执。

### 数据库接口

微信 4.1.10.27 的联系人数据库路径为 `db_storage\contact\contact.db`。Hook 同时兼容旧逻辑名 `MicroMsg.db`，并明确排除 `contact_fts.db`。

- `/QueryDB/GetAllDBName` 已验证可返回捕获到的 `contact.db` 路径和句柄。
- `/QueryDB/execute` 仅允许单条只读 SQL，并交由微信 SQLite 工作线程执行。
- SQLite 仅用于联系人和历史消息查询，不作为实时消息接收入口。

## 自动化回归测试

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1 -RequireLogin
```

完整流程和状态字段说明见 [docs/STATUS_AND_TESTING.md](docs/STATUS_AND_TESTING.md)。

## 当前限制

- `/SendImgMsg`、`/ForwardXMLMsg`、`/Decode_Pic`：4.1.10.27 的相关偏移尚未重新验证，目前会安全拒绝执行。
- `/GetSelfProfile` 的 `area`、`signinfo`、`avatar`、`small_avatar`、`sex` 等可选字段仍可能为空，不会使用猜测偏移填充。
- `/SendTextMsg` 已验证本地发送入队和自动回复链路，尚未单独实现微信服务端送达回执。
- 多账号切换、退出后重新登录仍建议在发布前执行完整真实账号回归。

## 版本适配笔记

- [联系人全量获取](GET_CONTACTS_NOTES.md)
- [登录状态](docs/LOGIN_STATUS_NOTES_4.1.10.27.md)
- [个人资料](docs/SELF_PROFILE_NOTES_4.1.10.27.md)
- [接收消息](docs/RECEIVE_MESSAGE_NOTES_4.1.10.27.md)
- [发送消息](docs/SEND_MESSAGE_NOTES_4.1.10.27.md)

## 安全约束

- 仅对已在 IDA 和真实运行时验证过的偏移安装 Hook。
- Hook 必须透传原函数返回值。
- 不在 HTTP 线程直接操作微信内部 SQLite 连接。
- 不在消息接收 Hook 内重入发送函数。
- 修改后需重新编译 DLL，并在微信重启、重新登录和真实消息测试后复核接口与计数器。
