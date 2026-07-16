# WeChat-Hook 4.1.10.27

适用于微信 PC `4.1.10.27` 的 Hook 项目。

WX4.1.10.27下载：https://pan.xunlei.com/s/VOxe0zLuEvSwlE86aYZcNCmSA1?pwd=vkkf

## 快速启动

编译 `x64_Version_dll.vcxproj` 和 `launcher/WeChatHookLauncher.vcxproj` 后，使用命令行启动：

```powershell
.\launcher\bin\WeChatHookLauncher.exe --start
```

启动器会启动微信、注入 `version.dll`，并开启 30001 端口。

## 接口状态总览

```http
GET  http://127.0.0.1:30001/
GET  http://127.0.0.1:30001/QueryDB/status
POST http://127.0.0.1:30001/GetSelfProfile
POST http://127.0.0.1:30001/GetContact
POST http://127.0.0.1:30001/SendTextMsg
POST http://127.0.0.1:30001/QueryDB/GetAllDBName
POST http://127.0.0.1:30001/QueryDB/execute
POST http://127.0.0.1:30001/SendImgMsg
POST http://127.0.0.1:30001/ForwardXMLMsg
POST http://127.0.0.1:30001/Decode_Pic
POST http://127.0.0.1:30001/AutoReply/config
```

已通过真实微信进程验证：

- `/`：HTTP 服务健康检查。
- `/QueryDB/status`：返回登录状态、状态来源、状态切换次数、消息观察和自动回复计数。
- `/GetSelfProfile`：真实返回 `wxid`、`alias`、`nickname`、`phone`；未登录时返回 `profile_read_ok=false`，不会返回上一会话缓存。
- `/GetContact`：曾在真实微信进程中成功返回联系人 `username`、`nick_name`、`alias`、头像地址等字段；不存在的 wxid 返回 `status=404`，不崩溃。该接口依赖微信自己的 SQLite 线程，微信空闲时可能返回 `-504 timeout`，因此不保证空闲状态下立即成功。
- `/SendTextMsg`：已验证登录保护和发送请求入队；未登录返回 `ret=-2`，入队成功返回 `ret=0`。本次真实跨账号消息测试还确认了同一发送链路的好友自动回复：入队 1 次、发送成功 1 次、失败 0 次。接口返回本地入队结果，不等同于微信服务端送达回执。
- `/QueryDB/GetAllDBName`：真实运行返回由 SQLite Hook 捕获的 `MicroMsg.db` 句柄；不扫描进程内存。
- `/AutoReply/config`：真实验证参数校验及开启/关闭；群聊自动回复默认关闭，使用 `{"group_enabled":true}` 显式开启。
- 普通文本接收：真实收到 `TEST_PROFILE_DB123`，拆分出发送者 `wxid_orly2zssd5e112`、接收者 `wxid_ip31nye3qygp22` 和正文；消息被识别为好友消息并触发自动回复。

本次真实运行的自动回复计数为：`AutoReplyCandidates=1`、`AutoReplyFriendCandidates=1`、`AutoReplyQueued=1`、`AutoReplySent=1`、`AutoReplyFailed=0`。微信主进程及其相关进程均保持响应，未出现崩溃或异常内存增长。

个人资料的 `area`、`signinfo`、`avatar`、`small_avatar`、`sex` 字段目前通过 Contact 表尝试读取，但本次运行仍为空；不会使用猜测偏移填充。联系人查询和历史消息查询可以使用 SQLite，但 SQLite 不作为实时消息接收入口。

详细的版本适配笔记：

- [登录状态笔记](docs/LOGIN_STATUS_NOTES_4.1.10.27.md)
- [个人资料笔记](docs/SELF_PROFILE_NOTES_4.1.10.27.md)
- [接收消息笔记](docs/RECEIVE_MESSAGE_NOTES_4.1.10.27.md)
- [发送消息笔记](docs/SEND_MESSAGE_NOTES_4.1.10.27.md)

## 自动化回归测试

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1 -RequireLogin
```

完整流程和状态字段说明见 [docs/STATUS_AND_TESTING.md](docs/STATUS_AND_TESTING.md)。

## 当前完成情况

已完成并实际验证：

- 命令行自动启动微信并注入 DLL
- HTTP 服务自动启动和端口检查
- 登录完成回调识别登录状态
- `/QueryDB/status` 返回 `IsLogin`、状态来源和状态切换计数
- 未登录时清理资料对象，不返回上一会话缓存
- `/GetSelfProfile` 返回微信号、别名、昵称、手机号
- `/GetContact` 在 SQLite 线程活跃时返回联系人资料，并对不存在的 wxid 安全返回
- `/SendTextMsg` 完成登录检查和发送请求入队；好友自动回复已完成真实跨账号运行验证
- `/QueryDB/GetAllDBName` 返回 SQLite Hook 捕获的 `MicroMsg.db`
- 根路径健康检查 `/`
- 普通文本接收、发送者 wxid/正文拆分和好友消息自动回复
- UTF-8 JSON 响应头
- 未登录和已登录自动化回归测试

尚未完成或仍需专项验证：

- 地区、签名、头像、性别等资料字段：尚未确认稳定的内存结构，当前可能为空
- `LoginProbeCalls`：探针已安装，但该版本实际登录流程未调用当前候选函数，状态目前由登录完成回调确认
- 退出登录后的动态回归：代码已清理状态，但还需要在真实账号上执行一次“登录 → 退出登录 → 重新登录”验证
- 多账号切换和微信重启后的完整回归
- 群聊自动回复和自身消息跳过：代码有分类计数，但尚未用真实群聊消息完成端到端验证
- `/QueryDB/execute`：仅实现单条只读 SQL 的安全队列；空闲时真实查询会超时，尚未完成稳定成功验证
- `/SendImgMsg`：已验证登录保护、文件校验和未验证偏移的安全拒绝；真实图片发送调用已禁用，直到重新定位 4.1.10.27 结构
- `/ForwardXMLMsg`：已验证参数保护和未验证偏移的安全拒绝；真实 XML 发送调用已禁用，直到重新定位 4.1.10.27 结构
- `/Decode_Pic`：已实现源文件和目标路径校验；对于有效文件也会安全返回“偏移未验证”，尚未验证真实加密图片解码
- `/GetContact`：已有真实成功记录，但需要在微信 SQLite 线程活跃时触发；空闲超时问题仍需优化
- `/SendTextMsg`：本地发送入队和自动回复链路已验证，尚未单独验证微信服务端送达回执
- `/AutoReply/config`：配置接口已验证，但群聊开启后的真实回复仍需群聊消息和明确测试授权
- SQLite Contact 行缓存：已实现并保持进程稳定，但当前测试未捕获到目标联系人行，尚未证明空闲时能命中缓存

## 注意事项

偏移仅适用于微信 `4.1.10.27`。地区、签名、头像、性别等尚未确认结构的字段不会使用猜测偏移读取；升级微信版本前应重新验证偏移和回归测试。
## Latest runtime verification (WeChat 4.1.10.27)

- The live SQLite layout uses `db_storage\\contact\\contact.db`; the hook recognizes this path as well as legacy `MicroMsg.db` and rejects `contact_fts.db`.
- `/QueryDB/GetAllDBName` was verified to return the captured `contact.db` path and handle from the SQLite hook.
- Group auto-reply was verified after a real inbound group message: `AutoReplyGroupCandidates=1`, `AutoReplyQueued=1`, `AutoReplySent=1`, `AutoReplyFailed=0`; target `18652463466@chatroom`, body `[auto-reply] wxid_orly2zssd5e112:\n11111`.
- After rebuilding and reinjecting the DLL, WeChat remained responsive at about 255 MB working set with no crash.
- `/GetContact` and `/QueryDB/execute` still require an active contact-database callback; idle requests time out and are not counted as successful verification. Optional profile fields remain empty.
- `/SendImgMsg`, `/ForwardXMLMsg`, and `/Decode_Pic` continue to return the safety error for unverified 4.1.10.27 offsets.
