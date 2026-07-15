# WeChat-Hook 4.1.10.27

适用于微信 PC `4.1.10.27` 的 Hook 项目。

## 快速启动

编译 `x64_Version_dll.vcxproj` 和 `launcher/WeChatHookLauncher.vcxproj` 后，使用命令行启动：

```powershell
.\launcher\bin\WeChatHookLauncher.exe --start
```

启动器会启动微信、注入 `version.dll`，并开启 30001 端口。

## 已验证接口

```http
GET  http://127.0.0.1:30001/
GET  http://127.0.0.1:30001/QueryDB/status
POST http://127.0.0.1:30001/GetSelfProfile
POST http://127.0.0.1:30001/GetContact
POST http://127.0.0.1:30001/SendTextMsg
```

接口验证范围：

- `/`：HTTP 服务健康检查。
- `/QueryDB/status`：返回登录状态、状态来源、状态切换次数、消息观察和自动回复计数。
- `/GetSelfProfile`：已验证返回 `wxid`、`alias`、`nickname`、`phone`。未登录时返回 `profile_read_ok=false`，不会返回上一会话缓存。
- `/GetContact`：已通过真实微信进程验证，可返回联系人 `username`、`nick_name`、`alias`、头像地址等字段；不存在的 wxid 返回 JSON `status=404`，不崩溃。
- `/SendTextMsg`：已验证登录检查和发送请求入队。未登录返回 `ret=-2`，请求成功进入发送队列返回 `ret=0`；该接口返回的是本地入队结果，不等同于微信服务端送达回执。

个人资料的 `area`、`signinfo`、`avatar`、`small_avatar`、`sex` 字段目前保留但未确认稳定的内存布局，可能为空；不会使用猜测偏移填充。联系人查询和历史消息查询可以使用 SQLite，但 SQLite 不作为实时消息接收入口。

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
- `/GetContact` 返回联系人资料，并对不存在的 wxid 安全返回
- `/SendTextMsg` 完成登录检查和发送请求入队
- 根路径健康检查 `/`
- 普通文本接收、发送者 wxid/正文拆分和好友/群聊/自身消息分类
- UTF-8 JSON 响应头
- 未登录和已登录自动化回归测试

尚未完成或仍需专项验证：

- 地区、签名、头像、性别等资料字段：尚未确认稳定的内存结构，当前可能为空
- `LoginProbeCalls`：探针已安装，但该版本实际登录流程未调用当前候选函数，状态目前由登录完成回调确认
- 退出登录后的动态回归：代码已清理状态，但还需要在真实账号上执行一次“登录 → 退出登录 → 重新登录”验证
- 多账号切换和微信重启后的完整回归
- 图片、XML、数据库执行等其他路由：当前没有纳入已验证接口清单

## 注意事项

偏移仅适用于微信 `4.1.10.27`。地区、签名、头像、性别等尚未确认结构的字段不会使用猜测偏移读取；升级微信版本前应重新验证偏移和回归测试。
