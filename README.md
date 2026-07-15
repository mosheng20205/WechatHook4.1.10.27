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
GET  http://127.0.0.1:30001/QueryDB/status
POST http://127.0.0.1:30001/GetSelfProfile
```

已验证个人资料字段：`wxid`、`alias`、`nickname`、`phone`。接口还会从 `MicroMsg.db` 的 `Contact` 表尝试补充 `area`、`signinfo`、`sex`、`avatar`、`small_avatar`；字段为空或数据库不可用时保持空值，不使用猜测的内存偏移。未登录时个人资料接口返回 `profile_read_ok=false`，不会返回上一会话缓存。

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
- UTF-8 JSON 响应头
- 未登录和已登录自动化回归测试

尚未完成或仍需专项验证：

- 地区、签名、头像、性别等资料字段：已增加数据库安全读取，仍需在实际账号资料上逐字段验证
- `LoginProbeCalls`：探针已安装，但该版本实际登录流程未调用当前候选函数，状态目前由登录完成回调确认
- 退出登录后的动态回归：代码已清理状态，但还需要在真实账号上执行一次“登录 → 退出登录 → 重新登录”验证
- 多账号切换和微信重启后的完整回归

## 注意事项

偏移仅适用于微信 `4.1.10.27`。地区、签名、头像、性别等尚未确认结构的字段不会使用猜测偏移读取；升级微信版本前应重新验证偏移和回归测试。
