# WeChat Hook 4.1.10.27：状态与测试

## 启动

```powershell
T:\github\WeChat-Hook\launcher\bin\WeChatHookLauncher.exe --start
```

启动器会启动微信、注入 `version.dll`，并使用 30001 端口。

## 接口测试

未登录或已登录均可运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1
```

要求已登录时运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\test-api.ps1 -RequireLogin
```

## 状态字段

- `IsLogin`：当前镜像登录状态，0/1。
- `LoginStateSource`：1 表示登录完成回调，2 表示状态探针。
- `LoginProbeHookInstalled`：状态探针 Hook 是否安装。
- `LoginStateChanges`：状态切换次数。

## 个人资料

当前已验证字段：`wxid`、`alias`、`nickname`、`phone`。接口还会从 `MicroMsg.db` 的 `Contact` 表尝试读取 `Province`、`City`、`Signature`、`Sex`、`BigHeadImgUrl` 和 `SmallHeadImgUrl`，对应返回 `area`、`signinfo`、`sex`、`avatar` 和 `small_avatar`，不使用猜测的内存偏移。

接口返回 `application/json; charset=utf-8`。未登录时 `profile_read_ok=false` 且不会返回上一次会话的资料。

## 回归流程

1. 关闭所有微信进程。
2. 执行 `--start`。
3. 未登录时运行 `test-api.ps1`，确认 `IsLogin=0` 且 `ProfileReadOk=false`。
4. 登录后运行 `test-api.ps1 -RequireLogin`，确认资料可读。
5. 退出登录后再次运行测试，确认资料被清空。
- Message receive and reply (WeChat 4.1.10.27): the message dispatch observer is installed at RVA 0x1749DC0. It asynchronously POSTs to CallBackURL with msglist[0].field1/field2 and msgtype. Use POST /SendTextMsg with {wxidorgid,msg}; not logged in returns ret=-2, queued send returns ret=0. QueryDB/status exposes MessageReceiveCalls, MessageCallbackPosts and MessageHookInstalled.
