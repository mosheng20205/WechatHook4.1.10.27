# 微信登录状态逆向与实现笔记（4.1.10.27）

> 适用目标：微信 `4.1.10.27` 的 `Weixin.dll`。本文记录当前项目已验证的登录状态镜像方案。登录回调和探针 RVA 都是版本私有数据，新版本必须重新定位并做登录/退出动态对比。

## 1. 对外接口

```http
GET http://127.0.0.1:30001/QueryDB/status
```

核心字段：

| 字段 | 含义 |
| --- | --- |
| `IsLogin` | 当前镜像状态，`0` 未登录，`1` 已登录 |
| `LoginStateSource` | `1` 登录完成回调，`2` 状态探针，`0` 未知 |
| `LoginStateChanges` | 观察到的状态切换次数 |
| `LoginStateLastChange` | 最近一次切换的 `GetTickCount64()` 值 |
| `LoginFinishCalls` | 登录完成回调命中次数 |
| `LoginFinishPayload` | 最近一次登录完成回调的 payload 地址 |
| `LoginProbeCalls` | 状态探针调用次数 |
| `LoginProbeLast` | 最近一次探针返回值 |
| `LoginProbeHookInstalled` | 探针 Hook 是否安装成功 |

## 2. 已确认的 Hook 方案

### 2.1 登录完成回调

- 当前版本 RVA：`Weixin.dll + 0x70FB30`。
- Hook 原型：`int64_t __fastcall(context, payload)`。
- 必须先调用原函数并保留原返回值。
- 运行时观察到成功登录路径的返回值可能为 `0`，不能只判断返回值；非空 `payload` 是当前版本更可靠的成功信号。
- 状态更新规则：`result != 0 || payload != nullptr` 时镜像为已登录，并将 `LoginStateSource` 设为 `1`。

### 2.2 登录状态探针

- 当前版本候选 RVA：`Weixin.dll + 0x36AB30`。
- Hook 原型：`unsigned char __fastcall(context)`。
- 先调用原函数，再记录返回值，并把非零返回值映射为已登录。
- 状态来源设为 `2`。
- 早期运行中曾出现 `LoginProbeCalls = 0`，说明探针不一定在所有登录路径被调用；因此不能单独依赖它，必须保留登录完成回调路径。

## 3. 状态镜像和退出保护

所有状态更新集中在 `SetMirroredLoginState()`：

1. 将状态规范化为 `0/1` 并原子写入 `g_IsLogin`。
2. 只有状态真正变化时才递增 `LoginStateChanges`。
3. 记录最近变化时间。
4. 变为未登录时清空 `g_ProfileObject`，因为该对象属于当前会话，退出后可能已经被微信释放。

登录状态判断不能使用“上一次成功登录留下的资料对象”或未验证的固定内存地址。未登录时所有依赖会话对象的读取都必须直接返回空/失败。

## 4. 运行时验证方法

每个版本至少完成以下四组测试：

1. 微信进程启动但未登录：`IsLogin = 0`。
2. 完成登录：`IsLogin = 1`，`LoginFinishCalls` 或 `LoginProbeCalls` 增加。
3. 主动退出登录：`IsLogin = 0`，`LoginStateChanges` 增加，资料对象清零。
4. 微信完全重启后重复 1～3，确认状态不会继承上一次进程。

推荐记录：

```powershell
$s = Invoke-RestMethod http://127.0.0.1:30001/QueryDB/status
$s | Select IsLogin,LoginStateSource,LoginStateChanges,LoginFinishCalls,
    LoginProbeCalls,LoginProbeLast,LoginProbeHookInstalled | ConvertTo-Json
```

## 5. 安全与迁移规则

- Hook 必须透传原函数返回值，不能用固定值替代原调用。
- 登录回调参数只用于记录和状态判断，不能把 payload 直接当作个人资料对象。
- 不要在 HTTP 线程中读取已注销会话的微信内部对象。
- 新版本应先用只计数 Hook 确认函数确实在登录和退出路径命中，再写入状态镜像。
- 若登录完成回调签名、payload 语义或探针返回类型发生变化，应同时更新 Hook 原型和状态判断条件。
