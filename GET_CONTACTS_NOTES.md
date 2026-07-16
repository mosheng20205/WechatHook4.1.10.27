# 获取联系人实现说明（微信 4.1.10.27）

> 目标：让 `/GetContacts` 返回**全部联系人的完整资料**（昵称、别名、头像、拼音等），并将响应标记为 `"complete": true`。

## 1. 背景与问题

登录后原有实现只能拿到"会话用户名列表"：

- 登录同步回调 `sub_182CF90A0`（`ContactSessionInfoCalls`）只暴露约 18 个**会话 wxid**，不含完整资料。
- 其中仅约 4 条通过登录期 CGI 增量同步带回了昵称/头像，其余仅有 `wxid/username`。
- 因此 `/GetContacts` 只能返回部分数据，`"complete"` 被硬编码为 `false`。

## 2. 方案选型（为什么不走"主动调度内存全量加载"）

曾评估过纯内存 Hook 的"主动调度全量加载"方案（方案 B），经 IDA 验证后**放弃**，原因：

- 完整联系人加载是**按需任务**，普通登录不触发，调用链为：
  `sub_180CCC090`（调度）→ `sub_180CDD670`（任务）→ `sub_180CCC6F0`（分页读）→ `sub_180CCD320`（拆分，已被 `Hook_ContactPipeline` 观察）。
- 调度器 `sub_180CCC090` 的入参 `a1` 是一个**带两个独立引用计数子对象**的"完成上下文对象"（见 `sub_180CDD570` 读取 `a1+8`、`a1+16`），主服务对象还来自一个全 DLL 有 100+ 引用的通用全局，并非联系人单例。
- 登录期没有自然触发点安全捕获该上下文；主动重建这些内部对象属崩溃高危，直接违反项目"稳定性优先、只对已验证偏移加 Hook、不在非微信线程重入内部同步/DB 逻辑"的硬规则。

**最终采用：SQLite 全表回填（AGENTS.md 明确背书、真机验证稳定的路径）**，同时**保留全部现有内存 Hook**用于实时/机会性捕获。

## 3. 实现（`src/GetSelfProfile.cpp`）

核心：首次请求 `/GetContacts` 时，把只读查询交给**微信自己的 SQLite 工作线程**执行，逐行合并进联系人缓存。HTTP 线程**绝不**直接操作内部 SQLite 句柄。

关键新增/改动：

- `BackfillContactsFromDatabase(timeoutMs)`
  - 通过已验证安全的 `RunSqlQueryOnSqliteThread("MicroMsg.db", "SELECT * FROM Contact", ...)`（定义于 `src/inline_weixin_dll_load.cpp`）排队执行只读查询。
  - 逐行提取键（兼容 `username / UserName / user_name / wxid / Wxid`），调用 `CacheContactRow(wxid, row)` 合并；DB 行为完整资料，覆盖登录时的会话-only 条目。
  - 原子标志：`g_ContactBackfillDone`（成功一次即完成）与 `g_ContactBackfillRunning`（防并发重复查询）。
- `/GetContacts` 处理器：在构建快照前调用 `BackfillContactsFromDatabase(15000)`。微信空闲时 SQLite 线程可能未及时认领查询而返回 0，此时快照仍为 `complete:false`，**下次请求自动重试**。
- `BuildCachedContactSnapshot`：`"complete"` 不再硬编码，改为反映 `g_ContactBackfillDone`。
- `ClearContactCache()`（登出时调用）会重置 `g_ContactBackfillDone`，保证换账号重新回填。

数据来源与格式：

- 结果由 `xdb/db_mgr.cpp` 的 `DatabaseMgr::execute()` 产出，形如 `{"status":0,"data":[{列:值,...}]}`，单次上限 1000 行。
- Contact 表列名为 snake_case（`username`、`nick_name`、`alias`、`big_head_url`、`small_head_url`、`quan_pin` 等），与 `/GetContact` 单查一致。

## 4. 运行时验证结果

| 项目 | 结果 |
|------|------|
| DLL 替换 | 新 `version.dll`（679936 B）覆盖到 `C:\Program Files\Tencent\Weixin\version.dll` |
| 注入 + 启动 | `WeChatHookLauncher --start` 注入成功，`/QueryDB/status` 返回 200 |
| 登录 | `IsLogin = 1` |
| **`/GetContacts`** | **`count = 66`，`complete = true`** |
| 完整字段覆盖 | 66/66 含 `nick_name`，66/66 含 `big_head_url`，另含 `quan_pin`、`small_head_url` 等 |
| 进程稳定性 | 5 个微信进程，主进程约 238.7 MB，无崩溃、无异常内存增长 |
| `ContactPipelineCalls` | `0`（印证全量加载链路登录时未触发，补全全部来自 SQLite 回填） |

样本行（真实完整资料）：

```json
{"nick_name":"小红书Python学员群","quan_pin":"xiaohongshuPythonxueyuanqun",
 "small_head_url":"https://wx.qlogo.cn/mmcrhead/...","username":"...@chatroom"}
```

## 5. 注意事项

- **`count = 66 > 54` 属正常**：`SELECT * FROM Contact` 返回联系人全表，除好友外还包含**群聊（`@chatroom`）、公众号/服务号、陌生人**等条目。
- **首次可能仍 `complete:false`**：刚登录且微信空闲时，SQLite 线程可能尚未认领查询；多调用一两次 `/GetContacts`（或期间微信有任何联系人相关 DB 活动）即可置 `complete:true`。
- 响应中同一条目可能同时含 `UserName`（DB 列）与 `username`（快照补充键），部分严格 JSON 解析器（如 PowerShell `ConvertFrom-Json`）会因大小写不敏感报"重复键"，属解析器限制，非数据错误。

## 6. 后续可选增强

- 支持 `/GetContacts` 传 `{"friends_only": true}`，按 `local_type` / `verify_flag` / 排除 `@chatroom`、`gh_` 前缀过滤出纯好友。
- 支持传入自定义 `SELECT`/列裁剪以减小响应体。
