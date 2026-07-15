# WeChat-Hook 项目规则与已验证事实

## 已验证的消息分发入口

- 适用版本：微信 `4.1.10.27`。
- `Weixin.dll + 0x4D93DB0`（IDA 名称 `sub_184D93DB0`）是实时同步消息总分发器。
- 该函数从 `a1 + 0x20` 获取同步上下文对象，检查 `appmsg`、`type`、`sysmsg`，并按消息类型分派。
- 运行时 Hook 已验证：发送一条普通消息后 `MessageReceiveCalls` 增加（实测一次为 6），说明该入口确实被实时消息路径调用。
- 当前在该分发器中最稳定命中的普通测试链路仍偏系统同步分支；解析发送者和正文时，不要再盲目套用候选偏移，优先追踪消息入队/数据库写入/上层普通文本处理函数。
- 下一步目标：解析 `a1 + 0x20` 指向对象中的普通文本消息对象，提取发送者和正文；确认字段后再接入回调和自动回复。

## 已验证：普通文本接收、wxid 拆分与自动回复

- 适用版本：微信 `4.1.10.27`，目标模块为 `Weixin.dll`。
- IDA MCP 已确认 `sub_182C28700 -> sub_182C2C810 -> sub_1816D5180` 是普通同步消息处理链；`sub_1816D5180` 使用 0x78（120）字节消息项步长。
- `sub_180A1B9C0` 将原始消息项复制为结构化消息对象。结构化对象中已在真实运行时验证：`object + 0x18`（`SyncBatchText1`）为发送者 wxid，`object + 0x38`（`SyncBatchText2`）为当前账号 wxid，`object + 0x180`（`SyncBatchText3`）为普通文本正文，`object + 0x1C0`（`SyncBatchText4`）为 msgsource XML。
- 实测其他账号发送 `你好456`：`SyncBatchText1 = wxid_orly2zssd5e112`，`SyncBatchText2 = wxid_ip31nye3qygp22`，`SyncBatchText3 = 你好456`。
- `QueryDB/status` 实测计数为 `AutoReplyCandidates = 1`、`AutoReplyQueued = 1`、`AutoReplySent = 1`、`AutoReplyFailed = 0`，证明已成功提取发送者 wxid、正文并调用异步自动回复发送逻辑。
- 自动回复通过独立工作线程调用 `WeixinSend::SendText(sender_wxid, "收到：" + content)`；接收 Hook 内不得直接重入发送函数。发送前仍需检查登录状态、wxid 格式、空正文和自身 wxid，避免误发。
- `SyncBatchText4` 仅为消息元数据，不应作为普通文本正文；SQLite 继续只用于联系人/历史消息查询，不作为实时接收消息入口。

## 修改规则

- 仅对已在 IDA 和运行时验证过的偏移加 Hook。
- Hook 必须透传原函数返回值，不得用固定返回值替代原调用。
- 修改后必须重新编译 DLL，并在微信重启、重新登录、发送测试消息后验证计数器和接口结果。
-
## 已验证：实时普通文本接收与拆分

- 适用版本：微信 `4.1.10.27`，`Weixin.dll`。
- IDA MCP 已确认 `sub_183544650` 调用 `sub_182C28700` 时，消息容器元素步长为 `0x70`（调用者使用 `add r14, 70h`）。
- `sub_182C28700` 的消息条目类型读取位置已验证为 `item + 0x48`。
- Hook `sub_182C28700` 后，使用 `0x70` 步长枚举容器，可捕获普通文本消息。
- 运行时已成功验证：其他账号发送 `你好123` 后，接口状态返回：
  - `IsLogin = 1`
  - `RawSyncMsgItemCount = 1`
  - `MessageStructCopyCalls = 1`
  - `MessageStructTalker = "莫生"`
  - `MessageStructContent = "你好123"`
- 当前消息对象暴露出的文本格式为 `发送者 : 正文`；代码已在 `src/inline_weixin_dll_load.cpp` 中将该字段拆分到发送者和正文缓冲区。
- 该接收链路已通过真实微信进程、重新登录和跨账号发送普通文本完成验证；后续自动回复应使用工作线程调用发送接口，不得在消息 Hook 内直接重入发送函数。
