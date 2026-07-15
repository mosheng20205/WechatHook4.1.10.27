# 微信接收消息逆向与实现笔记（4.1.10.27）

> 适用目标：`Weixin.dll`，微信 `4.1.10.27`。文档记录的是本项目在 IDA Pro MCP 和真实运行时中验证过的接收链路。所有 RVA、步长和字段偏移都必须在新版本重新确认，不能直接当作通用 ABI。

## 1. 已确认的消息链路

### 1.1 实时同步总分发器

- `Weixin.dll + 0x4D93DB0`（IDA 名称 `sub_184D93DB0`）是实时同步消息总分发器。
- 函数从 `a1 + 0x20` 获取同步上下文，并按 `appmsg`、`type`、`sysmsg` 等分支继续分派。
- 该入口适合做调用计数和分支观察；不应仅凭 `a1 + 0x20` 直接猜测普通文本字段。

### 1.2 结构化 AddMsg 路径（当前优先使用）

IDA MCP 和运行时确认的调用关系：

```text
sub_182C28700 -> sub_182C2C810 -> sub_1816D5180
```

- `sub_1816D5180` 遍历 `micromsg.AddMsg` 消息项，当前版本的安全观察步长为 `0x78`。
- 每个消息项的 vtable 必须等于 `Weixin.dll + 0x83DF408`，不匹配时不得解引用。
- `sub_180A1B9C0` 将原始项复制为结构化对象。运行时验证的字段为：

| 结构化对象偏移 | 当前含义 | 项目状态字段 |
| ---: | --- | --- |
| `+0x18` | 发送者 wxid | `SyncBatchText1` |
| `+0x38` | 当前账号/接收者 wxid | `SyncBatchText2` |
| `+0x180` | 普通文本正文 | `SyncBatchText3` |
| `+0x1C0` | msgsource XML 元数据 | `SyncBatchText4` |

- 原始 `micromsg.AddMsg` 字段读取位置：
  - 字段 2 `fromusername`：`item + 0x08`
  - 字段 3 `tousername`：`item + 0x18`
  - 字段 5 `content`：`item + 0x20`
- 读取前必须检查 protobuf has-bits、ArenaStringPtr 结构和字符串长度；校验失败时直接跳过。

### 1.3 旧的显示文本路径（可用于交叉验证）

另一路调用者 `sub_183544650` 使用 `0x70` 步长调用 `sub_182C28700`，消息条目的类型读取位置为 `item + 0x48`。该路径曾在真实运行时暴露出 `发送者 : 正文` 格式的显示文本，并成功捕获普通文本。

这条 `0x70` 路径与上面的 `0x78` AddMsg 路径不是同一个结构，不能混用步长或字段偏移。当前实现优先使用带 vtable/has-bits 校验的 `0x78` 路径。

## 2. 运行时验证结果

已用其他微信账号发送普通文本完成验证：

- 发送者 wxid、接收者 wxid 和正文均能拆分。
- 示例正文：`你好456`、`你好789`。
- 典型状态计数：`SyncBatchProcessorCalls` 增加、`SyncBatchVtableMatches` 与有效消息数一致、`SyncBatchFieldReadCalls` 增加。
- 微信主进程在连续消息测试后保持响应，工作集约 `256 MB`；没有观察到由该只读解析器引起的崩溃或异常内存增长。
- SQLite 没有参与实时接收链路；SQLite 只用于联系人和历史记录查询。

## 3. 好友、群聊和自身消息分类

当前自动回复入口在解析出 `fromusername`、`tousername` 和正文后统一调用分类器：

1. `fromusername` 等于当前账号 wxid：记录为 `self`，跳过，不回复自己发出的消息。
2. `fromusername` 包含 `@chatroom`：记录为 `group`，`fromusername` 作为群 room wxid。
3. 其他符合 `wxid_`、`filehelper`、`gh_` 等格式的发送者：记录为 `friend`，使用发送者 wxid 作为回复目标。

群聊自动回复开关默认关闭（`AutoReplyGroupEnabled = 0`），因此群消息会计数但不会进入发送队列，避免误发群消息。当前分类已经能区分群 room；群内具体成员 wxid 的进一步提取尚未作为安全必需字段接入。

可通过 `/QueryDB/status` 观察：

- `AutoReplyLastChatType`：`friend`、`group` 或 `self`
- `AutoReplyLastSender`：最近一次分类的发送者
- `AutoReplyLastRoom`：最近一次群聊 room wxid
- `AutoReplyFriendCandidates`
- `AutoReplyGroupCandidates`
- `AutoReplyGroupSkipped`
- `AutoReplySelfSkipped`

## 4. 安全规则

- Hook 必须透传原函数返回值；接收观察点只读，不修改微信原始消息对象。
- 只对已验证 vtable、步长、has-bits 和字符串长度的对象读取字段。
- 不要在接收 Hook 线程内直接调用发送函数；接收线程只负责复制字符串和入队，发送由独立工作线程延迟执行。
- 任何新版本都必须先做计数 Hook，再做只读字段读取，最后才接入自动回复。
- 不要把 SQLite 查询结果当作实时接收事件，也不要从 HTTP 线程直接操作微信内部 SQLite 连接。

## 5. 迁移到新微信版本的检查顺序

1. 在 IDA 中重新定位实时分发器、`AddMsg` 遍历函数和结构化复制函数。
2. 动态确认消息项步长、vtable、has-bits 位置及字段 2/3/5 的字符串对象布局。
3. 先只安装计数 Hook，确认登录、好友消息、群消息和自身消息分别命中。
4. 再开启只读字段捕获，检查 wxid 与正文的 UTF-8/UTF-16 编码和最大长度。
5. 最后才启用分类器和自动回复，并验证微信重启、重新登录、退出登录及多条连续消息。
