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

## 最新验证：安全 AddMsg 字段读取与进程稳定

- 适用版本：微信 `4.1.10.27`，目标模块为 `Weixin.dll`。
- 微信重启并注入新版 DLL 后，在 `sub_1816D5180` 观察点增加了 `micromsg.AddMsg` vtable 校验；仅对 vtable 为 `Weixin.dll + 0x83DF408`、数组步长为 `0x78` 的消息项读取字段。
- 字段读取使用 protobuf `has-bits` 和 ArenaStringPtr 校验：字段 2（`fromusername`）位于 `item + 0x08`，字段 3（`tousername`）位于 `item + 0x18`，字段 5（`content`）位于 `item + 0x20`。未通过校验的对象不会被解引用。
- 真实连续验证结果：其他账号发送 `你好456` 和 `你好789` 后，`SyncBatchProcessorCalls = 2`、`SyncBatchVtableMatches = 2`、`SyncBatchFieldReadCalls = 2`；最后一条消息拆分为：发送者 `wxid_orly2zssd5e112`、接收者 `wxid_ip31nye3qygp22`、正文 `你好789`。
- 两次消息处理期间 `AutoReplyCandidates = 0`、`AutoReplyQueued = 0`、`AutoReplySent = 0`，自动回复仍保持关闭，避免在解析点重入发送逻辑。
- 第二次验证后微信主进程工作集约 `256.3 MB`，所有微信进程保持响应，未出现崩溃或异常内存增长。
- `SyncBatchLastMsgType` 当前仅记录 field1 的原始值，语义尚未确认，不得据此筛选普通文本类型。
- 本节结论优先于早期按 `0x70` 步长盲扫原始同步向量的实验记录；当前规则以 `0x78` 步长、AddMsg vtable 和 has-bits 校验为准。

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

## 已验证：联系人查询与稳定性保护

- 适用版本：微信 `4.1.10.27`，`Weixin.dll`。
- `/GetContact` 已通过真实微信进程验证，可返回联系人完整行数据，包括 `username`、`nick_name`、`alias`、`big_head_url`、`small_head_url`、`quan_pin` 等字段，并返回 `contact_found = true`。
- 联系人查询使用 SQLite Hook 捕获包含 `Contact`/`ChatRoom` 的数据库连接；HTTP 接口只提交查询请求，实际 `sqlite3_prepare_v2`/`step` 在微信自己的 SQLite 调用线程执行，禁止 HTTP 线程直接操作内部连接。
- 已验证示例：查询 `wxid_orly2zssd5e112` 返回 `nick_name = "莫生"`、`alias = "zhx_ms"`、头像地址和 `contact_found = true`；不存在的 wxid 返回 `status = 404`，不会崩溃。
- 已移除 `PRAGMA database_list`、全进程 VFS 扫描以及无界结果读取；这些路径可能使用错误句柄或造成数 GB 内存增长。
- 重新编译结果为 0 个警告、0 个错误；查询后微信进程保持稳定（实测工作集约 277 MB）。
- 原始同步消息 Hook 当前只记录调用参数，不再盲目把同步向量当作消息对象调用 Getter；安全的 AddMsg vtable/has-bits 字段读取已在 `sub_1816D5180` 边界启用，但自动回复仍保持关闭。
- SQLite 仅用于联系人和历史消息查询，不作为实时消息接收入口；实时消息接收必须继续沿已验证的消息分发链路定位。

## 已验证（结论：不可行）：任意 appmsg/XML 转发在 4.1.10.27 无可用发送路径

> ⚠️ 本节结论已被下方「已验证：appmsg/XML 真实发送（通用 CGI 分发器 + 自定义 vtable task）」小节推翻。当时结论「不可行」仅针对复用 `send_message` 本地内容类路径；后续通过绕开本地内容类、直接构造 sendappmsg CGI task 并经通用分发器下发，已实现真实发送。本节仅作历史实验记录保留，实施时以下方最新小节为准。

- 适用版本：微信 `4.1.10.27`，`Weixin.dll`。IDB imagebase `0x7ffe8e960000`（RVA = 绝对地址 − imagebase）。
- 转发链接/卡片本质是「服务器按引用中转」：本地不构造原始 XML 对象。运行时实测转发到文件传输助手与真实联系人，均未命中以下任一发送函数：
  - `send_message`（RVA `0x1677A30`）：仅普通文本与文件/图片 compose 命中；实测普通文字使 `send_calls` +1，转发始终不增长。
  - copy-from-source 工厂 `sub_7FFE900A1640`（RVA `0x1741640`）：`forward_calls` 恒为 0。
  - start-send 总分发器 `sub_7FFE94BEE6B0`（RVA `0x628E6B0`，自证字符串 "send sources invalid when start send"）：`forward_calls` 恒为 0。
- 通用 appmsg 内容类为「MessageSendSource」基类，vtable RVA `0x84F9A78`，对象大小 `0x718`（1816）字节。工厂/构造器共 4 处写该 vtable：copy-from-source `sub_7FFE900A1640`、copy-ctor `sub_7FFE90244250`、默认工厂 `sub_7FFE90C092B0`（RVA `0x46A92B0`）、大分发工厂 `sub_7FFE9137AC80`（即旧记 `sub_182A1AC80`）。工厂按序列化类名字符串分派，无 `AppMessageSendSource` 分支，appmsg 落入通用基类。
- 通用基类 base 子对象布局（默认工厂 + 基类 ctor `sub_7FFE8F012D30` 静态推导，并与已验证 `TextMessage` 结构交叉核对）：`WeixinString` 槽位于 `0x18/0x38/0x58/0x78/0xB0/0x108/0x148/0x168/0x190/0x6A8/0x6C8/0x6E8`；`receiver@0xB0`、`msgtype@0xD8`、`uuid@0x6A8`。copy-from-source 转发时保留 `0x38/0x58/0x78` 并重置 `receiver@0xB0`。
- 运行时实测（经验式发送）：用默认工厂 `sub_7FFE90C092B0` 构造通用基类对象、以 `param1_vtable`（文本 param 类 `0x84EC9C8`）包装后调用 `send_message`，**直接崩溃 Weixin.exe**。根因：文本发送路径读取文本子类 `content@0x708`，越过 `0x718` 字节的通用基类末尾造成越界；通用基类没有专用 appmsg 发送处理器。因此扫描 XML 字符串槽（`0x38/0x58/0x78`）无意义，崩溃与槽位无关。
- 结论：4.1.10.27 上任意 appmsg/XML 发送**没有可通过 `send_message` 复用的路径**；文本与文件/图片各有专用内容类，appmsg（链接卡片/转发）走独立中转派发，静态与运行时均未定位到可安全复用的发送入口。
- 当前实现（安全）：`/ForwardXMLMsg` 默认返回 `ret = -3` 并安全拒绝，不崩溃；构造/发送 harness（`WeixinSend::SendAppMsg` + 偏移白名单 + `xml_offset`/`type_value` 扫描）仅在请求体显式 `experimental_send=true` 时触发，仅供后续研究。禁止把默认路径改为直接发送，除非在真实客户端重新验证出不崩溃、可投递的 appmsg 发送入口。
- `wx_send_xml.cpp` 中 4.1.5.30 的 `FORWARD_XML_CALL` 等偏移对 4.1.10.27 已确认失效（落入无关 Qt UI 代码），不得使用。

## 已验证：appmsg/XML 真实发送（通用 CGI 分发器 + 自定义 vtable task）

- 适用版本：微信 `4.1.10.27`，`Weixin.dll`。IDB imagebase `0x7ffe8e960000`（RVA = 绝对地址 − imagebase）。参考成熟实现：`T:\github\WeChatApi-4.1.8.27`。
- **通用 CGI 任务分发器捕获点**：`sub_7FFE8EC64F80`（RVA `0x304F80`）是网络管理器的 `manager->vtable[5]`。IDA 已交叉验证：sendappmsg 专用提交原语 `sub_7FFE9200F120`（RVA `0x36AF120`）内部通过 `(*(*(a1)+40))(a1, task)` 分发到它；`get_bytes` 读 vtable `@0x7ffe96b814f8` 确认 slot 5（`+0x28`）指向 `0x7ffe8ec64f80`。该分发器签名为 `(manager, task)`，读取 `task+8/+12/+232/+236`、生成 task_id 写 `task+8`，并把 task 插入 `manager+72` 的红黑树。
- **被动捕获管理器**：Hook `manager->vtable[5]`（RVA `0x304F80`）后，登录/同步/联系人/sendappmsg 等**任意 CGI 动作**都会经过它，即可被动捕获活的网络管理器指针到 `g_AppMsgSubmitManager`。实测微信启动、**尚未登录**（`IsLogin = 0`）时 `TaskDispatchCalls = 2`、`AppMsgSubmitManager` 已为有效非零指针 —— **彻底消除了对「手动发一张卡片才能捕获管理器」的依赖**。旧的 F120 观察器（只在实际发卡片时触发）不可靠，已实测多次发卡片未命中。
- **自定义 vtable CGI task 发送方案**：① 手工序列化 protobuf；② 用微信原生 ctor `appmsg_task_ctor`（RVA `0x36AF460`）构造 sendappmsg CGI task；③ 覆写 task 的 6 槽 vtable，序列化槽直接交出预序列化字节，绕开原生 inner-req 序列化崩溃点；④ dtor 设为 no-op（task 故意泄漏，避免释放崩溃）；⑤ `task+208` 指向 dummy callback holder；⑥ 经 `manager->vtable[5]` 分发。
- **protobuf 线格式**：`AppMsg(1=fromusername, 3=0, 4=tousername, 5=type, 6=xml, 7=timestamp, 8=clientmsgid, 12=msgsource)`；`BaseRequest(1="", 2=0, 3="Windows", 4=0, 5="Windows", 6=0)`；`SendAppMsgReq(1=base bytes, 2=appmsg bytes)`。响应 field1(bytes)=BaseResponse，其 field1 varint = ret。CGI type `0xDE`（222），endpoint `/cgi-bin/micromsg-bin/sendappmsg`。
- **真实 self wxid 解析**：`SelfInfo.wxid`（`/GetSelfProfile` 填充）返回的是**别名**（如 `python100day`），直接作 `fromusername` 会被服务器拒绝（`ret = -2`）。`ResolveSelfWxid()` 从 `g_SqliteContactDbPath`（形如 `...\xwechat_files\wxid_ip31nye3qygp22_eba2\...`）解析出真实 `wxid_`，作为 `fromusername`。
- **真实运行时验证**：登录后 `POST /ForwardXMLMsg`（body `{"to_wxid":"filehelper","type":5,"content":"<appmsg>...</appmsg>"}`）返回 `{"ret":0,"retmsg":"success","type":5}`；`QueryDB/status` 计数 `AppMsgSendCalls = 1`、`AppMsgDispatchOk = 1`、`AppMsgDispatchFail = 0`、`AppMsgSerializeCalls = 1`、`AppMsgResponseCalls = 1`、`AppMsgLastRespSize = 375`、**`AppMsgLastRet = 0`（服务器接受）**。卡片「WeChat-Hook 真实发送测试 / native sendappmsg CGI replay」已在文件传输助手与联系人会话中可见。微信主进程稳定约 `243 MB`，全程无崩溃。
- **诊断计数器**（`/QueryDB/status`）：`TaskDispatchHookInstalled`、`TaskDispatchCalls`、`AppMsgSubmitManager`、`AppMsgSendCalls`、`AppMsgDispatchOk/Fail`、`AppMsgSerializeCalls`、`AppMsgResponseCalls`、`AppMsgLastRespSize`、`AppMsgLastRet`。
- **约束**：接收 Hook 内不得重入发送；发送前校验登录状态与 `g_AppMsgSubmitManager != 0`；task vtable 序列化槽必须交出完整预序列化字节，禁止回退到原生 inner-req 序列化路径（会崩溃）。
