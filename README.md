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
- `/ForwardXMLMsg`：appmsg/XML 链接卡片**真实发送**，已经真实微信进程端到端验证（服务器返回 `ret = 0`，卡片在对话中可见）。
- 好友和群聊自动回复：均已完成真实消息端到端验证。
- 防撤回 + 撤回灰条提示：撤回后原消息（文本 **AND** 图片）仍可见，并可额外显示`「xxx 撤回了一条消息」`灰条，默认关闭、运行时开关门控。
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
GET  http://127.0.0.1:30001/AutoReply/config
POST http://127.0.0.1:30001/AutoReply/config
GET  http://127.0.0.1:30001/AutoReply/rules
POST http://127.0.0.1:30001/AutoReply/rules
GET  http://127.0.0.1:30001/AntiRevoke/config
POST http://127.0.0.1:30001/AntiRevoke/config
GET  http://127.0.0.1:30001/RevokeTip/config
POST http://127.0.0.1:30001/RevokeTip/config
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

### XML 卡片转发

`/ForwardXMLMsg` 将 appmsg/XML 链接卡片**真实发送**到指定会话（已端到端验证）。

```powershell
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/ForwardXMLMsg' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"to_wxid":"filehelper","type":5,"content":"<appmsg><title>标题</title><des>描述</des><type>5</type><url>https://github.com/</url></appmsg>"}'
```

实现要点：

- 发送不复用本地文本/图片内容类（实测会崩溃），而是直接构造 `sendappmsg` CGI task，经网络管理器的通用任务分发器（`manager->vtable[5]`，RVA `0x304F80`）下发。
- 网络管理器在登录/同步等任意 CGI 动作时被动捕获，无需手动触发。
- `fromusername` 使用从联系人数据库路径解析出的真实 `wxid_`（而非别名），否则服务器会以 `ret = -2` 拒绝。
- native 调用均用 SEH 包裹；发送前校验登录状态与管理器已捕获。
- 诊断计数（`/QueryDB/status`）：`AppMsgSendCalls`、`AppMsgDispatchOk/Fail`、`AppMsgLastRet`（`0` 为服务器接受）。

### 防撤回 + 撤回灰条提示

开启后，撤回的消息（文本 **AND** 图片）会留在会话中可见；再开启灰条提示，会在同一会话额外插入`「xxx 撤回了一条消息」`本地灰条。两者默认关闭、运行时开关门控。

```powershell
# 1) 开启防撤回（保留被撤回的原消息）
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/AntiRevoke/config' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"enabled":true}'

# 2) 额外开启撤回灰条提示（需先开启防撤回）
Invoke-RestMethod `
  -Uri 'http://127.0.0.1:30001/RevokeTip/config' `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"enabled":true}'
```

实现要点：

- 防撤回以字节补丁（`0F 84` -> `90 E9`，`module + 0x22D09E7`）跳过 `sub_1822D07C0` 的撤回-应用分支，字节级校验、可逆；文本与图片一致生效。
- 灰条通过微信原生本地系统消息插入原语（`sub_184C280B0`）在 Hook 消息处理线程**同步**插入，线程亲和正确；native 调用 SEH 包裹。
- 防撤回会使 sysmsg 解析器返回「未处理」，导致原始 `<sysmsg>` XML 泄漏到临时「微信用户」会话；已在 Hook 内把 revokemsg 标记为「已消费」消除该泄漏，且不影响已保留的原消息气泡。
- 诊断计数（`/QueryDB/status`）：`AntiRevokeEnabled`、`RevokeTipInjectOk/Fail`、`RevokeConsumeOverrides`、`RevokeDistinctCount`。

详细逆向结论与真机验证记录见 [docs/ANTI_REVOKE_NOTES_4.1.10.27.md](docs/ANTI_REVOKE_NOTES_4.1.10.27.md)。

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

- `/SendImgMsg`：图片消息 vtable(`0x84F96B8`/`0x84F9748`)已在 IDA 对 4.1.10.27 校验，复用文本发送已验证的调用链，native 调用用 SEH 包裹；返回本地入队结果，对端送达仍需真实账号验证。
- `/Decode_Pic`：自实现 WeChat 4.0 "\x07\x08V2" `.dat` 图片解密（AES-128-ECB + 尾段单字节 XOR，AES/XOR 密钥均运行时从微信账号上下文派生，偏移已在 IDA 对 4.1.10.27 校验，native 派生调用用 SEH 包裹）。已真机端到端验证：真实 `.dat` 解出可打开图片（用例1 输出标准 JPEG，与离线重建逐字节一致；用例2 输出微信专有 `wxgf` 封装格式，解密结构一致），异常输入(不存在/空文件 `ret=-1`、非加密文件 `ret=-3`)安全返回错误码且进程稳定。
- `/ForwardXMLMsg`：appmsg/XML 链接卡片真实发送已启用并端到端验证（服务器 `ret = 0`，卡片在对话中可见，微信进程稳定无崩溃）。发送经由直接构造 `sendappmsg` CGI task 并经通用任务分发器下发；返回值代表服务器应答结果。
- `/GetSelfProfile` 的 `area`、`signinfo`、`avatar`、`small_avatar`、`sex` 等可选字段依赖数据库，仍可能为空，不会使用猜测偏移填充。
- `/SendTextMsg` 已验证本地发送入队和自动回复链路，返回值仅表示进入本地发送队列，不代表微信服务端或对端已送达。
- `/QueryDB/GetAllDBName` 仅返回 SQLite Hook 实际捕获到的联系人库句柄，不扫描进程内存；`/QueryDB/execute` 仅允许单条只读 SQL。
- 实时接收回调:配置 `wx.ini [wx] recv_url` 后，接收链路会把已验证的消息(含 msgtype、群 room 与群内成员 sender)异步 POST 到该地址;非文本消息按类型分类推送。
- 多账号切换、退出后重新登录仍建议在发布前执行完整真实账号回归。

## 版本适配笔记

- [联系人全量获取](GET_CONTACTS_NOTES.md)
- [登录状态](docs/LOGIN_STATUS_NOTES_4.1.10.27.md)
- [个人资料](docs/SELF_PROFILE_NOTES_4.1.10.27.md)
- [接收消息](docs/RECEIVE_MESSAGE_NOTES_4.1.10.27.md)
- [发送消息](docs/SEND_MESSAGE_NOTES_4.1.10.27.md)
- [XML 卡片发送](docs/SEND_XML_NOTES_4.1.10.27.md)
- [图片解密](docs/DECODE_PIC_NOTES_4.1.10.27.md)
- [防撤回 + 撤回灰条提示](docs/ANTI_REVOKE_NOTES_4.1.10.27.md)

## 安全约束

- 仅对已在 IDA 和真实运行时验证过的偏移安装 Hook。
- Hook 必须透传原函数返回值。
- 不在 HTTP 线程直接操作微信内部 SQLite 连接。
- 不在消息接收 Hook 内重入发送函数。
- 修改后需重新编译 DLL，并在微信重启、重新登录和真实消息测试后复核接口与计数器。
