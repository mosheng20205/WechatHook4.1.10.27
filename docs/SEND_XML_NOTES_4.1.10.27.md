# 微信 XML 卡片（appmsg）发送逆向与实现笔记（4.1.10.27）

> 适用目标：`Weixin.dll`，微信 `4.1.10.27`。本文件记录 `/ForwardXMLMsg` 真实发送 appmsg/XML 链接卡片（msgtype 49）的逆向结论、任务构造方式与运行时约束。换版本时必须重新验证所有 RVA、vtable 布局和 CGI 协议字段。对应实现见 [`src/wx_send.cpp`](../src/wx_send.cpp) 的 `WeixinSend::SendAppMsg` 与 [`src/ForwardXMLMsg.cpp`](../src/ForwardXMLMsg.cpp)。

## 1. 为什么不复用本地内容对象

早期实现（保留在 [`src/wx_send_xml.cpp`](../src/wx_send_xml.cpp) 中）尝试在本进程手工构造图片/视频/动图的 native 内容结构，再交给微信序列化，实测在异步网络工作线程内崩溃：

- 把 native `SendAppMsgRequest` protobuf 对象（无论从零构造还是克隆模板）交给异步网络工作线程序列化，会在 `Weixin.dll + 0x46A92E3` 崩溃——任何 ArenaStringPtr / has-bit / arena 不匹配在该点都是致命的，且在 SEH 覆盖范围之外。
- `wx_send_xml.cpp` 中旧的 `FORWARD_XML_CALL`（4.1.5.30 的 RVA `0x1CF3D20`）在 4.1.10.27 已确认失效：它落在 Qt UI 布局函数 `sub_181CF2FA0` 内部 0xD80 字节处，调用会跳进无关 UI 代码并崩溃。

结论：**当前发送路径永不把 native 对象交给微信序列化**，而是自建 CGI task + 自序列化 protobuf 字节。

## 2. 已确认的 sendappmsg CGI 提交链路

IDA MCP + F120 观察 Hook 确认的关键函数（RVA 基于 imagebase `0x180000000`）：

| 符号 | RVA | 作用 |
| --- | ---: | --- |
| `appmsg_submit`（`sub_7FFE9200F120`） | `0x36AF120` | sendappmsg 提交原语，硬编码 `/cgi-bin/micromsg-bin/sendappmsg`（cgi type 222），通过网络管理器下发。被动观察点，捕获活网络管理器。 |
| `appmsg_task_ctor`（`sub_7FFE9200F460`） | `0x36AF460` | CGI task 构造：cgi type←task_info+16，endpoint←task_info+24，空 inner request 建在 task+240，response holder 在 task+208，state=3。 |
| `appmsg_holder_write`（`sub_7FFE8EF3A760`） | `0x5DA760` | 向输出 holder 追加字节。 |
| `appmsg_holder_size`（`sub_7FFE8EF3A7D0`） | `0x5DA7D0` | 读响应 holder 大小。 |
| `appmsg_holder_data`（`sub_7FFE8EF3A7A0`） | `0x5DA7A0` | 读响应 holder 数据指针。 |

- task 原生 vtable `off_7FFE97216F98` 为 6 槽：`[dtor, serialize, response, getinner(->task+240), dummy, literal 1]`。
- 网络管理器 `g_AppMsgSubmitManager` 在 F120 观察点被动捕获，**下发用 `manager->vtable[5]`**（`mvt + 40`），与 F120 一致。

## 3. 自建 task + vtable 覆盖

`SubmitAppMsgTask` 按 native 提交原语的方式构造 task，再覆盖 task 的 6 槽 vtable，使其不再走 native 序列化/析构：

- `[0] dtor` → no-op（task **故意泄漏**：避免跨分配器 free + 析构从未填充的 response 对象 @task+336）。
- `[1] serialize` → 发出**我方手工序列化**的 protobuf 字节到输出 holder（native inner-req 序列化即崩溃路径，永不被调用）。
- `[2] response` → 捕获回复字节并解析 `BaseResponse.ret`。
- `[3] getinner` → 返回 task+240（native 语义）。
- `[4] dummy` / `[5] literal 1`（native 语义）。
- task+208 指向一个 dummy-vtable 回调 holder，让框架的 response-notify 路径持有一个有效（无害）对象。

task_info 布局（对照 `sub_7FFE9200F120` 验证）：header@0=0xDE、dword@12=1、cgi type@16=222、endpoint 指针@24、endpoint len@40=32、cap@48=47、byte@56=1。

task、task_info、回调 holder、预序列化的请求字节**全部故意泄漏**，确保异步工作线程永远不会命中 use-after-free。

## 4. protobuf 线格式（版本无关）

自序列化按下列 schema（镜像可用参考项目，与微信 schema 版本无关）：

```text
AppMsg:        1=from(str) 3=0(varint) 4=to(str) 5=type(varint)
               6=xml(str) 7=timestamp(varint) 8=clientmsgid(str)
               12=msgsource(str)
BaseRequest:   1="" 2=0 3="Windows" 4=0 5="Windows" 6=0
SendAppMsgReq: 1=BaseRequest(bytes) 2=AppMsg(bytes)
```

- `AppMsg.type` 即请求体的 `type` 字段，默认 `5`（链接/文章类 appmsg，与抓取到的真实发送一致），可按请求覆盖以支持其他 appmsg 子类型，无需重编译。
- `clientmsgid` 使用 `"{GetTickCount64}{ThreadId}"`。
- `msgsource` 固定为 `<msgsource><bizflag>0</bizflag></msgsource>`。

## 5. fromusername 解析（关键坑）

sendappmsg CGI 要求 `AppMsg.fromusername` 必须是**真实内部 wxid（`wxid_xxx`）**；若用人类别名（如 `python100day`）服务器会以 `ret = -2` 拒绝。`ResolveSelfWxid` 按优先级解析：

1. 消息同步 Hook 捕获的 self wxid（结构化对象 `+0x38`，`g_SyncBatchText2`）。
2. 从捕获的联系人库路径解析：`...\xwechat_files\<wxid>_<suffix>\db_storage\contact\contact.db`，剥去尾部 `_<suffix>`。
3. 最后兜底：`SelfInfo.wxid` 仅当它已形如 `wxid_` 时才使用。

## 6. HTTP 接口与返回值

`POST /ForwardXMLMsg` 请求体：

```json
{ "to_wxid": "filehelper", "type": 5, "content": "<appmsg>...</appmsg>" }
```

返回值语义：

- `ret = -1`：JSON 非法，或 `to_wxid`/`content` 为空、含 `\0`，或 `content` 超过 1MB。
- `ret = -2`：未登录（`g_IsLogin == false`）。
- `ret = -5`：本次登录尚未捕获到 sendappmsg 网络管理器——需先手动发送/转发一次真实卡片（任意会话）让管理器被动捕获，再重试。
- `ret = 0`：成功。发送侧成功判据 = task 已通过活管理器下发；response-notify 回调（vtable 槽[2]）为尽力而为——卡片在下发时已交给微信网络工作线程，无论回复解析是否在超时内落地都会发出。仅当解析到非零 `BaseResponse.ret` 才标记为真实的服务端拒绝。
- `ret = 1`：`SendAppMsg` 返回失败。

诊断计数（`/QueryDB/status`）：`AppMsgSendCalls`、`AppMsgDispatchOk/Fail`、`AppMsgSerializeCalls`、`AppMsgResponseCalls`、`AppMsgLastRespSize`、`AppMsgLastRet`（`0` 为服务器接受）。

## 7. 运行时验证结果

已通过真实微信进程端到端验证：

- 服务器返回 `ret = 0`，appmsg/XML 链接卡片在对话中可见。
- 网络管理器在登录/同步等任意 CGI 动作时被动捕获，无需手动触发。
- native 调用（task 构造、holder 读写、管理器下发）均用 SEH 包裹；发送前校验登录状态与管理器已捕获。
- 微信进程稳定，无崩溃。

## 8. 风险与当前边界

- 所有 RVA 与 vtable 槽位是微信版本私有实现；新版本必须重新定位 `sendappmsg` 提交原语、task ctor、holder 三件套和管理器下发槽位。
- vtable 覆盖 + 全量泄漏是刻意的稳定性策略：绝不把 native 对象交给异步序列化，也绝不跨分配器释放 task。
- 首次发送前必须让管理器被动捕获（本次登录手动发一次卡片），否则 `ret = -5`。
- 返回 `ret = 0` 代表服务器应答被接受，不承诺所有 appmsg 子类型（视频、文件、名片等）都可复用该链路。

## 9. 迁移到新版本的检查顺序

1. 用 IDA MCP 搜索 `/cgi-bin/micromsg-bin/sendappmsg` 字符串，定位提交原语（对应 F120）。
2. 重新确认 task ctor（cgi type/endpoint/inner request/response holder 偏移）与 task vtable 6 槽含义。
3. 重新定位 holder 三件套（write/size/data）RVA。
4. 在提交原语装被动观察 Hook，捕获活网络管理器与下发槽位（`manager->vtable[?]`）。
5. 先用文件传输助手做单目标卡片发送验证 `ret = 0`，再用真实好友回归。
6. 复核 `ResolveSelfWxid` 三级来源在新版本仍有效（self wxid 偏移、联系人库路径格式）。
