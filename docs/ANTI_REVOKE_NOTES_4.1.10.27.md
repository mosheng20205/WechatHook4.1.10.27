# 微信防撤回 + 撤回灰条提示逆向与实现笔记（4.1.10.27）

> 适用目标：`Weixin.dll`，微信 `4.1.10.27`，IDA imagebase `0x180000000`（RVA = 绝对地址 − imagebase）。本文件记录「真·防撤回」（撤回后文本与图片消息仍可见）与「撤回灰条提示」（额外显示`「xxx 撤回了一条消息」`）两项功能的逆向结论、补丁点、注入方式、返回值消费修正与运行时约束。换版本时必须重新验证所有 RVA、字段偏移与字节形态。对应实现见 [`src/inline_weixin_dll_load.cpp`](../src/inline_weixin_dll_load.cpp)（`Hook_SysMsgParser`、`AntiRevoke_Enable/Disable`）与 [`src/wx_send.cpp`](../src/wx_send.cpp)（`WeixinSend::InsertLocalSysTip`）。

## 1. 功能总览

| 能力 | 效果 | 开关 | 默认 | 验证状态 |
| --- | --- | --- | --- | --- |
| 真·防撤回 | 撤回后原消息（文本 **AND** 图片）仍留在会话可见 | `POST /AntiRevoke/config` | OFF | 已真机验证 |
| 撤回灰条提示 | 保留原消息的同时，额外插入`「xxx 撤回了一条消息」`本地灰条 | `POST /RevokeTip/config` | OFF | 已真机验证（灰条可见） |
| 原始 XML 消费修正 | 消除防撤回副作用导致的原始 `<sysmsg>` XML 泄漏到「微信用户」会话 | 随 `/AntiRevoke/config` 生效 | 随防撤回 | 已实现并部署 |

三项均只在 `/AntiRevoke/config` 开启时生效；灰条提示还需额外开启 `/RevokeTip/config`。

## 2. sysmsg 分发器 sub_1822D07C0（核心 Hook 点）

撤回通知与其他所有 `<sysmsg type=...>` 子类型都经由同一入口 `sub_1822D07C0`（RVA `0x22D07C0`）解析。项目以 `Hook_SysMsgParser` Hook 它，先透传原函数，再读取解析结果。

已验证字段偏移（相对解析出的消息对象 `object`，即第一个参数）：

| 偏移 | 字段 | 说明 |
| --- | --- | --- |
| `object + 0x1A0` | sysmsg type | 撤回时为 `"revokemsg"`，作为唯一识别依据 |
| `object + 0x1D0` | content / replacemsg | 撤回提示文本载体 |
| `object + 0x1F0` | session | 群撤回时的 `xxx@chatroom` |
| `object + 0x1C8` | newmsgid | Format 2（session 变体）填充 |
| `object + 0x2B0` | revoketime | Format 1（revoketime 变体）填充的 unix 秒 |
| `node - 0x128` | talker | 调用者 `sub_1822D0540` 剥去同步信封 `wxid:\n` 前缀后写入；防撤回补丁不影响它 |

- 撤回识别：`strcmp(type@object+0x1A0, "revokemsg") == 0`。
- **返回值语义（关键）**：`1 = 已消费/handled`（调用者不再显示），`0 = 未处理`（调用者把原始 XML 当消息显示）。
- 第三个参数 `flag` 实为调用者栈上的 `&out-byte`（`&v29`）；当返回 1 且该字节非 0 时，调用者仍会走回退显示路径。

## 3. 真·防撤回：jz 字节补丁

补丁点 `sub_1822D07C0 + 0x227`（== `module + 0x22D09E7`，`g_Patch_Revoke`）：

- 原始字节 `0F 84 xx xx xx xx` = `jz loc_1822D0B08`，位于 `sub_1809F05E0(a1+416)` 判定「是否撤回 sysmsg 家族」之后。
- 补丁把前两字节改写为 `90 E9` = `nop; jmp loc_1822D0B08`，即**无条件跳过撤回-应用分支**，使微信不再从 UI/存储移除被撤回的消息（文本与图片一致生效）。
- `AntiRevoke_Enable()` 仅当目标是预期的 `0F 84`（或已是本补丁 `90 E9`）时才改写，绝不盲目覆盖偏移漂移后的未知字节；`AntiRevoke_Disable()` 还原保存的原字节。补丁可逆、字节级校验。

## 4. 撤回灰条提示（方案 B：本地系统消息注入）

用微信原生本地系统消息插入原语，在保留原消息的同一会话追加一条灰条。

- 原语 `sub_184C280B0`（RVA `0x4C280B0`，`offset::revoke_tip_insert`），签名 `(a1_unused, WeixinString* talker, WeixinString* content)`。
- 原语内部把 `content` 包成 `<sysmsg type="paymsg"><content><![CDATA[...]]></content></sysmsg>`，构造 728 字节、type=10000 的本地消息对象，经 `sub_180A1AB20` 设 talker、`sub_186845F8C`(RTDynamicCast) 取会话管理器、`sub_18064AA70` 取会话对象，最后 `sub_18173DA00(conv, msgObj)` 插入。无网络 I/O。
- 封装为 `WeixinSend::InsertLocalSysTip(chat, notice)`，SEH 包裹；两个 `WeixinString` 堆缓冲区**故意泄漏**（撤回罕见，且释放原生复制路径可能仍引用的缓冲区有 fault 风险）。

### 4.1 线程亲和性（关键坑）

- **必须在 Hook 自己的消息处理线程同步调用**。原函数此时已返回、无中途重入，且该线程刚成功保留了撤回气泡，会话/UI 对象的线程亲和正确。
- 早期用 detached `std::thread` 从**错误线程**触碰会话/UI 对象，实测被 SEH 挡下、灰条不显示（`RevokeTipInjectFail` 全增）。改同步调用后 `RevokeTipInjectOk` 正常增长、灰条可见。

### 4.2 灰条文本清洗

- `content@object+0x1D0` 常常是整段 `<sysmsg type="revokemsg">...</sysmsg>` 信封而非纯文本；直接塞进 CDATA 会渲染成乱码。
- 注入前从 `<replacemsg>`/`<content>` 提取内层纯文本；都取不到时回退固定文案`「对方撤回了一条消息」`。

## 5. 原始 XML 消费修正（防撤回副作用）

### 5.1 泄漏根因

`sub_1822D07C0` 的唯一代码调用者 `sub_1822D0540`（调用点 `0x1822D0740`）尾部逻辑：

```c
LOBYTE(v29) = 0;
if ( !parser(a1, v5, &v29) )   // 返回 0（未处理）
    return sub_1822D1640(...); // 回退：把原始 sysmsg XML 当消息显示
result = 1;
if ( (_BYTE)v29 )              // 返回 1 但 out-byte 非 0
    return sub_1822D1640(...); // 同样回退显示
return result;                 // 返回 1 且 out-byte 为 0 → 不显示
```

`sub_1822D1640`（RVA `0x22D1640`）会把原始 sysmsg 串复制进四个消息字段（`sub_1822DCF40/DE130/DF210/DFC00`）并经 `sub_1822E15B0` 派发——即「把未消费的 sysmsg 变成一条可见消息」的回退路径。

防撤回 jz 补丁跳过了整个撤回块，使解析器返回 `0（未处理）`，调用者遂走 `sub_1822D1640`，把原始 `<sysmsg type="revokemsg">` XML 当普通消息插入会话；当撤回者是陌生群友时，会归到临时的「微信用户」P2P 会话，形成可见的 XML 泄漏。

### 5.2 修正方式

在 `Hook_SysMsgParser` 中，当 `g_AntiRevokeEnabled` 且识别到 `revokemsg` 时：

- 清零调用者 out-byte：`*(uint8_t*)flag = 0;`
- 覆盖返回值为 `1（已处理）`。

这等同原版微信对 revokemsg 的消费行为（返回 1 + out-byte 为 0，不走 `sub_1822D1640`），**只改变「是否把该 sysmsg 当消息显示」的决策**，不触碰已被 jz 补丁保留的原消息气泡（气泡去留由第 3 节的字节补丁独立决定）。计数器 `g_RevokeConsumeOverrides` 记录每次覆盖。

## 6. 登录重放去重

- 撤回可能在登录/同步时被重放，产生重复 webhook。以稳定 key 去重：Format 2 用真实 `newmsgid`；Format 1 无 `newmsgid`，用 `revoketime << 32 ^ FNV(talker+tip)` 合成。
- 新 key 触发 webhook 并 `RevokeDistinctCount++`；重复 key `RevokeSuppressedCount++` 并抑制。

## 7. HTTP 接口

```http
GET  http://127.0.0.1:30001/AntiRevoke/config      -> {"enabled":bool,"ret":0}
POST http://127.0.0.1:30001/AntiRevoke/config       body {"enabled":true|false}
GET  http://127.0.0.1:30001/RevokeTip/config        -> {"enabled":bool,"ret":0}
POST http://127.0.0.1:30001/RevokeTip/config        body {"enabled":true|false}
```

- `POST /AntiRevoke/config` 返回 `ret = 0` 成功；`ret = -1` 表示补丁点不在预期字节形态（模块未加载或偏移漂移）。
- `POST /RevokeTip/config` 需先开启 `/AntiRevoke/config` 才有可注解的保留撤回，否则返回提示 `msg`。
- 请求体字段名为 `enabled`（非 `enable`）。

诊断计数（`/QueryDB/status`）：`AntiRevokeEnabled`、`RevokeTipInjectEnabled`、`RevokeTipInjectCalls`、`RevokeTipInjectOk`、`RevokeTipInjectFail`、`RevokeConsumeOverrides`、`RevokeDistinctCount`、`RevokeSuppressedCount`、`SysMsgParserCalls`。

## 8. 运行时验证结果

- 另一账号向登录账号发单聊 + 群聊消息后撤回：原消息（文本与图片）在会话中保持可见，未被移除。
- 开启 `/RevokeTip/config` 后，单聊与群聊会话均显示`「莫生 撤回了一条消息」`灰条（`RevokeTipInjectOk` 增长）。
- native 注入调用 SEH 包裹；灰条在 Hook 消息处理线程同步插入，线程亲和正确，微信进程稳定（实测工作集约 261 MB），无崩溃。
- 原始 XML 消费修正已实现并部署，配合防撤回消除「微信用户」原始 XML 泄漏；以 `RevokeConsumeOverrides` 计数与会话内无原始 XML 为判据复核。

## 9. 风险与当前边界

- 补丁点 `0x22D09E7`、字段偏移、灰条注入链路 RVA 均为微信版本私有实现，新版本必须重新逆向定位与字节校验。
- 两项功能默认关闭、运行时开关门控；防撤回补丁字节级可逆。
- 注入必须在 Hook 线程同步进行，禁止 detached worker 触碰会话/UI 对象。
- 灰条原语硬编码 `sysmsg type="paymsg"`，正文以 CDATA 承载纯文本；勿把整段 XML 信封塞入。
- 接收/解析 Hook 内不得重入发送函数；返回值覆盖仅在防撤回开启且确为 `revokemsg` 时生效。

## 10. 迁移到新版本的检查顺序

1. 用 IDA MCP 定位 sysmsg 分发器（对应 `sub_1822D07C0`），确认撤回子类型判定分支与其后的条件跳转。
2. 重新确认解析对象字段偏移（type/content/session/newmsgid/revoketime）与 talker 来源（`node - 0x128`）。
3. 重新定位并字节校验防撤回 jz 补丁点，确认 `0F 84`→`90 E9` 仍跳过撤回-应用分支。
4. 反编译调用者，复核返回值/out-byte 与回退显示函数（对应 `sub_1822D1640`）的关系，确认消费修正仍有效。
5. 重新定位本地系统消息插入原语（对应 `sub_184C280B0`）与其会话管理器/插入子调用链。
6. 先用文件传输助手/单聊验证原消息保留 + 灰条显示，再用群聊回归，确认无原始 XML 泄漏、进程稳定。
