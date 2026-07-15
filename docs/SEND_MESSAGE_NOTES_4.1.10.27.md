# 微信发送消息逆向与实现笔记（4.1.10.27）

> 适用目标：`Weixin.dll`，微信 `4.1.10.27`。本文件记录发送请求的结构观察、已确认的字段和自动回复封装规则。换版本时必须重新验证 RVA、vtable 和对象布局。

## 1. 发送请求链路

IDA MCP 追踪到的主要关系：

```text
sub_1836D3060
  -> 构造 /cgi-bin/micromsg-bin/newsendmsg 请求
  -> sub_182C6D230（外层 SendMsgRequestNew 容器）
  -> sub_182C6CDA0 / sub_182C72DE0（重复字段和元素复制）
  -> MARS 队列桥接
```

- `sub_182C6D230` 是外层请求容器的复制/解析入口，不能把它的 `+0x10`、`+0x20` 直接当作目标 wxid 或正文。
- `sub_182C6CF10` 是 `SendMsgRequestNew` 相关解析器；它不是 `MicroMsgRequestNew` 解析器。字段 2 为嵌套对象时，会继续调用后者，这是之前分析中的一个容易混淆点。
- `sub_1836D3060` 负责把请求送入后续 MARS 队列；观察阶段不得主动调用该函数。

## 2. 已确认的单条消息元素

`sub_182C72DE0` 遍历重复消息元素，并为每个元素分配 56 字节对象，使用 vtable `off_1887A8038`，随后调用：

```text
sub_182C6C060(destination, source, arena)
```

`sub_182C6C060` 是单条消息元素复制边界。源对象的 flags 位于 `source + 0x34`，当前版本已确认：

| flags | 元素字段 | 含义 | 当前读取位置 |
| ---: | ---: | --- | ---: |
| `0x01` | 字段 1 | 目标联系人嵌套字符串对象 | `source + 0x08`，再进入 wrapper/native string |
| `0x02` | 字段 2 | 文本正文 | `source + 0x10` |
| `0x20` | 字段 6 | msgsource XML | `source + 0x20` |

字段 1 的 wrapper 由 `sub_1805D3710` 处理：wrapper `+0x14` 是存在性/has 标志，native string 对象位于 wrapper `+0x08`。读取 `filehelper` 的运行时观察证明该字段路径有效。

## 3. 运行时观察结果

在 `Weixin.dll + 0x2C6C060` 安装只读观察 Hook 后，向文件传输助手发送普通文本得到：

- 目标 wxid：`filehelper`
- 正文：测试文本（例如 `你好8765`）
- msgsource：位于字段 6 的 XML 元数据
- vtable/flags 校验通过，字段读取计数正常增加
- 观察 Hook 只复制字符串和计数，不调用发送函数，因此不会产生重入发送或误发

这证明目标 wxid 和正文应从“单条元素”读取，而不是从外层 `sub_182C6D230` 的固定偏移读取。

## 4. 自动回复封装

当前接收链路解析出消息后，先进入分类器，再进入异步队列：

```text
接收 Hook
  -> 复制 from/to/content
  -> friend/group/self 分类
  -> 通过校验后入队
  -> 独立线程延迟约 300 ms
  -> WeixinSend::SendText(target_wxid, reply)
```

- 好友消息使用发送者 wxid 作为 `target_wxid`。
- 群聊使用 room wxid（包含 `@chatroom`）作为目标，但默认不入队，`AutoReplyGroupEnabled = 0`。
- 自身 wxid 命中时直接跳过，防止自发消息形成回复循环。
- 队列检查登录状态、wxid 格式、正文非空，并对相同 `wxid + 正文` 做去重。
- 回复前缀当前使用 ASCII 字符串 `[auto-reply] `，避免 DLL 源文件代码页造成乱码。
- 接收 Hook 线程不得直接调用 `WeixinSend::SendText`；必须复制必要字段后异步发送。

## 5. 风险与当前边界

- 发送函数和所有 RVA 都是微信版本私有实现；新版本必须重新定位 `newsendmsg`、元素复制边界和 MARS 桥接。
- 即使字段读取稳定，也不能仅凭静态反编译就断言发送调用安全；应先用观察 Hook 验证目标 wxid、正文和 flags，再进行最小范围真实发送测试。
- 群聊默认关闭自动回复是刻意的安全策略；启用前应明确确认 room wxid、回复频率、去重和失败重试策略。
- 当前文档记录的是目标/正文字段和队列封装，未承诺所有消息类型（图片、文件、引用、系统消息）都可复用普通文本发送接口。
- 微信重启后必须重新加载 DLL；登录状态变化后必须重新验证目标对象是否仍有效。

## 6. 迁移到新版本的检查顺序

1. 用 IDA MCP 搜索 `newsendmsg` 字符串和请求构造调用者。
2. 重新确认外层请求、重复元素和单条元素复制函数的调用关系。
3. 动态只读观察目标 wxid、正文、flags 和 vtable；不要先启用真实发送。
4. 用文件传输助手做单目标文本测试，再用一个好友做真实发送测试。
5. 最后接入自动回复，并分别验证好友、群聊、自身消息、未登录、退出登录和微信重启场景。
