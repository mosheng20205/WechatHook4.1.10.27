已执行下一步。`SendMsgRequestNew` 的字段号与偏移已确认，业务名称可按以下高置信候选映射：

| 字段 | 对象偏移 | 候选含义                      |
| ---- | -------- | ----------------------------- |
| 1    | `+0x08`  | `MicroMsgRequestNew` 基础请求 |
| 2    | `+0x10`  | `ToUserName`，目标 wxid       |
| 3    | `+0x18`  | `Type`，文本通常为 `1`        |
| 4    | `+0x1C`  | `Scene`                       |
| 5    | `+0x28`  | `ClientMsgId`                 |
| 6    | `+0x20`  | `Content`，正文               |
| 7    | `+0x2C`  | `LocalId`                     |

该字段组合与公开 WebWeChat 发送消息结构中的 `ClientMsgId`、`Content`、`LocalId`、`ToUserName`、`Type` 一致，但这只能作为交叉验证，不能替代当前 4.1.10.27 的运行时验证。[参考结构](https://gist.github.com/MaskRay/3b5b3fcbccfcba3b8f29)

另外已校正之前的判断：`sub_182C6CF10` 仍是 `SendMsgRequestNew` 的解析器；它引用 `MicroMsgRequestNew` 虚表只是因为字段 1 是嵌套基础请求。

目前还没有修改源码或真实发送。下一步应验证对象序列化结果，确认 `+0x10` 和 `+0x20` 分别确实是目标 wxid 与正文，然后再实现安全发送封装。


已执行下一步分析，结论如下：

- `SendMsgRequestNew` 是外层包装对象，真正的消息元素位于其字段 2 的 `MicroMsgRequestNew` 向量中。
- 已确认 `MicroMsgRequestNew` 序列化字段：

| 偏移 | Protobuf 字段 | 类型 | 业务候选 |
|---|---:|---|---|
| `+0x08` | 1 | 字符串 | 发送方/基础标识 |
| `+0x10` | 2 | 字符串 | 目标 wxid（高置信候选） |
| `+0x18` | 3 | 整数 | 消息类型，文本通常为 `1` |
| `+0x1C` | 4 | 整数 | 场景 |
| `+0x20` | 6 | 字符串 | 正文 Content（高置信候选） |
| `+0x28` | 5 | 整数 | ClientMsgId |
| `+0x2C` | 7 | 整数 | LocalId/消息 ID |

关键证据：

- `sub_182C6CA10` 明确把 `+0x10` 序列化为字段 2，把 `+0x20` 序列化为字段 6。
- `sub_180E84AB0` 明确说明外层对象只负责包装嵌套消息列表。
- `sub_1836D3060` 负责发送到 `/cgi-bin/micromsg-bin/newsendmsg` 并进入 MARS 队列。

同时校正之前的误判：`sub_182C6CF10` 是 `SendMsgRequestNew` 解析器，不是 `MicroMsgRequestNew` 解析器；它调用后者是因为字段 2 是嵌套对象。

当前还未完成的是：从真实发送调用者或只读运行时观察中确认 `+0x10`、`+0x20` 的实际字符串值。因此本轮没有修改源码，也没有触发真实发送，避免误发或崩溃。当前微信状态接口仍显示 `IsLogin=1`，接收链路稳定，自动回复计数保持为 0。