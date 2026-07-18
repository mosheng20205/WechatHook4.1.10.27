# 微信图片（.dat）解密逆向与实现笔记（4.1.10.27）

> 适用目标：`Weixin.dll`，微信 `4.1.10.27`。本文件记录 `/Decode_Pic` 自实现 WeChat 4.0 `"\x07\x08V2"` `.dat` 图片解密的格式、算法、双密钥运行时派生与真机验证结论。换版本时必须重新验证派生函数 RVA 与文件头字段布局。对应实现见 [`src/wx_send.cpp`](../src/wx_send.cpp) 的 `WeixinSend::DecodePic`。

## 1. 为什么自实现而不调 native 解码器

native 图片解码分发链（`dec_pic_wrapper = 0x496E30` → `dec_pic_call = 0x493E70` → `sub_1809BA960` thunk → `sub_1809BA970` 核心编解码器）在从 HTTP 线程调用时始终返回 `-3`（缺少微信内部调用上下文/线程亲和）。

因此改为**在本 DLL 内独立复刻 V2 解密算法**，只复用微信的运行时密钥派生。native 解码器留作偏移参考（`sub_1809BA970` 是编码器，交叉印证了文件布局：写 `07 08 56 32` magic 头、AES 明文长、XOR 区长；`v10==2` 为纯 XOR 格式，`v10!=2` 为 AES+XOR 格式）。

## 2. 已确认的 V2 加密文件格式

15 字节头（小端）：

| 偏移 | 长度 | 含义 |
| ---: | ---: | --- |
| `[0..3]` | 4 | magic `07 08 56 3x`（`0x31`='1'=V1，`0x32`='2'=V2） |
| `[4..5]` | 2 | `07 08`（常量） |
| `[6..9]` | 4 | `u32 aesPlainLen`：AES-128-ECB 区的明文长度 |
| `[10..13]` | 4 | `u32 xorLen`：尾部单字节 XOR 区长度 |
| `[14]` | 1 | flag（`0x01`） |

文件体布局：`[15字节头][AES-128-ECB 密文][未加密中间段][XOR 区]`。计算式：

```text
aesEncLen = fileLen - 15 - xorLen              (16 的倍数，含 PKCS7 整块填充)
middleLen = fileLen - 15 - aesEncLen - xorLen  (通常 = 0，仅原图 > 1KB+1MB 时存在)
```

## 3. 算法与双密钥运行时派生

两把密钥均**运行时从微信账号上下文派生**（无硬编码），镜像 native 编码器 `sub_1809BA970`：

| 密钥 | 派生函数（RVA） | 取值方式 |
| --- | --- | --- |
| AES-128 key | `img_key_derive`（`sub_1809B1FD0`，`0x9B1FD0`） | `sub_1809B1FD0(std::string* out, 2)` 返回的 32 字符派生字符串的**前 16 个 ASCII 字节** |
| XOR key | `img_xor_key`（`sub_1809B1F20`，`0x9B1F20`） | 无参调用，返回值的**低 8 位** |

本次登录会话实测：派生字符串 `"2408dd3972892d04486e13452db0af28"`，AES-128 key = `"2408dd3972892d04"`（ASCII 字节），XOR key = `0x21`。

解密流程：

1. `AES-128-ECB`（BCrypt：`BCryptOpenAlgorithmProvider(AES)` + `BCryptSetProperty(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB)` + `BCryptGenerateSymmetricKey` + `BCryptDecrypt`，**不设 padding flag，逐块解密**）解 `file[15 : 15+aesEncLen]`。
2. 拼接输出：`[AES 明文前 aesPlainLen 字节][未加密中间段 middleLen][XOR 区逐字节 ^ xorkey]`。

## 4. SEH 隔离与实现约束

- 两个 native 派生调用（`DeriveImageAesKey` / `DeriveImageXorKey`）用 `__try/__except` 包裹，且**内部不含任何需要展开的 C++ 对象**（避免 C2712）。
- `DeriveImageAesKey` 派生出的 `std::string` 小堆缓冲**故意泄漏**（用我方分配器释放会 fault）；`DecodePic` 由用户触发，单次泄漏可忽略。
- `DecodePic` 主体本身不含 `__try`（SEH 隔离在 helper 内），因此可安全使用 `std::vector` / `std::wstring`。
- 文件读取上限 200MB；输出用 `CREATE_ALWAYS` 截断写入。
- 头部校验失败（非 `07 08 56`）返回 decode failed；`15 + xorLen > fileLen` 或 AES 区非 16 对齐直接失败。

## 5. HTTP 接口与返回值

`POST /Decode_Pic` 请求体：

```json
{ "src_path": "C:\\...\\xxx.dat", "dst_path": "C:\\...\\out.jpg", "mode": 1, "wide": true }
```

返回值语义：

- `ret = -1`：参数错误或文件错误（路径空/超长/含 `\0`、文件不存在、0 字节空文件）。
- `ret = -3`：decode failed（非加密文件、头部校验不过、AES 区不对齐、密钥派生失败）。
- `ret = 0`：成功，`dst_path` 写出解密后的图片。

## 6. 真机端到端验证结论

自实现 V2 解密已在真实微信进程（`4.1.10.27`，已登录）验证：

- **用例1**（全尺寸图 `5881363e...dat`，918968B）：`ret = 0`，输出 918937B，magic `FF D8 FF E0 ... 4A 46 49 46`、结尾 `FF D9`（标准 JPEG，可打开），与离线 .NET AES 逐字节重建结果完全一致。
- **用例2**（`67ea5ceb...dat`，58542B）：`ret = 0`，输出 58511B，magic `77 78 67 66`（`"wxgf"`，微信专有封装图片格式）——解密结构完全一致（aesLen=1024/xorLen=57487/16 对齐），该图原本即以 wxgf 存储；wxgf→标准图的转码属另一独立功能。
- **异常用例**：不存在路径 `ret = -1`、0 字节空文件 `ret = -1`、非加密普通文本 `ret = -3`。
- 每次调用后微信 5 进程存活、`IsLogin = 1`、主进程工作集稳定约 253MB，无崩溃或异常内存增长。

## 7. 风险与当前边界

- 密钥派生 RVA（`0x9B1FD0` / `0x9B1F20`）是微信版本私有实现；新版本必须重新定位这两个函数并确认返回结构（`std::string` ABI：size@+0x10，size>=16 时 +0x00 为堆指针）。
- 派生密钥依赖**已登录的账号上下文**；未登录或账号切换后需重新派生。
- 解密输出未必是裸 JPEG：若原图以 wxgf 存储，输出即为 wxgf 封装，需另行转码。
- native 解码器分发链仅作偏移参考，当前实现不依赖其成功返回。

## 8. 迁移到新版本的检查顺序

1. 用 IDA MCP 定位图片编码器（写 `07 08 56 3x` magic、AES 明文长、XOR 区长的函数），交叉印证文件布局是否仍为 `[15头][AES-ECB][中间段][XOR]`。
2. 从编码器回溯 AES key 派生（`sub_1809B1FD0` 平行）与 XOR key 派生（`sub_1809B1F20` 平行）函数，确认签名与返回结构。
3. 先离线用一张已知 `.dat` + 派生出的密钥做 .NET/Python AES 重建，确认算法钉死。
4. 再在 DLL 内接入 BCrypt 实现，用同一张 `.dat` 真机验证 `ret = 0` 且输出 magic 有效。
5. 补异常用例（不存在/空文件/非加密文件）确认安全返回错误码且进程稳定。
