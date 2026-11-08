# RustBinary

RustBinary 是基于 [nextjson](https://crates.io/crates/nextjson) 的二进制编解码库，
提供自描述与 schema 引导的格式、解析限制、可选压缩、认证帧和 Merkle 证明。
核心使用 `no_std` + `alloc`；默认启用的 `std` feature 提供 I/O 与平台能力。
声明的最低 Rust 版本为 1.78，CI 配置包含相应验证任务。

解析限制不等于进程内存沙箱。具体边界与升级说明见[安全契约](docs/security-contract.md)。

## 格式身份

流线格式是**带类型标签的自描述字节流**：每个值前有一字节类型标签，数组与对象以 `0xff`
终结。这就是动态流的格式身份。它不是 bincode 式的紧凑布局，也不是 CBOR 式的长度前缀布局，
也不会悄悄变成这两种中的任何一种。

对静态类型，本库还提供**schema 引导的 compact 简档**（`Config::with_compact_format()` +
`CompactBinary` 派生宏）。它是第二种、且是**追加式**的线格式，不是带标签流的某个模式：
不写逐值类型标签、不写字段名、容器用长度前缀，字节串与浮点数组走 memcpy / 批量端序
快速路径。`Value`、无标签枚举与 `FormatEncoder` 驱动的类型留在自描述流上；静态热路径
可以走 compact 简档。两者永远不会改变彼此的字节。

自描述流支持动态值、无标签枚举和借用字符串。`&str` 直接指向输入 frame；每个标量
携带类型标签，因此数值数组会比 schema 引导的表示占用更多空间。两端共享静态 schema
时，可以选择 compact 简档。

自描述与 CBOR 简档采用 nextjson 的 null 选项表示：`Some(())`、`Some(None)` 等
内容为 null 的值无法与 `None` 区分。需要保留这一区别时，使用带显式选项标签的
compact 简档。自定义序列化形状属于应用自己的线格式契约。

`archive` 特性**不是第二种流格式**。它是独立的存储格式——库内自研、根在前的相对指针
编解码器 + RustBinary 信封——用于只读内存映射对象存储，并独立版本化（`RBARC004`）。
流编解码器从不做内存强转、从不产生相对指针、也从不因为某个 Cargo feature 改变自己的
行为。

## 依赖策略

运行时依赖 nextjson 0.1.5，derive 支持另需过程宏依赖。工作区使用本地
`rustbinary-derive`，确保测试覆盖正在修改的宏代码。nextjson 0.1.5 已移除 `std`
feature 和标准库 `HashMap` 的直接实现；可迁移到 `BTreeMap`，或通过应用自己的
newtype 实现 nextjson trait。

BLAKE3、XChaCha20-Poly1305、系统随机数、密钥擦除、LZ77 和 mmap 均由本仓库维护。
减少依赖意味着本项目承担更多实现审查、平台验证和维护责任。库内 LZ77 是
RustBinary 自有格式，与 Zstandard 不兼容，不承诺压缩率、速度、字典能力或生态等价。

密码测试覆盖 RFC 8439 的 ChaCha20/Poly1305 示例、XChaCha20-Poly1305 草案向量，
以及 BLAKE3 上游非密钥模式的 256 位输出向量。[安全契约](docs/security-contract.md#test-evidence)
记录来源与范围。加密管线 golden fixture 只证明该固定样本仍可解码；历史生成器
未被记录，不能据此宣称与旧第三方管线全面逐字节兼容。项目不宣称已完成独立实现级安全审计。

## 分层

| 层          | 模块                   | 默认启用 | 职责                                                                 |
| ----------- | ---------------------- | -------- | -------------------------------------------------------------------- |
| **Core**    | `rustbinary::core`     | 是       | 紧凑编解码、资源上限、尾随策略、调用方缓冲区；始终 `no_std`          |
| **Protocol**| `rustbinary::protocol` | 否       | Schema 演进、指纹、反射、静态上界、位打包                           |
| **Pipeline**| `rustbinary::pipeline` | 否       | CBOR、压缩、加密、有序并行批处理（`std`）                           |
| **Sync**    | `sync`                 | 否       | rANS 熵编码、差分帧、IBLT 集合协调、信任演算                        |
| **Archive** | `rustbinary::archive`  | 否       | Merkle 校验的只读内存映射对象存储                                   |
| **Projection**| `rustbinary::projection`| 否     | 可投影自认证记录，具备投影健全性                                     |

[English](README.md)

## 特性

| 能力                    | 状态       | 说明                                                                        |
| ----------------------- | ---------- | --------------------------------------------------------------------------- |
| nextjson 二进制编解码   | 已实现     | 严格 marker-varint 模式与固定宽度 legacy 模式                               |
| 整数/字符串自适应编码   | 已实现     | 按值选宽度、ZigZag 有符号数、ASCII7 打包                                    |
| `i64` 集合自适应编码    | 已实现     | raw / delta / run-length 三种 frame                                         |
| rANS 熵编码             | 已实现     | 自研静态模型编码器；无哈希重放校验                                          |
| SIMD                    | 仅热路径   | 运行时 AVX2/SSE2/NEON，标量回退；AVX-512/SVE/SME 只探测不使用               |
| 零分配编解码路径        | 已实现     | 精确长度输出与调用方缓冲区                                                   |
| 借用式零复制反序列化    | 已实现     | 嵌套 `&str` 字段直接指向输入 frame                                          |
| 位打包                  | 已实现     | `BitPacked` derive、宽度检查、规范零 padding                                |
| Schema 指纹             | 已实现     | 结构哈希，包含编解码配置（FNV-1a，**非**密码学）                             |
| 编译期内存上界          | 已实现     | `StaticSize::{MAX_SIZE, PACKED_MAX_BITS, PACKED_MAX_SIZE}`                  |
| RFC 8949 CBOR           | 已实现     | 自研流式 CBOR 编解码（无值树）；可选 稳定 map 排序                     |
| Schema 演进             | 已实现     | 稳定字段 ID、版本、默认值、跳过未知字段                                     |
| 压缩                    | 已实现     | 自适应 Zstandard；压缩后更大则保留原文                                      |
| 加密                    | 已实现     | XChaCha20-Poly1305、随机 192-bit nonce、认证 header                         |
| 并行序列化              | 已实现     | 有序 batch frame，输出与调度无关                                            |
| 运行时反射              | 已实现     | 编译期生成、无分配的静态元数据（`Reflect`），含逐字段符号表                  |
| 差分帧                  | 已实现     | 基准相对整数差分 + 确定性 HPACK 式动态表                                    |
| IBLT 集合协调           | 已实现     | 自研可逆布隆查找表（Goodrich 与 Mitzenmacher）                              |
| 信任演算                | 已实现     | 类型级认证状态机；未认证接收在类型层面不可表达                              |
| Merkle 归档             | 已实现     | 库内 BLAKE3 树，O(log n) 证明，仅信封打开                                |
| 可投影自认证记录        | 已实现     | 可信根成员证明、精确查询检查、schema 版本绑定                   |
| 资源有界解码            | 已实现     | 解析计数与 schema 估算，不提供堆分配硬上限      |
| 可配置深度上限          | 已实现     | `Config::with_depth_limit` 在编码与解码两侧限制嵌套深度                     |
| 形式化验证              | Kani harness | varint/ZigZag 核心 + 投影树几何 + 预算极限代数                              |
| `no_std` 优先               | 已实现     | crate 无条件 `no_std` + `alloc`；`std` 是可选 feature                  |
| `no_std` 各层              | 已实现     | compact、adaptive、entropy、reconcile、evolution、projection、bounded、probe、CBOR、trust 演算均可不带 `std` 构建 |

## 安装

```toml
[dependencies]
rustbinary = "0.1"
# nextjson 钉到精确的 codec 目标：0.1.5 在编码与解码两侧拒绝非有限浮点，
# RustBinary 继承该契约。
nextjson = { version = "0.1.5", features = ["derive"] }
```

按需启用：

```toml
rustbinary = { version = "0.1", features = ["protocol"] }   # 整个 Protocol 层
rustbinary = { version = "0.1", features = ["sync"] }       # 熵 + 集合协调 + 信任
rustbinary = { version = "0.1", features = ["archive"] }    # Merkle mmap 归档
```

`no_std` 目标关闭 `std` 并按需启用各层——核心、Protocol 以及所有自研 feature 均可不带 `std` 构建：

```toml
rustbinary = { version = "0.1", default-features = false, features = ["compact"] }
```

全部是纯 Rust，无 C 构建步骤，运行时依赖图恰好是 nextjson 加库内派生 crate（见依赖
策略）。

### 特性矩阵

| Feature            | 默认 | 用途                                                                        |
| ------------------ | ---- | --------------------------------------------------------------------------- |
| `std`              | 是   | I/O 适配器与仅 std 的转换层（archive、compression、encryption、parallel、SIMD、trust 会话）；自描述核心始终 `no_std` |
| `protocol`         | 否   | 聚合：adaptive, bit-packing, derive, fingerprint, reflection, schema-evolution, static-size |
| `pipeline`         | 否   | 聚合：cbor, compression, encryption, parallel                               |
| `sync`             | 否   | 聚合：entropy, reconcile, trust                                             |
| `archive`          | 否   | Merkle 校验的 mmap 归档；库内 codec、mmap 与 BLAKE3；需要 `std` 与 `derive`  |
| `compact`          | 是   | schema 指导的紧凑简档运行时；隐含 `derive`（该简档通过 `CompactBinary` derive 使用） |
| `derive`           | 否   | 重导出过程宏及其运行时 feature；被 `compact` 与 `archive` 隐含                        |
| `fingerprint`      | 否   | 结构指纹运行时与 frame                                                      |
| `reflection`       | 否   | 无分配反射运行时                                                            |
| `static-size`      | 否   | 编译期上界运行时                                                            |
| `simd`             | 否   | 运行时探测与热路径分发；绝不改变线格式                                      |
| `bit-packing`      | 否   | 位级 trait 与调用方缓冲区 codec                                             |
| `adaptive`         | 否   | 调用方缓冲的自适应字符串/集合；隐含 `bit-packing`                          |
| `entropy`          | 否   | 静态模型 rANS 熵编码；隐含 `reflection`                                     |
| `reconcile`        | 否   | 差分帧（`delta`）与 IBLT（`ibl`）                                          |
| `trust`            | 否   | 类型级信任演算与会话状态机                                                  |
| `cbor`             | 否   | 经 nextjson 中继的 RFC 8949 CBOR                                           |
| `compression`      | 否   | 库内 LZ77 frame                                                            |
| `encryption`       | 否   | XChaCha20-Poly1305、OS 随机、zeroize 密钥                                   |
| `parallel`         | 否   | scoped 线程有序 batch frame                                                 |
| `schema-evolution` | 否   | 稳定字段 ID 版本化 frame                                                    |
| `bounded`          | 否   | `DecodeBounded` 成本代数（B/A/D/W）、`Budget`、`decode_bounded`；`no_std`，需要 `derive` |
| `projection`       | 否   | 可投影自认证记录与投影证明；`no_std`，库内 BLAKE3                          |

## 快速开始

```rust
use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Packet {
    sequence: u64,
    payload: Vec<u8>,
}

let config = rustbinary::options()
    .with_varint_encoding()
    .with_little_endian()
    .with_limit(8 * 1024 * 1024)
    .with_collection_limit(100_000)
    .reject_trailing_bytes();

let packet = Packet { sequence: 42, payload: vec![1, 2, 3] };
let bytes = config.serialize(&packet)?;
assert_eq!(config.deserialize::<Packet>(&bytes)?, packet);
# Ok::<(), rustbinary::Error>(())
```

`options()` 与顶层函数使用严格紧凑模式：小端、规范 marker-varint、ZigZag 有符号数、
64 MiB 字节上限、1,000,000 元素集合上限、拒绝尾随字节。`legacy_options()` 是旧的
无限定固定宽度模式，只适合可信的内存内数据——它被命名成这样就是让你注意到它。

### 配置链

改变格式的方法返回不同的包装类型，因此变换顺序在类型中可见：

```text
Config -> CborConfig -> CompressedConfig -> EncryptedConfig
```

```rust
let secure = rustbinary::options()
    .with_limit(16 * 1024 * 1024)
    .with_cbor_format()
    .with_deterministic_encoding()
    .with_compression(3)
    .with_compression_threshold(256)
    .with_encryption(rustbinary::EncryptionKey::new([0xA5; 32]));
# let value = vec![1u32, 2, 3];
let frame = secure.serialize(&value)?;
assert_eq!(secure.deserialize::<Vec<u32>>(&frame)?, value);
# Ok::<(), rustbinary::Error>(())
```

密钥必须来自真实的密钥管理系统；硬编码密钥只适合测试。

## 线格式

该格式编码的是值，不是 Rust 对象内存：没有 padding、原生指针、vtable 或 `repr(Rust)`
布局。

| nextjson 值             | 线表示                                                    |
| ----------------------- | --------------------------------------------------------- |
| `null` / unit / `None`  | tag `0x00`                                                |
| `false` / `true`        | tags `0x01` / `0x02`                                      |
| `u64` / `u128`          | tags `0x03` / `0x04` + 无符号负载                         |
| `i64` / `i128`          | tags `0x05` / `0x06` + ZigZag 负载                        |
| `f64` / `f32`           | tags `0x07` / `0x08` + 配置端序下的 IEEE 754 位           |
| string / char           | tag `0x09` + 编码字节长度 + UTF-8                         |
| array                   | tag `0x0a` + 元素 + `0xff`                                |
| object                  | tag `0x0b` + (`字符串键` + 值) 对 + `0xff`                |

默认模式下整数与长度负载使用规范 marker-varint：

| Marker    | 负载     | 可接受的最小值           |
| --------- | -------- | ------------------------ |
| `0..=250` | 无       | 0                        |
| `251`     | 2 字节   | 251                      |
| `252`     | 4 字节   | 65,536                   |
| `253`     | 8 字节   | 4,294,967,296            |
| `254`     | 16 字节  | 18,446,744,073,709,551,616 |
| `255`     | 保留     | 永不接受                 |

解码器拒绝非最小形式、收窄溢出、畸形 UTF-8、非法标签、截断、越限与不允许的尾随
字节。varint 与 ZigZag 机制只存在于一处（`canonical`），编解码两侧共用，Kani harness 检查其
往返、有界与规范唯一性（见验证一节）。

## 零分配与零复制

`serialized_size` 用一次计数写入完成测量，不分配。`serialize_into_slice` 一次写入
调用方内存并返回精确初始化长度；slice 过小时 `Error::BufferTooSmall` 携带精确所需
大小。

Slice 反序列化把嵌套 `&str` 字段直接从输入借用：

```rust
use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(NsonSerialize, NsonDeserialize)]
struct View<'a> {
    name: &'a str,
    #[njson(borrow)]
    payload: &'a str,
}

let source = View { name: "edge", payload: "frame" };
let config = rustbinary::options().with_limit(4096);
let mut storage = vec![0; config.serialized_size(&source)? as usize];
let written = config.serialize_into_slice(&mut storage, &source)?;
let view: View<'_> = config.deserialize(&storage[..written])?;
assert_eq!(view.payload, "frame");
# Ok::<(), rustbinary::Error>(())
```

该路径上 codec 不分配；用户自定义的 nextjson 实现内部仍可能分配。基于 reader 的解码
要求 owned 目标；把引用返回到临时 reader 缓冲区内是不健全的。打包后的 ASCII7 字符串
展开为 owned 文本；原始自适应 UTF-8 可以 `Cow::Borrowed` 返回。

## 自适应编码

`with_adaptive_encoding()` 保持紧凑模式并增加显式的数据感知 API。frame 携带稳定策略
标签，解码器校验规范 varint、padding、长度、delta 溢出与 RLE 游程。

```rust
let adaptive = rustbinary::options()
    .with_limit(1 << 20)
    .with_adaptive_encoding();

let values = [1000, 1001, 1002, 1003];
let required = adaptive.encoded_i64_slice_size(&values)?;
let mut output = vec![0; required];
adaptive.encode_i64_slice_into_slice(&mut output, &values)?;
assert_eq!(adaptive.decode_i64_vec(&output)?, values);

let encoded = adaptive.encode_string("telemetry/primary")?;
assert_eq!(adaptive.decode_string(&encoded)?, "telemetry/primary");
# Ok::<(), rustbinary::Error>(())
```

字符串 frame 含策略字节、规范解码长度 varint 与负载。策略 0 是原始 UTF-8；策略 1 是
低位在前的 ASCII7 打包，仅当每个字节都是 ASCII 且打包形式严格更小时才选。`i64` 集合
比较三种完整编码——独立 ZigZag 值、首值 + 带检查差分、值/游程对——按文档规定的平局
顺序选严格最小者。

## rANS 熵编码

`with_entropy_encoding()` 启用 `entropy` 模块：自研 rANS 编码器（range Asymmetric
Numeral Systems；16 位重归一化；64 位状态），配以**由 `Reflect` schema 推导的静态模型**。
它不是 zstd 或任何东西的包装：无 C、不传输字典、`no_std` + `alloc`。

模型在不传输任何东西的情况下推导：

- `#[derive(Reflect)]` 逐字段记录精确符号表：枚举变体基数、`#[bits = N]` 范围、
  显式 `#[entropy(symbols = N)]`，或已知原语（`bool` 到 2、`u8`/`i8` 到 256）。
- `Model::from_uniform` 在该精确符号表上建立均匀先验；`Model::from_weights` 从应用
  权重建立静态先验。
- `SchemaModel::from_reflect` 遍历 shape，逐字段产出一个模型。两端编译同一类型，
  因此推导出同一张表；解码器除了它已有的 schema 之外不需要任何东西。

### 不使用哈希如何检测损坏

rANS replay 检查的是：解码结果使用同一模型重新编码后，是否与收到的帧一致。
它用于拒绝非规范表示。另一个合法码字可以解码成不同数据并通过 replay，因此不能
把它解释成认证，也不能声称具有已量化的随机损坏检出率。

raw fallback 只检查帧结构与长度；关闭 raw fallback 同样不能建立完整性边界。
应按威胁模型选择可信摘要、MAC、AEAD 或认证传输。默认开启 replay 会增加一次编码；
`without_replay_verification()` 中的 replay 指编码重放，不是协议防重放或消息新鲜性。

## 位打包

`BitPacked` 为有界字段派生位级 codec。`#[bits = N]` 字段用 `BitValue` 范围校验；其他
字段递归使用 `BitPack`。枚举标签用最小位宽并拒绝未知解码标签。

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Header {
    #[bits = 3]
    mode: u8,
    enabled: bool,
    #[bits = 7]
    delta: i16,
}

let config = rustbinary::options().with_bit_packing();
let header = Header { mode: 2, enabled: true, delta: -1 };
let packed = config.serialize(&header)?;
assert_eq!(config.deserialize::<Header>(&packed)?, header);
# Ok::<(), rustbinary::Error>(())
```

`BitWriter` 清空输出使末端 padding 为规范零；`BitReader` 拒绝非零 padding 与（配置时）
尾随字节。

## SIMD

`simd_backend()` 在运行时选择 AVX2、SSE2、NEON 或标量路径并缓存结果。自适应 ASCII
分类与单字节 varint 扫描使用这些内核。所有非对齐加载都由安全分发器做边界检查；
unsafe 代码局限于目标特定模块，crate 全局拒绝 `unsafe_op_in_unsafe_fn`。

AVX-512、SVE、SME 由 `hardware_capabilities()` 探测并报告，但没有任何内核使用它们；
更宽的向量对小型 codec 记录未必更快，这里也没有对应的硬件 CI 覆盖。

## 指纹、反射与静态上界

```rust
use rustbinary::StaticSize as _;

#[derive(
    NsonSerialize,
    NsonDeserialize,
    rustbinary::Fingerprint,
    rustbinary::Reflect,
    rustbinary::StaticSize,
)]
struct Header {
    enabled: bool,
    count: u16,
    coordinates: [i32; 2],
}

let config = rustbinary::options().with_fingerprint();
let value = Header { enabled: true, count: 7, coordinates: [2, 3] };
let frame = config.serialize(&value)?;
let _: Header = config.deserialize(&frame)?;
assert!(Header::MAX_SIZE >= frame.len() - 16);
# Ok::<(), rustbinary::Error>(())
```

- `Fingerprint` 对字段与变体名、声明类型、声明顺序、整数编码、有效端序、尾随策略、
  资源上限与 CBOR 确定性模式求哈希。它是基于 FNV-1a 的兼容性标识——**不是**密码学
  哈希，不能替代 AEAD、签名或授权。
- `StaticSize` 为静态类型提供最坏情况普通与位打包大小上界；动态集合刻意不实现它。
- `Reflect` 在编译期生成无分配元数据（类型名、字段、变体），无运行时注册表。每个
  `FieldInfo` 还携带字段符号表（`symbols`），供 rANS schema 模型消费。

## Schema 演进

`schema-evolution` 特性以稳定 schema ID、schema 版本、规范字段 ID 排序、长度分隔字段
与未知字段跳过为值加框。字段 ID 与 schema ID 是显式的协议决策，不是重构时会变化的
哈希。

frame 以 magic `RBE1`、格式版本、flags、schema ID、schema 版本、字段数与
`(field_id, payload)` 条目开头。编码器对 ID 排序并拒绝重复；解码器要求严格递增的 ID，
并在切片前校验全部长度运算。

应用规则：每个兼容类型族一个永久 schema ID；永不把字段 ID 复用于不同含义或不相容的
类型；重命名 Rust 字段时保留 ID；为向后兼容添加可选或默认字段；用编码版本表达刻意的
语义迁移；需要转发或保留时检查未知字段。

## 可投影自认证记录（投影健全性）

投影证明将披露字段的字节绑定到外部可信的 Merkle 根。
`verify(proof, anchor, schema_version)` 验证证明自带字段的成员资格；新增的
`verify_query(proof, anchor, schema_version, query)` 还要求返回字段与调用方查询完全一致，
缺少或多出字段均拒绝。当前格式不提供字段不存在的证明。
`verify_untrusted` 只检查内部一致性，发送者可以同时替换内容和根。

论证依赖 BLAKE3 抗碰撞性、可信根来源与规范源记录，不能把哈希当成数学上的单射。
部分证明既不读取，也不担保另一个文件中未披露字段的当前状态；不透明负载的语义和
应用 schema 约束仍由应用验证。

n 个字段中披露 k 个字段时，兄弟哈希数量为 O(k log(n/k) + k)。验证还需读取披露负载，
并承担 BTreeMap 的对数级记账开销。当前证明构建会扫描记录并构建 O(n) 空间的树。

## 资源有界解码（成本代数）

`decode_bounded` 对输入字节、累计读取字节、全局 token 访问次数、单容器元素数量和
嵌套深度执行运行时限制。全局计数包含对象键、未知字段和回溯重试，不能用深度乘以
单容器上限推导全局元素数；深度二也能包含大量并列子容器。

`Budget::with_max_values` 控制全局访问次数。`max_work` 计算解析器读取的字节，包含回溯
重读，不计量任意 trait 代码的 CPU 时间。`ResourceUse` 返回 `read`、`work_read`、
`values` 和实际配置的 `depth_bound`。

`max_alloc` 限制准入估算：动态类型计入输入字节与 token 权重，静态类型使用 schema
估算。成功返回时 `alloc_estimate <= max_alloc`，这仍然不是实际堆分配上界。
Vec 容量、扩容瞬时双缓冲、Box、分配器元数据和自定义反序列化均不受原公式约束。
`DecodeBounded` 常量是可信实现提供的 schema 估算，derive 也必须结合 nextjson 属性与
字段实现审查。严格内存硬上限需要应用在分配器或进程层实现隔离。

升级时将 `alloc_bound` 改为 `alloc_estimate`，将 `work_bound` 改为 `work_read`；
不能继续把前者用于内存安全保证。Config 新增 `with_value_limit` 和
`with_decode_work_limit`，这两个限制仅作用于自描述解码与预检，不覆盖 compact、CBOR、
归档或压缩内部。

## CBOR、压缩与加密

pipeline 显式有序：序列化、可选压缩、再加密。CBOR 排序选项递归排序 map 键，不满足 RFC 8949 第 4.2 节的完整确定性要求。压缩
只在超过大小阈值时运行，且仅当库内 LZ77 输出严格更小时才存储。加密把完整 frame 头
（算法、nonce、长度）作为 AEAD 关联数据认证，每次使用全新 192-bit nonce，因此密文
刻意不确定。

- CBOR 是 crate 自有的流式 RFC 8949 编解码器（`src/cbor_codec.rs`）：值直接在 `T` 与
  字节之间编码/解码，没有中间值树、没有 JSON 文本往返，但容器容量、临时分配和自定义 trait 仍影响
  内存峰值。支持定长/不定长容器、bignum tag 2/3、半精度浮点与原生字节串；字节与集合上限
  在解码过程中内联强制。稳定 map 排序是唯一的显式例外，需要物化值树来
  排序键（opt-in）。
- 压缩使用 magic `RBZ1`、记录 raw 与 stored 长度的 24 字节头；解码器拒绝未知 flags、
  不一致长度、解压长度不匹配、截断与越限。即使未配置上限，解压始终有界。
- 加密使用 magic `RBX1`。`EncryptionKey` 拥有 32 字节、`Debug` 脱敏、析构时 zeroize。
  密钥派生、轮换、存储与访问控制仍是应用/KMS 的职责。

## 并行批处理

`with_parallel_serialization()` 在 scoped 工作线程上编码独立 batch 元素，并输出有序
`u64` 长度表后跟负载区，因此输出字节与调度无关。它面向大型独立记录；小值可能因线程
与合并开销而更慢。

## 带 Merkle 证明的内存映射归档

`archive` 特性是存储格式：库内自研、根在前的相对指针编解码器（`crate::archive_codec`）
包在 128 字节 RustBinary 信封里。`build` 产出信封、小端负载，以及覆盖固定大小负载块
的 BLAKE3 Merkle 树。哈希使用库内 BLAKE3（`crate::hash`，用官方测试向量校验）；
域分离（`LEAF`/`NODE`/`PAD` 标签加大端索引）与树几何是本模块自己的。信封记录格式
版本、flags、非零应用 schema ID、负载/文件长度、块大小与块数、Merkle 根与哈希区位置。

归档类型是普通 struct 加 `#[derive(Archive, Serialize)]`（`#[archive(check_bytes)]`
为兼容而接受）。derive 生成 `#[repr(C)]` 镜像类型（32 位相对指针，根在负载偏移 0）、
一次性结构校验器（`CheckBytes`）与两阶段写入器；任何零拷贝访问前，每个偏移、长度、
区间都被边界检查。`bool` 字段被 derive 拒绝（并非每个字节模式都是合法 `bool`）；
支持的字段面在派生 crate 中说明。

归档视图只能原地借用，不实现 `Copy` 或 `Clone`。手写 `CheckBytes` 是需要
`unsafe impl` 的安全契约。归档校验限制、小端要求、序列化 API 变更和旧数据迁移
见[安全与迁移说明](docs/security-contract.md#migration)。

两种访问模式：

- `MappedArchive::open` 一次性校验信封、schema、对齐、完整相对指针图，**以及** Merkle
  根；之后的 `root()` 是零复制的。
- `MappedArchive::open_header_only` 只校验信封（O(1)），**没有 `root()`**——类型化零
  复制访问需要完整校验或已验证的证明。`proof_for` 为任意负载字节区间以 O(log n) 构建
  自包含的 `MerkleProof`，从存储的哈希区读取兄弟哈希。`verify()` 由携带的块与兄弟
  哈希重算根；`extract()` 返回已验证字节。证明自包含，因此只持有根的轻客户端可以在
  没有文件其余部分的情况下验证区间。

对固定区间宽度，证明构建与验证都是 O(log n)，这把归档验证从一次性成本变成按访问成本。
树是补齐到 2 的幂的完全二叉树，使用域分离哈希，因此根是 `(payload, block_size)` 的纯
函数；默认每块一个 4 KiB 叶子。

打开任何归档都是 `unsafe`：每个进程必须在映射存活期内保持映射文件不可变且不被截断。
发布新文件并原子切换应用引用；绝不在原地更新映射文件。schema ID 由应用拥有，根布局
不兼容变更后必须改变；它是身份检查，不是密码学认证。

## 差分帧与 IBLT 集合协调

`reconcile` 特性面向 gossip/共识传输——接收方往往已持有基准状态：

- `DeltaConfig::encode_delta` 把 `value - base` 编码为规范 ZigZag varint。基准带外协商
  （例如最后提交状态的哈希），永不重复。
- `DeltaTable` 是确定性 HPACK 式 FIFO 表。`DeltaConfig::encode_updates` 对已见值发表
  引用，否则发字面量；两侧重放完全相同的插入/逐出规则，因此表状态是更新流的纯函数，
  永不传输。
- `Iblt`（可逆布隆查找表）协调**无序集合**：两个对等方编码各自的集合，一方相减，剥离
  后精确恢复 `mine \ theirs` 与 `theirs \ mine`。自研实现，三个 splitmix64 哈希，
  `no_std` + `alloc`，无依赖。

过小 IBLT 的解码以 `Error::Iblt` 干净失败，而不是返回错误数据。

## 信任演算

`trust` 特性把配置链提升为认证状态机：

- `TrustedConfig<C, Untrusted>` 可以反序列化，但只能通过显式命名的
  `deserialize_untrusted`。到认证状态不存在 `From`/`Into` 路径——唯一迁移是
  `authenticate`，它要求一个 `Verifier`。
- `TrustedConfig<C, Authenticated>` 是唯一拥有朴素 `deserialize` 名字的配置。
  `deserialize_verified` 把结果包进 `Verified`，其唯一构造函数是认证路径。
- `Session<C, Handshake, _>` **没有 `recv` 方法**。只有 `authenticate` 把会话移到认证
  状态后接收才出现；`close` 把会话移到终态 `Closed`，它不暴露任何东西。"反序列化未
  认证数据"因此不可表示，而不只是不鼓励。会话对任意 `Codec` 泛型，因此能与链上每个
  配置组合。

`EncryptedConfig`（XChaCha20-Poly1305）是内置的认证 `Codec`；应用验证器（MAC、签名、
握手证明）实现 `Verifier`。

## 流

`serialize_into` 直接写 `std::io::Write`；`deserialize_from` 从 `std::io::Read` 读 owned
值。只有 slice 解码能返回借用值。压缩与加密流 reader 传入 `&mut R` 时消费一个声明帧，
留下后续帧未读，并在分配正文前校验头长度关系与配置的上限。

## 安全与审计

安全姿态是：处处有界、该认证的地方认证、对不受保护的部分诚实交代。

- 每个值以一字节类型标签开头；`0xff` 终结容器。
- 浮点保留 IEEE 754 位模式；端序显式。
- 变长整数拒绝 marker 255 与非最小编码。
- 压缩与加密 frame 校验版本、flags、长度与上限；解密先认证后反序列化。
- 熵帧只有在规范时被接受（无哈希重放）；截断与替换被捕获，除了"损坏帧恰好是另一个
  负载的合法帧"这一情况——任何非认证方案都无法区分它。
- 归档携带 Merkle 根；证明与完整打开都做校验。
- 指纹是兼容性检查，不是密码学认证。

本轮审计发现并修复了四个问题：

| 发现 | 严重度 | 修复 |
| ---- | ------ | ---- |
| `delta` 变长整数解码器在恶意输入下可能把最后一组移位越过第 127 位（debug 下 panic / release 下回绕） | 高 | 移位前拒绝溢出 `u128` 的组 |
| 仅信封打开未按树几何校验哈希区长度；畸形文件可能驱动 `read_section_hash` 越界 | 高 | 在信封解析时校验 `hash_len == (leaf_count - 1) * 32` |
| `build` 与 `validate_archive` 各自重复计算了一次 Merkle 树 | 低 | 只算一次层级，根取自顶层 |
| `Session` 硬编码 `Config`，而 `TrustedConfig` 对 `Codec` 泛型 | 低（耦合） | `Session<C: Codec, S, R>` 并带显式帧长上限 |

在每个不可信边界：设置现实的字节与集合上限、除非外层协议拥有它们否则拒绝尾随字节、
对对抗数据做认证、把解压/反序列化错误当作输入失败。

两条边界值得单独说明。即使未配置字节上限，解压始终有界：解压大小对照 frame 头校验，
并在 `with_no_limit` / legacy 模式下封顶于 crate 级默认值。集合上限作用于序列与 map
元素数；字符串由字节上限约束。

## 验证

### 机器证明（Kani）

`src/kani_proofs.rs` 包含 varint/ZigZag 算术、小规模 Merkle 聚合和预算换算的 harness。
存在 harness 源码不等于已经成功执行证明；它们不覆盖哈希抗碰撞性、实际堆分配、
任意 schema 或完整解码器。应在支持 Kani 的环境中另行运行并保留结果。

### 测试证据

单元测试与属性测试覆盖往返、恶意输入、解析预算边界、投影成员资格和查询匹配，
不构成“没有 bug”的证明。[安全契约](docs/security-contract.md#test-evidence)记录密码
向量的来源和范围。格式 golden fixture、独立已知答案、模糊测试与形式化 harness
验证的对象不同，不能互相替代。

### 模糊测试（cargo-fuzz）

五个目标覆盖自描述、compact、CBOR 解码、结构化往返以及熵编码和投影帧。
Windows、Linux CI 执行 ASan 冒烟测试。[运行说明](fuzz/README.md)包含 Windows
原生环境配置、限额、日志和失败输入的复现方法。

```powershell
./scripts/fuzz.ps1 -Seconds 120
```

### 基准测试

`rustbinary-bench/` 是独立 crate（非 workspace 成员），提供两套基准：

- `cargo run --release`——9 次中位数表，在共享数据集（小型头部、遥测帧、大批数值、
  大批字符串）上对比 rustbinary 与 bincode 1、bincode 2、postcard、cbor4ii、
  minicbor，外加独立 rANS 字节 codec 与精确符号表枚举编码。
- `cargo bench --bench lab`——**公平基准实验室**（criterion），覆盖五类负载：
  `homogeneous`（1024 条相同记录）、`heterogeneous`（混合枚举变体）、`borrowed`
  （零拷贝 `&str`）、`adversarial`（10 万元素向量）、`schema-evolution`（用 V2
  类型解码 V1 字节）。对手为 bincode 1、bincode 2、**bincode-next**、postcard、
  rkyv、minicbor——所有 codec 由同一次调用、同一份 `[profile.release]` 编译，
  criterion 报告校准后的中位数统计、`black_box`，并逐对打印编码字节数。

实验室是这个库愿意接受评判的对比。每次 push 到 `main` 都会在全新的 GitHub
Actions 运行器上重跑一次，完整报告存于
[`github_action_benchmark.md`](github_action_benchmark.md)——由
`.github/workflows/benchmark.yml` 重新生成，绝不是过期的截图。以下是最近一次本机
实测（Windows 11、Intel i7-11850H、Rust 1.97、release 配置）的要点，完整逐行
数据见报告文件。

**homogeneous**（1024 条相同记录；单操作中位数）：

| codec | encode | decode | bytes |
|---|---|---:|---:|---:|
| rustbinary | 120.5 µs | 272.6 µs | 51716 |
| bincode 1 | 3.2 µs | 2.0 µs | 14344 |
| bincode 2 | 10.1 µs | 4.2 µs | 13829 |
| bincode-next | 7.9 µs | 8.6 µs | 13829 |
| postcard | 22.5 µs | 9.1 µs | 13686 |
| rkyv | 5.7 µs | 445.1 ns | 24584 |

**schema-evolution**（用带追加 `#[serde(default)]` 字段的 V2 类型解码 V1 字节）：

| codec | encode-v1 | decode-v1-as-v2 | bytes |
|---|---|---:|---:|---:|
| rustbinary | 306.8 ns | 217.3 ns | 68 |
| bincode 1 | 50.7 ns | error | 26 |
| bincode 2 | 182.3 ns | error | 18 |
| bincode-next | 173.7 ns | 71.3 ns | 18 |
| postcard | 185.7 ns | error | 17 |

读这张表要带着格式身份来读。rustbinary 是带类型标签的自描述格式：在巨型同构数组
上每个值都付一个标签，因此字节与速度都会输——表格毫不掩饰这一点。这笔税换来的
东西在 `schema-evolution` 里看得最清楚：bincode 1、bincode 2、postcard 无法用
V2 类型解码追加字段后的 V1 字节（顺序格式不带字段元数据，缺失值直接报错）；
bincode-next 会记录字段数，因此成功；rustbinary 靠稳定字段 ID 成功。同样的诚实
口径也适用于其他组——`borrowed` 不含 bincode 2 与 bincode-next，因为它们的
`decode_from_slice` 需要 `T: for<'de> Deserialize<'de>`，借用型 serde 类型无法满足；
在 `adversarial` 的 10 万 `Vec<u64>` 上 rustbinary 解码约 3.3 ms，而 bincode 1
只要 88.6 µs。这些是自描述的真实代价，如实报告而非遮掩；五类负载的完整逐 codec
表格都在 `github_action_benchmark.md` 里。

数字随机器与构建变化；基准 crate 存在就是为了让对比可以被重新运行，而不是被断言。

### 完整验证命令

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo test --workspace --all-features --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
```

### 示例

| 示例                                                       | 覆盖内容                               | 命令                                                                                           |
| ---------------------------------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [complete.rs](examples/complete.rs)                        | 端到端、全特性                         | `cargo run --example complete --all-features`                                                  |
| [core_codec.rs](examples/core_codec.rs)                    | 有界核心、缓冲区、借用、错误           | `cargo run --example core_codec`                                                               |
| [zero_copy.rs](examples/zero_copy.rs)                      | 嵌套借用与指针证明                     | `cargo run --example zero_copy`                                                                |
| [entropy.rs](examples/entropy.rs)                          | schema 驱动 rANS 编码                  | `cargo run --example entropy --features entropy,derive`                                        |
| [merkle_archive.rs](examples/merkle_archive.rs)            | Merkle 证明、仅信封访问                | `cargo run --example merkle_archive --features archive`                                        |
| [mmap_archive.rs](examples/mmap_archive.rs)                | 校验的 mmap 对象图                     | `cargo run --example mmap_archive --features archive`                                          |
| [delta_sync.rs](examples/delta_sync.rs)                    | 差分帧 + IBLT 集合协调                 | `cargo run --example delta_sync --features reconcile`                                          |
| [trust_session.rs](examples/trust_session.rs)              | 信任演算 + 会话状态机                  | `cargo run --example trust_session --features trust`                                           |
| [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs)  | 自适应决策与调用方缓冲区               | `cargo run --example adaptive_zero_alloc --features adaptive`                                  |
| [secure_pipeline.rs](examples/secure_pipeline.rs)          | 确定性 CBOR、压缩、AEAD                | `cargo run --example secure_pipeline --features cbor,compression,encryption`                   |
| [schema_evolution.rs](examples/schema_evolution.rs)        | 双向 schema V1/V2                      | `cargo run --example schema_evolution --features schema-evolution`                             |
| [parallel_batch.rs](examples/parallel_batch.rs)            | 有序多线程批次                         | `cargo run --example parallel_batch --features parallel`                                       |
| [metadata.rs](examples/metadata.rs)                        | 指纹、反射、上界、打包                 | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |

## docs.rs 与兼容性

包元数据以全特性构建 docs.rs。版本化 wrapper 拒绝未知版本与保留 flags，而不是猜测。
1.0 之前，线格式可能在 minor 版本之间变化，并必须在发布说明中点名。长期部署应锁定
版本、记录完整配置、保留 golden vectors、使用显式 schema ID。存在两个独立版本化的
格式族：流格式（`RBAN` 熵 frame、`RBZ1`/`RBX1` pipeline frame）与归档存储格式
（`RBARC004`）。一个格式族的变更绝不静默影响另一个。

## 非目标

- 在**流** codec 中直接从序列化内存强转任意 Rust 结构体（archive 特性是独立的、
  显式校验的存储格式，有自己的信封与 Merkle 根）。
- 可变共享内存对象图或对映射文件的原地更新。
- 用误导性的 async 门面包装阻塞 I/O。
- 在核心模式自动排序随机化 map。
- 在没有测试内核的情况下宣称 AVX-512/SVE 加速。
- 替代应用密钥管理、授权或 schema 治理。
- 用无 schema 紧凑格式替换带标签流格式：格式身份固定，对体积敏感的路径走 entropy、
  delta 或 archive 层。
- 宣称 FNV-1a 指纹或无密钥重放检查具备密码学强度；认证完整性属于 AEAD/信任层。

## 许可证

RustBinary 以 [Apache License, Version 2.0](LICENSE) 授权。你可以按该许可条款使用、
复制、修改与再分发本项目。再分发必须保留版权声明、许可文本与要求的署名声明。源码
变更应被清晰标识，Apache License 专利条款与免责声明同样适用。

完整法律文本见 [`LICENSE`](LICENSE)。本项目不附带任何形式的担保或条件。
