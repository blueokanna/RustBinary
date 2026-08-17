# RustBinary

RustBinary 是一个基于 [nextjson](https://crates.io/crates/nextjson) 的有界二进制编解码库。
类型直接用 nextjson 的 derive 描述，这个库负责把它们变成字节、再变回来。它只做一件窄事：
把结构化数据搬上线或落进文件——对面可能是恶意的，内存可能很紧，而且你希望在解码器跑起来
之前就知道它最多会吃掉多少资源。

这里每个特性都回答一个具体问题——"这个帧我拒得起吗？"、"轻客户端能不能不扫全记录就读
一个字段？"、"这种类型最坏能把我的堆怎么样？"——下文先给答案，再说明代价。本库没有装饰
性功能；凡是取舍而非纯赢的特性，README 都会直说。

## 格式身份

流线格式是**带类型标签的自描述字节流**：每个值前有一字节类型标签，数组与对象以 `0xff`
终结。这就是动态流的格式身份。它不是 bincode 式的紧凑布局，也不是 CBOR 式的长度前缀布局，
也不会悄悄变成这两种中的任何一种。

对静态类型，本库还提供**schema 引导的 compact 简档**（`Config::with_compact_format()` +
`CompactBinary` 派生宏）。它是第二种、且是**追加式**的线格式，不是带标签流的某个模式：
不写逐值类型标签、不写字段名、容器用长度前缀，字节串与浮点数组走 memcpy / 批量端序
快速路径。`Value`、无标签枚举与 `FormatEncoder` 驱动的类型留在自描述流上；静态热路径
可以走 compact 简档。两者永远不会改变彼此的字节。

自描述换来三条整个设计都依赖的性质：

- `Option`、无标签枚举、`nextjson::Value` 无需旁路元数据即可无歧义往返。
- 借用 `&str` 字段直接指向输入 frame，零复制。
- 解码器永远知道一个值在哪里结束、一个 frame 是否完整。

代价是每个值付一字节标签，数值数组每个元素各付一字节标签。这笔税是真实的，而且被
测量过而不是被藏起来——本仓库的基准实验室在同样的数据上把它与 bincode 1、bincode 2、
bincode-next、postcard、rkyv、minicbor 对比，输在哪一行都写得清清楚楚。如果你的负载是
一大堆 `f64` 别的什么都没有，无 schema 的紧凑编解码器在体积和速度上会胜过**带标签流**，
那就去用那个；compact 简档在保持同样有界、受资源策略约束的解码器的同时，基本抹平了
这部分差距。如果你的负载是异构记录、必须无歧义往返、且在没有带外 schema 的情况下可读，
标签税买来的就是这些。

`archive` 特性**不是第二种流格式**。它是独立的存储格式——rkyv 扁平相对指针 + RustBinary
信封——用于只读内存映射对象存储，并独立版本化（`RBARC002`）。流编解码器从不做内存强转、
从不产生相对指针、也从不因为某个 Cargo feature 改变自己的行为。

## 依赖策略

流路径依赖 nextjson，以及可选的派生 crate。可选 pipeline 增加 zstd、
chacha20poly1305、getrandom、zeroize。archive 增加 memmap2、rkyv 与 **blake3**。
供应链策略与密码实现策略是刻意分离的两个决策：

- **供应链**：第三方依赖被限制在真正需要的层（pipeline 编解码、归档存储、Merkle
  哈希），且都是可选 Cargo feature；流核心保持轻依赖。
- **密码实现**：凡是承载安全或完整性语义的原语都用经过审计的 crate，而不是库内
  自研。归档 Merkle 树使用官方 **`blake3`** crate（正式审查过的实现）；本库不再
  自带任何哈希原语。熵层完全不需要哈希——它靠重放校验帧，残余检测缺口见熵编码一节。

若威胁模型要求更小的依赖面，`blake3` crate 可替换为任何 `fn(&[u8]) -> [u8; 32]`
实现而不改变归档布局（调用点只有 `src/archive.rs` 里的一处包装）；域分离与树几何
归归档模块所有，不归哈希原语所有。

## 分层

| 层          | 模块                   | 默认启用 | 职责                                                                 |
| ----------- | ---------------------- | -------- | -------------------------------------------------------------------- |
| **Core**    | `rustbinary::core`     | 是       | 紧凑编解码、资源上限、尾随策略、调用方缓冲区、`no_std`              |
| **Protocol**| `rustbinary::protocol` | 否       | Schema 演进、指纹、反射、静态上界、位打包                           |
| **Pipeline**| `rustbinary::pipeline` | 否       | CBOR、压缩、加密、有序并行批处理                                    |
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
| RFC 8949 CBOR           | 已实现     | 自研流式 CBOR 编解码（无值树）；可选 canonical map 排序                     |
| Schema 演进             | 已实现     | 稳定字段 ID、版本、默认值、跳过未知字段                                     |
| 压缩                    | 已实现     | 自适应 Zstandard；压缩后更大则保留原文                                      |
| 加密                    | 已实现     | XChaCha20-Poly1305、随机 192-bit nonce、认证 header                         |
| 并行序列化              | 已实现     | 有序 batch frame，输出与调度无关                                            |
| 运行时反射              | 已实现     | 编译期生成、无分配的静态元数据（`Reflect`），含逐字段符号表                  |
| 差分帧                  | 已实现     | 基准相对整数差分 + 确定性 HPACK 式动态表                                    |
| IBLT 集合协调           | 已实现     | 自研可逆布隆查找表（Goodrich 与 Mitzenmacher）                              |
| 信任演算                | 已实现     | 类型级认证状态机；未认证接收在类型层面不可表达                              |
| Merkle 归档             | 已实现     | 审计 BLAKE3 树，O(log n) 证明，仅信封打开                                |
| 可投影自认证记录        | 已实现     | 投影健全性、O(log n) 证明、schema 版本绑定、跳过未知字段                   |
| 资源有界解码            | 已实现     | schema 派生 B/A/D/W 成本代数，预算强制的 `decode_bounded` 并带用量证据      |
| 可配置深度上限          | 已实现     | `Config::with_depth_limit` 在编码与解码两侧限制嵌套深度                     |
| 形式化验证              | Kani 证明  | varint/ZigZag 核心 + 投影树几何 + 预算极限代数                              |
| `no_std`                | 已实现     | Compact slice 编解码与调用方缓冲区无需默认 feature                          |
| `no_std + alloc`        | 已实现     | owned 值、指纹、演进、自适应、熵、集合协调                                  |

## 安装

```toml
[dependencies]
rustbinary = "0.1"
nextjson = { version = "0.1", features = ["derive"] }
```

按需启用：

```toml
rustbinary = { version = "0.1", features = ["protocol"] }   # 整个 Protocol 层
rustbinary = { version = "0.1", features = ["sync"] }       # 熵 + 集合协调 + 信任
rustbinary = { version = "0.1", features = ["archive"] }    # Merkle mmap 归档
```

Zstandard 需要构建主机上有 C 工具链；其余全部是纯 Rust，熵编码器零依赖，归档用审计过的
`blake3` crate 做哈希（见依赖策略）。

### 特性矩阵

| Feature            | 默认 | 用途                                                                        |
| ------------------ | ---- | --------------------------------------------------------------------------- |
| `std`              | 是   | owned Core 与 I/O API；Pipeline、SIMD、trust 需要                           |
| `alloc`            | via std | 兼容标记；owned API 始终可用                                          |
| `protocol`         | 否   | 聚合：adaptive, bit-packing, derive, fingerprint, reflection, schema-evolution, static-size |
| `pipeline`         | 否   | 聚合：cbor, compression, encryption, parallel                               |
| `sync`             | 否   | 聚合：entropy, reconcile, trust                                             |
| `archive`          | 否   | Merkle 校验的 mmap 归档；需要 `std`, rkyv, memmap2                          |
| `derive`           | 否   | 重导出过程宏及其运行时 feature                                              |
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
| `compression`      | 否   | 自适应 Zstandard frame                                                      |
| `encryption`       | 否   | XChaCha20-Poly1305、OS 随机、zeroize 密钥                                   |
| `parallel`         | 否   | scoped 线程有序 batch frame                                                 |
| `schema-evolution` | 否   | 稳定字段 ID 版本化 frame                                                    |
| `bounded`          | 否   | `DecodeBounded` 成本代数（B/A/D/W）、`Budget`、`decode_bounded`；需要 `std` 与 `derive` |
| `projection`       | 否   | 可投影自认证记录与投影证明；需要 `std` 与审计过的 `blake3`                  |

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
    .with_zstd_compression(3)
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
字节。varint 与 ZigZag 机制只存在于一处（`canonical`），编解码两侧共用，Kani 证明其
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

rANS 流不是自认证的。最终状态检查能拒绝截断和大部分替换，但对"字节变了但仍然能解码"
的情况有非零漏检率。这个模块的第一版用帧内 SHA-256 摘要掩盖了这个问题；这一版把哈希
整个去掉，换成精确的东西：

**重放校验。** 解码器用同一组模型把解码结果重新编码，并要求结果与帧中存储的负载和
最终状态逐字节一致。只有当帧是"它解码出的负载的规范编码"时才被接受——即
`frame == encode(decode(frame))`。

接受规则就是全部保证，失败模式如下：

- 截断或状态/计数损坏会在消费与状态检查处失败。
- 仍可解码的字节变更会产生**不同的**负载，而它的规范编码几乎不可能等于被损坏的帧，
  因此重放不一致、帧被拒绝。
- 残余缺口：被损坏的帧原则上可能是**另一个**负载的规范编码（`frame == encode(x)` 且
  `x` 不同于原文），此时重放会带着错误内容接受它。任何无哈希方案都关不掉这个缺口。
  注意：无密钥的帧摘要**能**捕获这类意外翻转——重放校验是用这点检测缺口换取零哈希。
  无论重放还是摘要都挡不住能改写帧的攻击者；认证完整性属于 AEAD/信任层。
- raw 回退帧存储字面输入、无冗余，因此只做长度校验。`without_raw_fallback()` 关闭该
  回退，让每个帧都保持编码态、都可被重放校验。

重放校验默认开启，代价是解码时多一次编码（基准表可见）。`without_replay_verification()`
可在传输层已认证字节的场景下关闭。

```rust
use rustbinary::{Model, RansEncoder, RansDecoder};

// 精确 5 符号表每个符号约 log2(5) = 2.32 位，而不是 3 位。
let model = Model::from_uniform(5)?;
let mut encoder = RansEncoder::new();
for _ in 0..100 { encoder.put_symbol(&model, 3)?; }
let (final_state, payload) = encoder.finish();
let mut decoder = RansDecoder::new(final_state, &payload);
let mut kinds = Vec::new();
for _ in 0..100 { kinds.push(decoder.get_symbol(&model)?); }
decoder.finish()?;
kinds.reverse();
# assert!(kinds.iter().all(|&k| k == 3));
# Ok::<(), rustbinary::Error>(())
```

见 [entropy.rs](examples/entropy.rs) 的 schema 驱动流程与带偏斜先验的独立字节 codec
（重复遥测数据 2 倍以上压缩，已在基准 crate 中实测）。

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

`projection` 特性是一种**协议格式，不是紧凑 codec**：规范、自认证的记录，其字段可
针对可信根**逐个**验证与解码，而无需扫描或反序列化记录的其余部分。保证是**投影健全性**：

```text
Verify(P, π, q) = v   ⟹   v = Project_q(Decode(P))
```

`P` 是记录，`q` 是投影查询（字段 ID 集合），`π` 是证明，`Decode(P)` 是唯一规范解码
（唯一性来自格式的规范性：严格递增字段 ID、定宽头部、无重复）。`q` 之外的字段永不
被读取，但其真实性仍被保证：每个字段都绑定进 Merkle 根，篡改或替换未读字段会改变根
并使验证失败。

- **构造**：字段为 `(field_id, payload_len, payload)` 三元组；根是
  `BLAKE3(schema_version ‖ merkle_root)`，因此证明无法针对不同 schema 版本重放。
  `RecordBuilder` 强制规范顺序；`prove` 提取批量证明（最小兄弟集）；`verify` 永不
  触碰记录，并要求**可信锚点**（记录根，由认证来源承诺——区块头、带密钥的承诺、
  签名的索引）。本模块绑定完整性；带密钥的认证是调用方的信任锚。`verify_untrusted`
  只检查内部一致性，检测损坏而非替换。
- **诚实的复杂度**：`prove` 为 O(n)；证明大小最坏 O(|q| · log(n/|q|))，单字段或连续
  区间为 O(log n)；`verify` 做 O(|q| + log n) 次哈希运算。Merkle 开销意味着该格式面向
  字段数适中的记录；对负载为主的记录，逐字段哈希成本可忽略。
- **已验证**：Kani 证明 `small_tree_proof_agrees_with_root` 证明聚合/重算协议对任意
  哈希与任意查询在代数上一致；`leaf_count_is_complete_and_bounded` 证明树完整且至多
  翻倍。

## 资源有界解码（成本代数）

`bounded` 特性把 `StaticSize` 从“最坏输出字节数”推进到**可证明的资源语义**。
`#[derive(DecodeBounded)]` 为每个类型生成镜像解析器的成本代数：

```text
B(T)  一次解码 T 最多消费的输入字节数
A(T)  一次解码 T 最多分配的堆字节数
D(T)  最大解析器嵌套深度
W(T)  最坏工作量（读字节 + 逐字段开销）
```

`decode_bounded` 在 [`Budget`] 下运行解码并返回携带**证据**的 `Decoded<T>`
（`ResourceUse`：精确读字节数，加上分配、深度、工作的可证明上界）。代数与解析器同构
——derive 镜像编码器/解码器遍历的确切容器/键结构——因此对静态有界类型，常量是精确的：
这样的解码按构造至多读 `B(T)` 字节、分配 `A(T)` 字节（通常为 0）、嵌套 `D(T)` 层、
做 `W(T)` 工作。

动态类型（`Vec`、`String`、`&str`）对内容相关的资源报告 `usize::MAX`，由运行时预算
强制执行调用方的上限。分配上限是保守且对 derive 覆盖的类型精确的：

- **数据**：输入中物化到堆的每一字节（字符串与字节缓冲本体）都被字节上限约束，因此
  `数据 ≤ 读取`。
- **结构**：集合后备缓冲与 Box 超出其线数据之外的部分。derive 计算
  `MAX_STRUCTURAL_ELEMENT`——类型中所有集合里最坏的单元素结构分配（`Vec<T>`/`Box<T>`
  为 `size_of::<T>()`，`String` 为 0）。一次解码至多有 `D(T)` 层嵌套集合，每层受集合
  上限约束，因此
  `分配 ≤ 读取 + MAX_STRUCTURAL_ELEMENT · D(T) · collection_limit ≤ max_input + max_alloc`。
  报告的 `alloc_bound` 即该上界。未声明 `MAX_STRUCTURAL_ELEMENT` 的手写 `DecodeBounded`
  实现回退到预算的 `element_structure_bytes` 旋钮（默认 `ELEMENT_STRUCTURE_BYTES` = 64，
  覆盖标准集合形态；宽元组或大内联元素布局应调高）。

每次失败都会报告超出的是哪个维度（`BudgetExceeded`）。这是 DoS 敏感消费者的入口：
区块链节点、enclave、网关从策略或 `Budget::from_type::<T>()`（由代数派生紧致默认值）
选择 `Budget`，并拿到本次解码消耗的证据。`Config::with_depth_limit` 把容器嵌套上限
压到库级 128 之下，并做了钳制，恶意上限不会导致越界索引。

## CBOR、压缩与加密

pipeline 显式有序：序列化、可选压缩、再加密。确定性 CBOR 递归排序规范 map 键。压缩
只在超过大小阈值时运行，且仅当 Zstandard 输出严格更小时才存储。加密把完整 frame 头
（算法、nonce、长度）作为 AEAD 关联数据认证，每次使用全新 192-bit nonce，因此密文
刻意不确定。

- CBOR 是 crate 自有的流式 RFC 8949 编解码器（`src/cbor_codec.rs`）：值直接在 `T` 与
  字节之间编码/解码，没有中间值树、没有 JSON 文本往返，解码值的内存峰值就是解码值
  本身。支持定长/不定长容器、bignum tag 2/3、半精度浮点与原生字节串；字节与集合上限
  在解码过程中内联强制。确定性 canonical map 排序是唯一的显式例外，需要物化值树来
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

`archive` 特性是存储格式：rkyv 扁平相对指针布局包在 128 字节 RustBinary 信封里。`build`
产出信封、小端负载，以及覆盖固定大小负载块的 BLAKE3 Merkle 树。哈希使用审计过的
`blake3` crate（见依赖策略）；域分离（`LEAF`/`NODE`/`PAD` 标签加大端索引）与树几何
是本模块自己的。信封记录格式版本、flags、非零应用 schema
ID、负载/文件
长度、块大小与块数、Merkle 根与哈希区位置。

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

`src/canonical.rs` 是规范小端 varint 与 ZigZag 的单一实现，编解码器共用。
`src/kani_proofs.rs` 中的 Kani harness 在完整 `u128`/`i128` 域上符号化证明：

- 往返：对所有 `u128` 有 `decode(encode(v)) == v`；ZigZag 双向往返。
- 有界：编码形式至多 17 字节且使用规范（最小）宽度。
- 规范唯一：往返加上 `decode` 的确定性蕴含任意两个不同值不会共享同一编码。

```text
cargo kani -p rustbinary --harness canonical::varint_roundtrip
cargo kani -p rustbinary --harness canonical::zigzag_roundtrip
cargo kani -p rustbinary --harness canonical::zigzag_injective
cargo kani -p rustbinary --harness canonical::varint_bounded_and_minimal
```

归档的 BLAKE3 用官方 BLAKE3 测试向量校验，覆盖单块、块组边界与多块组长度。
测试向量只校验正确性，不是实现级审计——见依赖策略。

### 属性测试（proptest）

`tests/entropy_roundtrip.rs` 与 `tests/canonical_proptest.rs` 对公开 API 做随机化：
字节与均匀符号表往返、逐字节损坏性质（报错，或**不同的**负载——绝不可能是原始负载）、
截断拒绝、非规范形式拒绝、整数往返。

### 模糊测试（cargo-fuzz）

`fuzz/` crate（独立，非 workspace 成员）向紧凑与 legacy 解码器喂任意字节（不得 panic、
每个错误都可分类），并对结构化随机记录做往返。

```text
cargo +nightly fuzz run decode_arbitrary_bytes
cargo +nightly fuzz run decode_structured_roundtrip
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
（`RBARC002`）。一个格式族的变更绝不静默影响另一个。

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
