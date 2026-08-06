# RustBinary

RustBinary 是一个面向 Serde 的有界二进制编解码库。线格式配置是显式的；
自适应编码、位打包、Schema 指纹、CBOR、压缩、认证加密、Schema 演进和并行
批处理均通过 feature 独立启用。

产品面明确分为三层：

| 层 | 公开入口 | 默认启用 | 职责 |
| --- | --- | --- | --- |
| **Core** | `rustbinary::core` | 是 | Compact V1 编解码、limit、尾随策略、确定性基础表示、调用方缓冲区、`no_std` |
| **Protocol** | `rustbinary::protocol` | 否 | 演进、指纹、反射、静态上界、位打包、兼容 profile |
| **Pipeline** | `rustbinary::pipeline` | 否 | CBOR、压缩、加密、有序并行变换 |

只读内存映射对象存储是独立、显式启用的 `rustbinary::archive` 产品面。Core、
Protocol、Pipeline 聚合 feature 都不会启用它，它也不会改变三层现有线格式或
`no_std` 边界。

[English](README.md)

## 设计身份

RustBinary 采用自己的显式格式模型，而不是把其他 codec 的 API 换名复刻：

1. 线格式变化必须体现在配置类型链上；启用 Cargo feature 不会静默改写普通字段。
2. 自适应策略比较包含 tag、长度在内的完整编码成本，并使用稳定的平局规则。
3. 调用方内存是 API 契约，而不是依赖编译器偶然消除分配。
4. 字节上限、集合上限和尾随策略会传递到各层 wrapper。
5. 兼容性哈希、确定性编码、压缩和 AEAD 各自承担独立职责，不能混为一种安全机制。

由此形成规范化的数据感知 frame、稳定字段 ID 演进格式和类型化处理流水线。除非某个
profile 明确声明，否则不暗示与其他二进制格式兼容。

## 实现状态

| 能力 | 状态 | 实现说明 |
| --- | --- | --- |
| Serde 二进制编解码 | 已实现 | 固定宽度兼容模式与严格 marker-varint 模式 |
| 整数自适应编码 | 已实现 | 按实际值选择宽度，有符号整数使用 ZigZag |
| 字符串自适应编码 | 已实现 | 运行时在原始 UTF-8 与 ASCII7 之间择优 |
| 集合自适应编码 | 已实现 | `i64` 集合在 raw、delta、RLE 中选择最小结果 |
| SIMD | 热路径已实现 | x86_64 运行时 SSE2/AVX2，AArch64 NEON，其他平台标量回退 |
| AVX-512、SVE、SME | 仅能力探测 | `hardware_capabilities` 可报告，尚无对应 codec 内核 |
| 零分配编解码路径 | 已实现 | 精确长度 Serde 输出及调用方缓冲区自适应解码 |
| 借用式零复制反序列化 | 已实现 | 嵌套 `&str`、`&[u8]` 直接指向输入 frame |
| 只读相对指针对象归档 | 已实现，需 `archive` | 版本化包头、显式 schema ID、有界校验和 mmap 原地访问 |
| 位打包 | 已实现 | `BitPacked` derive、宽度检查、规范零 padding |
| Schema 指纹 | 已实现 | 覆盖类型结构及完整 binary/CBOR 配置 |
| 编译期内存上界 | 已实现 | `MAX_SIZE`、`PACKED_MAX_BITS`、`PACKED_MAX_SIZE` |
| RFC 8949 CBOR | 已实现 | Ciborium 编解码与递归 canonical map 排序 |
| Schema 演进 | 已实现 | 稳定字段 ID、版本、默认值、跳过未知字段、迁移 |
| 压缩集成 | 已实现 | 自适应 Zstandard；压缩后变大则保留原文 |
| 原生加密层 | 已实现 | XChaCha20-Poly1305、随机 192-bit nonce、认证 frame header |
| 确定性序列化 | 显式模式已实现 | 位打包、Schema frame、并行 batch、deterministic CBOR |
| 并行序列化 | 已实现 | scoped worker，输出顺序稳定 |
| 运行时反射 | 已实现 | `Reflect` 生成无注册、无分配的静态元数据 |
| `std::io` 流 | 已实现 | Reader/Writer API 位于 `adapters`，并保留资源限制 |
| `no_std` | 已实现 | Compact V1 slice 编解码和调用方缓冲区无需默认 feature |
| `no_std + alloc` | 已实现 | 保留 `Vec`、`String`、owned data、指纹、演进和标量 adaptive codec |
| Async Fiber/UFA | 未实现 | 不用阻塞 I/O 包装成假的 async API |

这里严格区分“已探测”和“已加速”；Serde codec 与相对指针对象归档也是两套独立的
格式和 API。

## 安装

```toml
[dependencies]
rustbinary = "0.1.4"
serde = { version = "1", features = ["derive"] }
```

只在确实需要时启用整层，也可只选择单项能力：

```toml
rustbinary = { version = "0.1.4", features = ["protocol"] }
rustbinary = { version = "0.1.4", features = ["fingerprint", "derive"] }
rustbinary = { version = "0.1.4", features = ["archive"] }
```

最低 Rust 版本由 `Cargo.toml` 的 `rust-version` 声明。可选模块未启用时不会参与编译。当前可选 Zstandard
依赖还需要目标平台具备可用的 C 工具链。

### Feature 矩阵

| Feature | 默认启用 | 用途与依赖 |
| --- | --- | --- |
| `std` | 是 | Core owned/I/O API；Pipeline 与运行时 SIMD feature 以它为前提 |
| `alloc` | 通过 `std` | 不依赖 `std` 的 owned `Vec`/`String` API |
| `protocol` | 否 | 完整 Protocol 层聚合 feature |
| `pipeline` | 否 | 完整 Pipeline 层聚合 feature |
| `archive` | 否 | 经校验的只读 mmap 归档；依赖 `std`、rkyv 和 memmap2 |
| `derive` | 否 | 与对应 runtime feature 一起导出过程宏 |
| `fingerprint` | 否 | 结构指纹 runtime 和 frame |
| `reflection` | 否 | 零分配反射 runtime |
| `static-size` | 否 | 编译期上界 runtime |
| `simd` | 否 | 运行时能力探测与热扫描分派，不改变线格式 |
| `bit-packing` | 否 | 核心位级 trait 和调用方缓冲区 codec |
| `adaptive` | 否 | 调用方缓冲区自适应字符串/集合；隐含 `bit-packing`；`alloc` 增加 owned API |
| `cbor` | 否 | 基于 Ciborium 的 RFC 8949 |
| `compression` | 否 | 自适应 Zstandard frame |
| `encryption` | 否 | XChaCha20-Poly1305、系统随机数、密钥清零 |
| `parallel` | 否 | scoped thread 有序批处理 |
| `schema-evolution` | 否 | 稳定字段 ID 版本化 frame |

主架构是 RustBinary Compact V1：纯 `no_std` slice core、用于 owned data 的
`alloc` extension，以及承载流和平台服务的 `std` adapters。

```powershell
cargo build --no-default-features
cargo build --no-default-features --features alloc
cargo build --features std
```

## 二进制配置

顶层 `serialize`/`deserialize` 与 `options()` 都使用严格紧凑模式：小端、规范
marker-varint、ZigZag 有符号整数、默认 64 MiB 字节上限、一百万元素集合上限，
并拒绝尾随字节。`legacy_options()` 显式选择旧的无界定宽模式并允许尾随字节。

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

配置值体积小且可复制。改变格式的方法返回不同 wrapper，使处理顺序在类型上可见：

```text
Config -> CborConfig -> CompressedConfig -> EncryptedConfig
```

允许的方法顺序就是允许的数据处理顺序，因此不会通过这条类型链误把加密放在压缩之前。

### 核心线格式规范

格式编码的是值，不是 Rust 对象内存；不会写入 padding、原生指针、vtable 或
`repr(Rust)` 布局。

| Serde 值 | 线表示 |
| --- | --- |
| `bool` | 单字节，只允许 `0` 或 `1` |
| `Option<T>` | 单字节 `0`/`1` tag，`Some` 后跟 `T` |
| `u8` / `i8` | 单字节 |
| 定宽整数 | 按配置端序写入声明宽度 |
| 可变无符号整数 | 规范 marker 加 0/2/4/8/16 字节 payload |
| 可变有符号整数 | ZigZag 后使用无符号 marker 格式 |
| `f32` / `f64` | 按配置端序保留 IEEE 754 位模式 |
| `char` | 一个合法 UTF-8 scalar，不带长度 |
| 字符串/字节 | 编码后的字节长度加原始字节 |
| 序列/map | 声明元素/entry 数量后跟内容 |
| tuple/struct | 按 Serde 声明顺序写字段值，不写名字 |
| enum | 按配置编码 `u32` variant index，后跟 variant 内容 |

Marker varint 必须使用最短规范形式：

| Marker | Payload | 最小合法值 |
| --- | --- | --- |
| `0..=250` | 无；marker 即数值 | 0 |
| `251` | 2 字节 | 251 |
| `252` | 4 字节 | 65,536 |
| `253` | 8 字节 | 4,294,967,296 |
| `254` | 16 字节 | 18,446,744,073,709,551,616 |
| `255` | 保留且非法 | 永不接受 |

解码器拒绝非最短形式、窄化溢出、非法 UTF-8、非法 primitive tag、截断、资源上限
违规以及不允许的尾随字节。

## 零分配与零复制

`serialized_size` 通过计数 writer 得到精确长度；`serialize_into_slice` 只执行一次
序列化并写入调用方内存。容量不足时，`Error::BufferTooSmall` 返回精确所需容量。

从 slice 反序列化时，任意嵌套层级的 `&str` 和 `&[u8]` 都可直接借用输入
frame，生命周期由 Rust 静态约束，不复制 payload、不重新创建字符串。ASCII7
需要展开，因此返回 owned string；adaptive raw UTF-8 可返回 `Cow::Borrowed`。

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct View<'a> {
    name: &'a str,
    #[serde(borrow)]
    payload: &'a [u8],
}

let source = View { name: "edge", payload: b"frame" };
let config = rustbinary::options().with_limit(4096);
let mut storage = vec![0; config.serialized_size(&source)? as usize];
let written = config.serialize_into_slice(&mut storage, &source)?;
let view: View<'_> = config.deserialize(&storage[..written])?;
assert_eq!(view.payload, b"frame");
# Ok::<(), rustbinary::Error>(())
```

这条路径上 codec 自身不分配；用户自定义的 Serde 实现仍可能自行分配。

codec 自身保证无分配的路径包括 `serialized_size`、`serialize_into_slice`、
adaptive `encode_*_into_slice`、`decode_i64_slice_into`、
`decode_string_into_slice` 以及位打包调用方缓冲区。Reader 解码要求
`DeserializeOwned`；返回指向临时 reader buffer 的引用在 Rust 中并不安全。

借用解析对字符串/字节 payload 是真正零复制，它属于 Serde 字节流路径；指针范围
断言见 [zero_copy.rs](examples/zero_copy.rs)。映射对象图使用独立的 archive 产品面。

## 内存映射归档

可选 `archive` feature 是基于 rkyv 经校验相对指针布局的独立存储格式。`build`
生成 64 字节 RustBinary 包头，后接小端、32 位相对指针归档。包头记录格式版本、固定
格式 flag、非零应用 schema ID，以及经过检查的 payload/文件长度。rkyv 版本已固定；
归档布局依赖若发生不兼容升级，必须重新审查并升级 RustBinary 格式版本。

`MappedArchive::open` 先检查文件大小上限，再一次性校验包头、schema、对齐及完整
相对指针图；之后 `root()` 不分配、不反序列化。打开操作是 `unsafe`：映射存活期间，
所有进程都必须保证文件不被修改或截断。生产发布应创建新文件并原子切换应用引用，
绝不能原地更新已映射文件。schema ID 由应用管理，不兼容根布局变更后必须更新；它是
身份检查，不是密码学认证。

完整 [mmap_archive.rs](examples/mmap_archive.rs) 会创建新文件、释放构建缓冲区、只读
映射、校验嵌套数据，并证明字符串、向量和子记录都直接位于映射区间内。

## 自适应编码

`with_adaptive_encoding()` 保留紧凑 Serde 配置，并提供显式的数据感知 API。
编码器比较完整编码长度后写入稳定策略 tag；解码器会校验规范 varint、padding、
长度、delta 溢出及 RLE run，不能把损坏数据静默接受。

```rust
let adaptive = rustbinary::options()
    .with_limit(1 << 20)
    .with_adaptive_encoding();

let values = [1000, 1001, 1002, 1003];
let required = adaptive.encoded_i64_slice_size(&values)?;
let mut output = vec![0; required];
adaptive.encode_i64_slice_into_slice(&mut output, &values)?;
assert_eq!(adaptive.decode_i64_vec(&output)?, values);
let mut decoded_values = [0_i64; 4];
adaptive.decode_i64_slice_into(&mut decoded_values, &output)?;
assert_eq!(decoded_values, values);

let text = adaptive.encode_string("telemetry/primary")?;
assert_eq!(adaptive.decode_string(&text)?, "telemetry/primary");
let mut decoded_text = [0_u8; 32];
assert_eq!(
    adaptive.decode_string_into_slice(&mut decoded_text, &text)?,
    "telemetry/primary"
);
# Ok::<(), rustbinary::Error>(())
```

自适应 frame 必须显式使用；如果普通 Serde 字段在不知情时改变表示，会破坏协议兼容性。

字符串 frame 由 `strategy:u8`、规范化解码字节长度 varint 和 payload 组成。策略 0
是原始 UTF-8；策略 1 是最低有效位优先的 ASCII7。只有输入全部为 ASCII 且完整打包
结果严格更小时才选择 ASCII7；大小相等时选择 raw UTF-8。

`i64` 集合比较三种完整成本：独立 ZigZag 的 `Raw`、首值加受检 `i128` delta 的
`Delta`、以及 value/run 对的 `RunLength`。Delta 必须严格小于 raw 且不大于 RLE；
RLE 必须严格小于 raw；其他情况规范选择 raw。解码会校验 varint、数量、run、delta
溢出、padding、资源上限和尾随策略。

策略检查、借用、精确调用方缓冲区和容量错误见
[adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs)。

## SIMD 分派

启用 `simd` 后，`simd_backend()` 在运行时选择 AVX2、SSE2、NEON 或 scalar。
adaptive 的 ASCII 分类和单字节 varint 连续扫描已接入这些内核。所有非对齐读取均由
安全分派层保证边界；unsafe 只存在于目标架构模块，crate 全局启用
`deny(unsafe_op_in_unsafe_fn)`。

AVX-512BW、SVE、SME 会被独立探测，但当前不会被选为 codec 后端。宽向量对小
record 不一定更快，SME 主要服务矩阵 tile；在具备对应硬件 CI 和基准之前，不能把
“CPU 支持该指令”伪装成“codec 已被该指令加速”。

## 派生系统

`Fingerprint` 覆盖字段/variant 名称、声明类型、声明顺序、整数编码、实际端序、
尾随策略、资源限制、格式以及 CBOR deterministic 模式。Native endian 在小端和
大端目标上产生不同指纹。

当前基于 FNV-1a 的 fingerprint 是兼容性标识，不是密码学哈希。它不能替代 AEAD、
数字签名或权限判断。

`BitPacked` 支持 `#[bits = N]`，拒绝超宽值，枚举使用最短 tag，并校验未使用
padding 位。`StaticSize` 提供静态类型最坏上界；动态集合有意不实现此 trait。
`Reflect` 生成字段、variant、类型名和声明顺序的静态元数据，不需要全局注册表。
这些元数据在编译期生成、运行时可读且无需分配。完整使用见
[metadata.rs](examples/metadata.rs)。

derive package 提供独立的[中文详细指南](https://github.com/blueokanna/RustBinary/blob/main/rustbinary-derive/README.zh-CN.md)
和[英文详细指南](https://github.com/blueokanna/RustBinary/blob/main/rustbinary-derive/README.md)。
其中说明生成的 trait 契约、支持的数据形状、泛型约束、`#[bits = N]` 校验、
编译期错误以及生产环境集成方式。

## CBOR、压缩和加密

流水线顺序固定且显式：先序列化，再可选压缩，最后加密。Deterministic CBOR 会
递归排序 canonical map key。Zstandard 达到阈值后才尝试，且结果没有变小时保留
原文。加密会认证密文和 frame 元数据，每次生成新 nonce，因此加密结果有意不确定。

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

生产环境必须从密钥管理系统获得 key；硬编码 key 只能用于测试。

压缩 header 记录 raw/stored 长度。解码器拒绝未知 flag、不一致的长度关系、解压后
长度不符、截断和配置上限违规；只有压缩结果严格更小时才保留压缩 payload。

加密从操作系统获得新的 192-bit nonce。完整 header 是 AEAD associated data，因此
算法 ID、nonce 和长度与密文一起被认证。`EncryptionKey` 持有 32 字节，`Debug`
会隐藏内容，drop 时执行清零；密钥派生、轮换、存储和访问控制仍属于应用/KMS。
完整示例见 [secure_pipeline.rs](examples/secure_pipeline.rs)。

## Schema 演进

`schema-evolution` 使用稳定 schema ID、版本、按字段 ID 的规范排序、字段长度、
未知字段跳过、默认值、借用字段及应用显式迁移。字段 ID 和 schema ID 是可审查的
协议决策，不使用会因普通重构而静默变化的自动哈希替代。

frame 包含 magic `RBE1`、格式版本、flag、稳定 schema ID、schema version、字段数，
以及带长度的 `(field_id, payload)` entry。编码器按 ID 排序并拒绝重复；解码器要求
ID 严格递增，并在切片之前检查全部长度运算。

应用协议规则：

1. 为一个兼容类型族分配永久 schema ID。
2. 不得为不同语义或不兼容类型复用字段 ID。
3. Rust 字段改名时保留原字段 ID。
4. 使用 optional/default 字段维持向后兼容。
5. 通过 encoded version 执行明确的语义迁移。
6. 需要转发或保留数据时检查 unknown fields。

包含改名、默认值、借用字段和 V1/V2 双向读写的完整代码见
[schema_evolution.rs](examples/schema_evolution.rs)。

## 并行与流式 I/O

`with_parallel_serialization()` 在 scoped worker 上处理互相独立的 batch 元素，
输出包含有序长度表，因此线程调度不改变字节结果。它适合大型独立 record；小对象
应使用普通单值 API。

`serialize_into` 直接写入 `std::io::Write`；`deserialize_from` 从
`std::io::Read` 解码 owned value。只有 slice API 可以返回借用字段。所有不可信
输入都应同时设置字节上限和集合元素上限。

并行编码只面向互相独立且足够大的 record。每个元素独立编码，有序 `u64` 长度表和
按输入顺序排列的 payload 保证线程调度不会改变字节。小对象可能因 worker 和合并
成本而更慢。完整代码见 [parallel_batch.rs](examples/parallel_batch.rs)。

传入 `&mut R` 时，压缩/加密流解码器只消费一个声明 frame，后续 frame 保持未读。
在为 body 分配内存之前，会先校验 header 长度关系和 raw/plaintext 上限。

## 确定性契约

- 端序、整数模式和 enum 表示显式配置。
- adaptive tag 与平局规则规范且稳定。
- 位打包末尾 padding 必须为零。
- Schema 演进字段按稳定数值 ID 排序。
- 并行 batch 保留输入顺序。
- Deterministic CBOR 递归排序 canonical map key。
- 浮点 IEEE 位模式（包括 NaN payload）保持不变。

普通 `HashMap` 的迭代顺序随机，因此不确定；应使用 `BTreeMap`、其他有序 serializer
或 deterministic CBOR。加密 frame 因每次使用新 nonce 而有意不确定，复用 nonce
才是安全错误。

## 线格式与安全规则

- `bool` 和 `Option` tag 只能是单字节 `0`/`1`。
- 浮点数保留 IEEE 754 bit pattern，端序显式配置。
- 可变整数拒绝 marker 255 和非最短编码。
- 普通 struct 只按声明顺序编码字段值，不写字段名。
- 普通 map 保留 Serde 迭代顺序，因此不保证确定性。
- 确定性 map 必须使用 deterministic CBOR 或有序 map。
- 压缩/加密 frame 校验版本、flag、长度和资源上限。
- 流解码器在为 body 分配内存前校验 frame 长度关系和配置上限。
- 解密必须先完成认证，之后才会反序列化。
- Fingerprint 只做兼容性检查，不提供密码学认证。
- 用户自定义 Serde 实现仍可能分配，或不接受 borrowed visitor。

处理任何不可信输入时，都应设置符合业务的字节/集合上限；除非外层协议明确拥有尾随
数据，否则应拒绝尾随字节；对抗攻击者时必须使用认证，并把解压/反序列化错误视为
输入失败。

## 错误模型

所有 API 返回 `rustbinary::Result<T>`。`Error` 保留 I/O 错误，并为资源上限、容量、
frame、schema、压缩、加密、位打包、自适应数据、worker 失败和 primitive 损坏提供
结构化 variant。该 enum 是 `#[non_exhaustive]`，下游穷举匹配必须保留 fallback。
frame offset、长度求和、delta 重建和整数窄化都执行受检运算，而不是依赖 panic 恢复。

## 验证

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo test --workspace --all-features --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
```

### 可执行 Examples

| Example | 覆盖内容 | 命令 |
| --- | --- | --- |
| [complete.rs](examples/complete.rs) | 全 feature 端到端组合 | `cargo run --example complete --all-features` |
| [core_codec.rs](examples/core_codec.rs) | 有界 Core、调用方缓冲区、借用、尾随与错误策略 | `cargo run --example core_codec` |
| [zero_copy.rs](examples/zero_copy.rs) | 嵌套借用和指针范围证明 | `cargo run --example zero_copy` |
| [mmap_archive.rs](examples/mmap_archive.rs) | 经校验只读 mmap 对象图及指针证明 | `cargo run --example mmap_archive --features archive` |
| [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs) | 自适应决策和调用方缓冲区 | `cargo run --example adaptive_zero_alloc --features adaptive` |
| [secure_pipeline.rs](examples/secure_pipeline.rs) | 确定性 CBOR、压缩、AEAD | `cargo run --example secure_pipeline --features cbor,compression,encryption` |
| [schema_evolution.rs](examples/schema_evolution.rs) | Schema V1/V2 双向演进 | `cargo run --example schema_evolution --features schema-evolution` |
| [parallel_batch.rs](examples/parallel_batch.rs) | 有序多 worker batch | `cargo run --example parallel_batch --features parallel` |
| [metadata.rs](examples/metadata.rs) | 指纹、反射、上界、位打包 | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |

## docs.rs 与兼容性

`Cargo.toml` 配置 docs.rs 使用全部 feature 构建。公共模块按子系统分组，feature-gated
API 会得到 docs.rs 自动标签。PowerShell 下的严格本地文档验证：

```powershell
$env:RUSTDOCFLAGS='-D warnings'
cargo doc --workspace --all-features --no-deps
```

所有版本化 wrapper 都拒绝未知版本和保留 flag，不做猜测性解析。1.0 之前，minor
版本之间仍可能发生线格式变化，且必须写入发布说明。长期部署应固定 crate 版本、记录
完整配置、维护 golden vectors，并为演进数据使用显式 schema ID。

## 当前非目标

- 从序列化字节直接强转任意 Rust struct
- 可变共享内存对象图或原地更新已映射文件
- 把阻塞 I/O 包装成误导性的 async facade
- 在核心 binary profile 中自动排序随机化 map
- 在没有已实现且经硬件测试的内核时宣称 AVX-512/SVE 加速
- 替代应用的密钥管理、权限控制或 schema 治理

## 许可证

RustBinary 使用[Apache License 2.0（Apache 软件许可证 2.0）](LICENSE)
授权。

你可以在该许可证条款下使用、复制、修改和再分发本项目。再分发时必须
保留版权声明、许可证文本以及许可证要求的归属声明；对源代码的修改应
当明确标注。Apache License 2.0 中的专利授权条款和免责声明同样适用。

完整法律文本位于 [`LICENSE`](LICENSE)。本项目不提供任何明示或默示的
担保或条件。
