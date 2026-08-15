# RustBinary

RustBinary 是一个基于 [nextjson](https://crates.io/crates/nextjson) 的有界二进制编解码库。
它实现了 nextjson 的 `NsonSerialize` / `NsonDeserialize` 与 `FormatEncoder` /
`FormatDecoder` 契约，类型直接用 nextjson 的 derive 描述。二进制线格式是带类型标签的
自描述流：每个值前有一字节类型标签，容器以 `0xff` 终结，因此 `Option`、`Value`、
无标签枚举和借用字符串都能无歧义往返。

公开 API 分为三层，外加一个可选的归档产品面：

| 层           | 模块                   | 默认启用 | 职责                                                          |
| ------------ | ---------------------- | -------- | ------------------------------------------------------------- |
| **Core**     | `rustbinary::core`     | 是       | Compact V1 编解码、资源上限、尾随策略、调用方缓冲区、`no_std` |
| **Protocol** | `rustbinary::protocol` | 否       | Schema 演进、指纹、反射、静态上界、位打包                     |
| **Pipeline** | `rustbinary::pipeline` | 否       | CBOR、压缩、加密、有序并行批处理                              |
| **Archive**  | `rustbinary::archive`  | 否       | 经校验的只读内存映射对象存储                                  |

[English](README.md)

## 特性

| 能力                  | 状态     | 说明                                                          |
| --------------------- | -------- | ------------------------------------------------------------- |
| nextjson 二进制编解码 | 已实现   | 严格 marker-varint 模式与固定宽度 legacy 模式                 |
| 整数/字符串自适应编码 | 已实现   | 按值选宽度、ZigZag 有符号数、ASCII7 打包                      |
| `i64` 集合自适应编码  | 已实现   | raw / delta / run-length 三种 frame                           |
| SIMD                  | 仅热路径 | 运行时 AVX2/SSE2/NEON，标量回退；AVX-512/SVE/SME 只探测不使用 |
| 零分配编解码路径      | 已实现   | 精确长度输出与调用方缓冲区                                    |
| 借用式零复制反序列化  | 已实现   | 嵌套 `&str` 字段直接指向输入 frame                            |
| 位打包                | 已实现   | `BitPacked` derive、宽度检查、规范零 padding                  |
| Schema 指纹           | 已实现   | 结构哈希，包含编解码配置                                      |
| 编译期内存上界        | 已实现   | `StaticSize::{MAX_SIZE, PACKED_MAX_BITS, PACKED_MAX_SIZE}`    |
| RFC 8949 CBOR         | 已实现   | nextjson CBOR 中继；可选 canonical map 排序                   |
| Schema 演进           | 已实现   | 稳定字段 ID、版本、默认值、跳过未知字段                       |
| 压缩                  | 已实现   | 自适应 Zstandard；压缩后更大则保留原文                        |
| 加密                  | 已实现   | XChaCha20-Poly1305、随机 192-bit nonce、认证 header           |
| 并行序列化            | 已实现   | 有序 batch frame，输出与调度无关                              |
| 运行时反射            | 已实现   | 编译期生成、无分配的静态元数据（`Reflect`）                   |
| `std::io` 流          | 已实现   | reader/writer 适配器保留配置的资源上限                        |
| `no_std`              | 已实现   | Compact V1 slice 编解码与调用方缓冲区无需默认 feature         |
| `no_std + alloc`      | 已实现   | owned 值、指纹、演进、自适应 codec                            |

## 安装

在 `Cargo.toml` 中加入本 crate 与 nextjson 框架：

```toml
[dependencies]
rustbinary = "0.1"
nextjson = { version = "0.1", features = ["derive"] }
```

可选能力通过 Cargo feature 启用，按需选择即可：

```toml
rustbinary = { version = "0.1", features = ["protocol"] }   # 整个 Protocol 层
rustbinary = { version = "0.1", features = ["fingerprint", "derive"] }
rustbinary = { version = "0.1", features = ["archive"] }    # 仅 mmap 归档
```

可选的 Zstandard 依赖需要构建平台具备 C 工具链。

### Feature 矩阵

| Feature            | 默认启用 | 用途                                                                                        |
| ------------------ | -------- | ------------------------------------------------------------------------------------------- |
| `std`              | 是       | owned Core 与 I/O API；Pipeline 与 SIMD 以它为前提                                          |
| `alloc`            | 随 std   | 兼容性标记；owned API 始终可用（nextjson 的 `FormatDecoder` 需要 alloc）                    |
| `protocol`         | 否       | 聚合：adaptive、bit-packing、derive、fingerprint、reflection、schema-evolution、static-size |
| `pipeline`         | 否       | 聚合：cbor、compression、encryption、parallel                                               |
| `archive`          | 否       | 经校验的只读 mmap 归档；依赖 `std`、rkyv、memmap2                                           |
| `derive`           | 否       | 与对应 runtime feature 一起导出过程宏                                                       |
| `fingerprint`      | 否       | 结构指纹 runtime 与 frame                                                                   |
| `reflection`       | 否       | 零分配反射 runtime                                                                          |
| `static-size`      | 否       | 编译期上界 runtime                                                                          |
| `simd`             | 否       | 运行时能力探测与热扫描分派，不改变线格式                                                    |
| `bit-packing`      | 否       | 位级 trait 与调用方缓冲区 codec                                                             |
| `adaptive`         | 否       | 调用方缓冲区自适应字符串/集合；隐含 `bit-packing`                                           |
| `cbor`             | 否       | 基于 nextjson 中继的 RFC 8949 CBOR                                                          |
| `compression`      | 否       | 自适应 Zstandard frame                                                                      |
| `encryption`       | 否       | XChaCha20-Poly1305、系统随机数、密钥清零                                                    |
| `parallel`         | 否       | scoped thread 有序批处理                                                                    |
| `schema-evolution` | 否       | 稳定字段 ID 版本化 frame                                                                    |

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

顶层 `serialize` / `deserialize` 函数与 `options()` 都使用严格紧凑模式：小端、
规范 marker-varint、ZigZag 有符号整数、默认 64 MiB 字节上限、一百万元素集合上限，
并拒绝尾随字节。`legacy_options()` 显式选择旧的无界定宽模式并允许尾随字节，只适合
可信的内存数据。

### 配置链

配置值体积小且可复制。改变格式的方法返回不同的 wrapper，处理顺序在类型上可见：

```text
Config -> CborConfig -> CompressedConfig -> EncryptedConfig
```

`Config` 决定端序、整数表示、字节/集合上限和尾随策略；各 wrapper 每次增加一项能力。
例如（启用全部相关 feature 时）：

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

格式编码的是值，不是 Rust 对象内存：不写 padding、原生指针、vtable 或
`repr(Rust)` 布局。每个值前有一字节类型标签；数组和对象以 `0xff` 终结。

| nextjson 值            | 线表示                                              |
| ---------------------- | --------------------------------------------------- |
| `null` / unit / `None` | 标签 `0x00`                                         |
| `false` / `true`       | 标签 `0x01` / `0x02`                                |
| `u64` / `u128`         | 标签 `0x03` / `0x04` + 无符号 payload               |
| `i64` / `i128`         | 标签 `0x05` / `0x06` + ZigZag payload               |
| `f64` / `f32`          | 标签 `0x07` / `0x08` + 按配置端序的 IEEE 754 位模式 |
| 字符串 / char          | 标签 `0x09` + 编码字节长度 + UTF-8                  |
| 数组                   | 标签 `0x0a` + 元素 + `0xff`                         |
| 对象                   | 标签 `0x0b` + (`字符串键` + 值) 对 + `0xff`         |

整数与长度 payload 使用 marker-varint（legacy 模式下为定宽 `u64`，因为 nextjson
的统一数据模型把所有整数按 `u64`/`i64` 宽度跨线传输）。Marker varint 必须使用最短
规范形式：

| Marker    | Payload | 最小合法值                 |
| --------- | ------- | -------------------------- |
| `0..=250` | 无      | 0                          |
| `251`     | 2 字节  | 251                        |
| `252`     | 4 字节  | 65,536                     |
| `253`     | 8 字节  | 4,294,967,296              |
| `254`     | 16 字节 | 18,446,744,073,709,551,616 |
| `255`     | 保留    | 永不接受                   |

解码器拒绝非最短形式、窄化溢出、非法 UTF-8、非法标签、截断、上限违规和不允许的
尾随字节。

## 零分配与零复制

`serialized_size` 通过计数 writer 得到精确长度；`serialize_into_slice` 只执行一次
序列化并写入调用方内存，返回精确初始化长度。容量不足时，`Error::BufferTooSmall`
携带精确所需容量。

从 slice 反序列化时，嵌套的 `&str` 与字节切片字段直接借用输入：

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

这条路径上 codec 自身不分配；用户自定义的 nextjson 实现仍可能自行分配。codec 自身
保证无分配的路径包括 `serialized_size`、`serialize_into_slice`、adaptive 的
`encode_*_into_slice` / `decode_*_into_slice` 以及位打包调用方缓冲区。Reader 解码
要求 owned 目标（`DeserializeOwned`）；返回指向临时 reader buffer 的引用不安全。

ASCII7 打包必然展开为 owned 文本；adaptive raw UTF-8 可返回 `Cow::Borrowed`。
指针范围断言见 [zero_copy.rs](examples/zero_copy.rs)。

## 自适应编码

`with_adaptive_encoding()` 保留紧凑 nextjson 配置，并提供显式的数据感知 API。
frame 携带稳定策略标签；解码器校验规范 varint、padding、长度、delta 溢出和 RLE run。

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

字符串 frame 由策略字节、规范化解码长度 varint 和 payload 组成。策略 0 是原始
UTF-8；策略 1 是最低有效位优先的 ASCII7。只有输入全部为 ASCII 且打包结果严格更小
时才选 ASCII7；大小相等时选 raw UTF-8。

`i64` 集合比较三种完整编码：独立 ZigZag 值（`Raw`）、首值加受检 `i128` delta
（`Delta`）、value/run 对（`RunLength`）。Delta 必须严格小于 raw 且不大于 RLE；
RLE 必须严格小于 raw；否则用 raw。完整示例见
[adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs)。

## 位打包

`BitPacked` 为有界字段派生位级 codec。标注 `#[bits = N]` 的字段使用 `BitValue`
范围校验；其他字段递归使用 `BitPack`。枚举标签使用最小位宽，未知解码标签被拒绝。

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

`BitWriter` 会清零输出，使末尾 padding 为规范零；`BitReader` 拒绝非零 padding 以及
（配置时）尾随字节。

## SIMD

启用 `simd` 后，`simd_backend()` 在运行时选择 AVX2、SSE2、NEON 或标量路径并缓存
结果。adaptive 的 ASCII 分类和单字节 varint 扫描已接入这些内核。所有非对齐读取都由
安全分派层保证边界；unsafe 只存在于目标架构模块，crate 全局启用
`deny(unsafe_op_in_unsafe_fn)`。

AVX-512、SVE、SME 会通过 `hardware_capabilities()` 独立探测并报告，但没有 codec
内核使用它们。宽向量对小 record 不一定更快，且这些后端目前没有硬件 CI 覆盖。

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

- `Fingerprint` 覆盖字段/variant 名称、声明类型、声明顺序、整数编码、实际端序、
  尾随策略、资源限制以及 CBOR deterministic 模式。它基于 FNV-1a，是兼容性标识，
  **不是**密码学哈希，不能替代 AEAD、签名或权限判断。
- `StaticSize` 为静态定长类型提供最坏情况普通/位打包大小上界。动态集合有意不实现。
- `Reflect` 在编译期生成无分配元数据（类型名、字段、variant），无需运行时注册表。
  完整示例见 [metadata.rs](examples/metadata.rs)。

derive package 提供独立的[中文详细指南](rustbinary-derive/README.zh-CN.md)和
[英文详细指南](rustbinary-derive/README.md)，说明生成的 trait 契约、支持的数据形状、
泛型约束、`#[bits = N]` 校验、编译期错误与生产集成方式。

## Schema 演进

`schema-evolution` feature 用稳定 schema ID、schema 版本、规范字段 ID 排序、
长度分隔字段和未知字段跳过为值加框。字段 ID 与 schema ID 是显式的协议决策，不是
会在重构中悄然变化的哈希。

frame 以 magic `RBE1` 开头，后接格式版本、flags、schema ID、schema 版本、字段数量，
以及 `(field_id, payload)` 条目。编码器对 ID 排序并拒绝重复；解码器要求 ID 严格
递增，并在切片前校验全部长度运算。

应用协议规则：

1. 为一个兼容类型族分配唯一的 schema ID。
2. 永远不要为不同含义或不兼容类型复用字段 ID。
3. 重命名 Rust 字段时保留字段 ID。
4. 向后兼容靠新增可选/带默认值字段实现。
5. 用编码版本驱动有意的语义迁移。
6. 需要转发或保留时检查未知字段。

完整的 V1/V2 升级与降级示例（含重命名、默认值和借用字段）见
[schema_evolution.rs](examples/schema_evolution.rs)。

## CBOR、压缩与加密

流水线顺序固定且显式：先序列化，再可选压缩，最后加密。Deterministic CBOR 递归
排序 canonical map key。压缩超过阈值才尝试，且结果没有变小时保留原文。加密把完整
frame header（算法、nonce、长度）作为 AEAD 关联数据认证，每次使用全新的 192-bit
nonce，因此加密结果有意不确定。

- CBOR（`cbor`）委托 nextjson 的 RFC 8949 中继。中继在类型化解码前物化 Value 树，
  因此单容器元素数量受集合上限约束，以限制内存放大。尾随字节始终被拒绝（中继要求
  恰好一个根值）。
- 压缩（`compression`）使用 magic `RBZ1`，24 字节 header 记录 raw/stored 长度；
  解码器拒绝未知 flags、不一致长度、解压长度不匹配、截断和上限违规。
- 加密（`encryption`）使用 magic `RBX1`。`EncryptionKey` 持有 32 字节密钥，
  `Debug` 输出脱敏，drop 时清零。密钥派生、轮换、存储和访问控制属于应用/KMS
  职责。完整示例见 [secure_pipeline.rs](examples/secure_pipeline.rs)。

## 并行批处理

`with_parallel_serialization()` 在 scoped worker 上编码独立 batch 元素，输出有序
`u64` 长度表和按源顺序排列的 payload 段，因此输出字节与 worker 调度无关。它面向
大型独立 record；小值可能因 worker 与合并开销而更慢。完整示例见
[parallel_batch.rs](examples/parallel_batch.rs)。

## 内存映射归档

可选 `archive` feature 是基于 rkyv 经校验相对指针布局的独立存储格式。`build` 生成
64 字节 RustBinary 包头，后接小端、32 位相对指针归档。包头记录格式版本、格式
flags、非零应用 schema ID，以及经过检查的 payload/文件长度。rkyv 版本已固定；
归档布局依赖若发生不兼容升级，必须重新审查并升级 RustBinary 格式版本。

`MappedArchive::open` 先检查文件大小上限（默认 1 GiB），再一次性校验包头、schema、
对齐及完整相对指针图；之后 `root()` 不分配、不反序列化。打开操作是 `unsafe`：映射
存活期间，所有进程都必须保证文件不被修改或截断。生产发布应创建新文件并原子切换
应用引用，绝不能原地更新已映射文件。schema ID 由应用管理，不兼容根布局变更后必须
更新；它是身份检查，不是密码学认证。完整示例见 [mmap_archive.rs](examples/mmap_archive.rs)。

## 流

`serialize_into` 直接写入 `std::io::Write`；`deserialize_from` 从 `std::io::Read`
读取 owned 值。只有 slice 解码可以返回借用值。压缩与加密的流式读取器在传入
`&mut R` 时只消费一个声明 frame，后续 frame 保持未读，并在为 body 分配内存之前
校验 header 长度关系和配置的 raw/plaintext 上限。

## 安全

- 每个值前有一字节类型标签；`0xff` 终结容器。
- 浮点保留 IEEE 754 位模式；端序是显式的。
- 可变整数拒绝 marker 255 和非最短编码。
- 结构体字段编码为命名对象键。
- 普通 map 保留 nextjson 迭代顺序，不确定；确定性 map 需要 deterministic CBOR
  或有序 map。
- 压缩与加密 frame 校验版本、flags、长度和上限。
- 解密在反序列化之前完成认证。
- 指纹是兼容性检查，不是密码学认证。
- 用户自定义的 nextjson 实现可能分配或拒绝借用访问者。

在每个不可信边界：设置现实的字节与集合上限，除非外层协议持有尾随字节否则拒绝之，
对敌对数据做认证，并把解压/反序列化错误视为输入失败。

两个上限值得单独说明。解压始终有界，即使未配置字节上限：解压后大小先与 frame
header 交叉校验，使用 `with_no_limit` / legacy profile 时以 crate 全局默认上限封顶，
恶意 frame 无法无界膨胀。集合上限只约束序列/映射的元素数量；字符串由字节上限约束。

## 错误模型

所有操作返回 `rustbinary::Result<T>`。`Error` 保留 I/O 错误，并为上限、容量、
frame、schema、压缩、加密、位打包、自适应数据、worker 失败和畸形基础值提供结构化
变体。它是 `#[non_exhaustive]`；下游穷尽匹配需要兜底分支。frame 偏移、长度求和、
delta 重建和整数收窄都使用受检运算，而不是依赖 panic 恢复。

`Error::category()` 提供稳定的运维分类：`UserInput`、`Protocol`、`Configuration`
或 `InternalBug`。

## 验证

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo test --workspace --all-features --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
cargo bench --bench codec_comparison
```

### 示例

| 示例                                                      | 覆盖内容                          | 命令                                                                                            |
| --------------------------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------- |
| [complete.rs](examples/complete.rs)                       | 全 feature 端到端组合             | `cargo run --example complete --all-features`                                                   |
| [core_codec.rs](examples/core_codec.rs)                   | 有界 Core、缓冲区、借用、错误策略 | `cargo run --example core_codec`                                                                |
| [zero_copy.rs](examples/zero_copy.rs)                     | 嵌套借用和指针范围证明            | `cargo run --example zero_copy`                                                                 |
| [mmap_archive.rs](examples/mmap_archive.rs)               | 经校验的 mmap 对象图              | `cargo run --example mmap_archive --features archive`                                           |
| [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs) | 自适应决策与调用方缓冲区          | `cargo run --example adaptive_zero_alloc --features adaptive`                                   |
| [secure_pipeline.rs](examples/secure_pipeline.rs)         | 确定性 CBOR、压缩、AEAD           | `cargo run --example secure_pipeline --features cbor,compression,encryption`                    |
| [schema_evolution.rs](examples/schema_evolution.rs)       | Schema V1/V2 双向演进             | `cargo run --example schema_evolution --features schema-evolution`                              |
| [parallel_batch.rs](examples/parallel_batch.rs)           | 有序多 worker 批处理              | `cargo run --example parallel_batch --features parallel`                                        |
| [metadata.rs](examples/metadata.rs)                       | 指纹、反射、上界、位打包          | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |

## docs.rs 与兼容性

包元数据以全部 feature 构建 docs.rs，feature 门控的 API 会获得 docs.rs 自动标签。
PowerShell 下的严格本地文档校验：

```powershell
$env:RUSTDOCFLAGS='-D warnings'
cargo doc --workspace --all-features --no-deps
```

版本化 wrapper 拒绝未知版本和保留 flags，而不是猜测。1.0 之前，线格式可能在 minor
release 之间变化，并必须在 release notes 中明确说明。长期部署应固定版本、记录完整
配置、保留 golden vectors，并使用显式 schema ID。

## 非目标

- 从序列化内存直接转换任意 Rust 结构体
- 可变共享内存对象图或对映射文件进行原地更新
- 把阻塞 I/O 包装成误导性的 async facade
- 在核心 profile 中自动排序随机化 map
- 在没有经过测试的内核时宣称 AVX-512/SVE 加速
- 取代应用密钥管理、授权或 schema 治理

## 许可证

RustBinary 以 [Apache License, Version 2.0](LICENSE) 授权。你可以在该许可条款下
使用、复制、修改和再分发本项目。再分发必须保留版权声明、许可文本和必需的署名
声明；源代码的修改应明确标识，并适用 Apache 许可的专利条款和免责声明。

完整法律文本见 [`LICENSE`](LICENSE)。本项目不附带任何形式的保证或条件。
