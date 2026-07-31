# rustbinary-derive

`rustbinary-derive` 是 [`rustbinary`](https://crates.io/crates/rustbinary)
的过程宏 package。它从普通 Rust 结构体和枚举生成经过约束检查的 Schema
元数据以及位级编解码实现。

[English documentation](README.md)

这个 crate 只负责过程宏，不包含第二套序列化引擎。生成的实现统一调用
`rustbinary` 所有的运行时 trait，因此线格式、资源限制、错误类型和配置
仍然由一个 runtime crate 管理。

## 提供的能力

| Derive | 生成的契约 | 典型用途 |
| --- | --- | --- |
| `Fingerprint` | `rustbinary::Fingerprint` | 检测类型和编解码配置漂移 |
| `StaticSize` | `rustbinary::StaticSize` | 获取编译期最坏大小上界 |
| `Reflect` | `rustbinary::Reflect` | 读取静态字段和 variant 元数据 |
| `BitPacked` | `rustbinary::BitPack` | 对有界字段按 bit 压缩存储 |

这些宏不会实现 `serde::Serialize` 或 `serde::Deserialize`。需要普通二进制、
CBOR、压缩、加密或 Schema 演进时，应把它们和 Serde derive 组合使用。

## 安装

应用通常只需要依赖 runtime crate，并使用它重新导出的宏：

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
rustbinary = { version = "0.1.1", features = [
    "derive",
    "fingerprint",
    "reflection",
    "static-size",
    "bit-packing",
] }
```

各 feature 相互独立，只启用应用真正使用的生成契约即可。启用对应 feature
后，`rustbinary` 会重新导出宏，因此应用代码通常使用
`rustbinary::Fingerprint`、`rustbinary::StaticSize`、`rustbinary::Reflect` 和
`rustbinary::BitPacked`。

如需在构建工具中直接拥有过程宏归属，也可以直接依赖本 package，但生成的
代码仍然需要 runtime crate，因为宏生成的路径固定为 `::rustbinary`：

```toml
[dependencies]
rustbinary = { version = "0.1.1", features = [
    "fingerprint",
    "reflection",
    "static-size",
    "bit-packing",
] }
rustbinary-derive = "0.1.1"
```

workspace 中同时写 `path` 和 `version` 是有意设计的。本地构建使用路径，
发布后使用 crates.io 中的相同版本。发布时必须先发布
`rustbinary-derive`，再发布 `rustbinary`。

## 完整示例

下面的类型同时使用本 package 的全部 derive。它是普通的 Serde 数据模型，
具有兼容性 fingerprint、静态元数据，并为有界标志提供独立的位打包布局。

```rust
use serde::{Deserialize, Serialize};
use rustbinary::{Fingerprint, Reflect, StaticSize, TypeShape};

#[derive(Debug, PartialEq, Serialize, Deserialize, Fingerprint, Reflect, StaticSize)]
struct Header {
    enabled: bool,
    partition: u16,
    coordinates: [i32; 2],
}

#[derive(Debug, PartialEq, rustbinary::BitPacked, StaticSize)]
struct Flags {
    enabled: bool,
    #[bits = 3]
    priority: u8,
    #[bits = 12]
    sequence: u16,
}

fn main() -> rustbinary::Result<()> {
    let value = Header {
        enabled: true,
        partition: 17,
        coordinates: [-4, 9],
    };
    let config = rustbinary::options().with_limit(4096);

    let frame = config.serialize(&value)?;
    let decoded: Header = config.deserialize(&frame)?;
    assert_eq!(decoded, value);
    assert!(frame.len() <= Header::MAX_SIZE);

    if let TypeShape::Struct(fields) = Header::SHAPE {
        assert_eq!(fields[1].name, "partition");
        assert_eq!(fields[1].type_name, "u16");
    }

    let flags = Flags {
        enabled: true,
        priority: 5,
        sequence: 2047,
    };
    let packed = rustbinary::options().with_bit_packing().serialize(&flags)?;
    assert_eq!(packed.len(), 2);
    assert_eq!(
        rustbinary::options()
            .with_bit_packing()
            .deserialize::<Flags>(&packed)?,
        flags
    );
    Ok(())
}
```

## `Fingerprint`

`Fingerprint` 生成以下 trait 实现：

```rust
pub trait Fingerprint {
    const TYPE_FINGERPRINT: u64;
    fn fingerprint(config: rustbinary::Config) -> u64;
}
```

生成的类型 fingerprint 是编译期 FNV-1a 兼容性标识，包含：

- module path 和声明的类型名；
- struct、tuple 或 enum 形状；
- 字段名或 tuple 索引；
- 每个字段类型的 `Fingerprint::TYPE_FINGERPRINT`；
- 字段声明顺序；
- enum variant 名称、索引和 payload 字段。

配置 fingerprint 还会加入实际端序、整数编码、尾随字节策略、资源上限和
格式 wrapper。`Endian::Native` 因而会在小端和大端目标上产生不同身份。

用它拒绝意外的 Schema 或配置漂移：

```rust
let config = rustbinary::options().with_fingerprint();
let frame = config.serialize(&value)?;
let value: Header = config.deserialize(&frame)?;
```

修改字段名、类型、顺序、enum variant、module path 或相关配置都会有意改变
身份。这适合缓存 key 和兼容性门禁，但不是密码学认证。不能把它当作签名、
密码哈希、权限判断或篡改检测；这些场景应使用加密或签名层。

### 泛型 fingerprint

每一个类型参数都会获得 `rustbinary::Fingerprint` 约束，因为生成的常量会
纳入参数类型身份：

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Fingerprint)]
struct Envelope<T> {
    sequence: u64,
    payload: T,
}

let a = <Envelope<u32> as Fingerprint>::TYPE_FINGERPRINT;
let b = <Envelope<u64> as Fingerprint>::TYPE_FINGERPRINT;
assert_ne!(a, b);
```

如果泛型参数确实需要不透明身份，应使用一个由应用明确实现
`Fingerprint` 的具体 wrapper，而不是削弱生成的约束。

## `StaticSize`

`StaticSize` 生成三个编译期常量：

```rust
pub trait StaticSize {
    const MAX_SIZE: usize;
    const PACKED_MAX_BITS: usize;
    const PACKED_MAX_SIZE: usize;
}
```

`MAX_SIZE` 是普通 binary profile 的保守最坏上界；`PACKED_MAX_BITS` 是
`BitPack` 布局可能使用的最大有效 bit 数；`PACKED_MAX_SIZE` 是对应的字节
上界。生成的算术会饱和，而不会在溢出时回绕。

该 derive 支持 struct、tuple struct、unit struct 和 enum。所有字段类型都
必须实现 `StaticSize`。`String`、`Vec<T>` 等动态容器有意不实现这个 trait，
因为它们不存在仅由类型决定的有限上界。对这类值应设置运行时资源上限：

```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct DynamicMessage {
    body: String,
}

let config = rustbinary::options()
    .with_limit(64 * 1024)
    .with_collection_limit(4096);
```

enum 的普通大小上界会包含最大 variant 及其普通表示 tag。这个上界不是说
每个值都会占用这么多字节，而是用于容量规划和安全边界。

## `Reflect`

`Reflect` 生成不需要全局注册表、也不需要运行时分配的静态常量：

```rust
pub trait Reflect {
    const TYPE_NAME: &'static str;
    const SHAPE: rustbinary::TypeShape;
}
```

`TypeShape::Struct` 包含 `FieldInfo`；`TypeShape::Enum` 包含 `VariantInfo`，
每个 variant 还包含自己的字段。字段描述包括声明名称（或 tuple 索引）、
token 形式的类型名和声明索引。

```rust
match Header::SHAPE {
    TypeShape::Struct(fields) => {
        for field in fields {
            println!("{}: {}", field.name, field.type_name);
        }
    }
    TypeShape::Enum(variants) => {
        for variant in variants {
            println!("variant {} = {}", variant.index, variant.name);
        }
    }
}
```

这是结构元数据，不是 Rust ABI 反射。它不会暴露内存 offset、padding、私有
运行时状态、Serde rename 规则或动态类型注册表。类型别名和泛型参数按其
声明时的 token 表示输出。

## `BitPacked`

`BitPacked` 为 struct、tuple struct、unit struct 和 enum 生成
`rustbinary::BitPack`。bit 按最低有效位优先写入调用者提供的字节区域。

字段有两种模式：

1. 带 `#[bits = N]` 的字段使用 `BitValue`，编码和解码都会按声明宽度做
   范围检查。
2. 没有该属性的字段递归使用 `BitPack` 以及它的 `MAX_BITS`。

内置 `BitValue` 支持 `bool`、所有有符号整数和所有无符号整数。`bool` 必须
恰好使用 1 bit；有符号值按声明宽度执行二进制补码符号扩展；宽度为 0 或
大于 128 会在宏展开时被拒绝。

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct ControlWord {
    ready: bool,
    #[bits = 2]
    mode: u8,
    #[bits = 10]
    retry_count: u16,
}

let value = ControlWord {
    ready: true,
    mode: 2,
    retry_count: 17,
};
let config = rustbinary::options().with_bit_packing();
let bytes = config.serialize(&value)?;
let decoded: ControlWord = config.deserialize(&bytes)?;
assert_eq!(decoded, value);
```

编码器会先清空调用者提供的输出，使 padding 保持规范零值。解码器拒绝非零
padding；配置为拒绝尾随字节时也会拒绝额外输入。未知 enum tag 会报错。enum
tag 使用能表示 variant 数量的最小 bit 数，所以新增或重排 variant 是线格式
变更。

嵌套 bit-packed 类型可以自然组合：

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Inner {
    #[bits = 4]
    value: u8,
}

#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Outer {
    inner: Inner,
    #[bits = 1]
    enabled: bool,
}
```

自定义字段类型可以在 runtime crate 中实现 `BitPack` 或 `BitValue`。derive
只会选择对应 trait 路径，不会猜测自定义类型的表示方式。

## 支持的数据形状

除明确说明外，四个 derive 都支持 struct 和 enum。union 会产生带源码位置
的编译错误，因为只从类型语法无法安全确定 union 当前激活的字段。

| 形状 | `Fingerprint` | `StaticSize` | `Reflect` | `BitPacked` |
| --- | --- | --- | --- | --- |
| 命名 struct | 支持 | 支持 | 支持 | 支持 |
| tuple struct | 支持 | 支持 | 支持 | 支持 |
| unit struct | 支持 | 支持 | 支持 | 支持 |
| enum | 支持 | 支持 | 支持 | 支持 |
| union | 拒绝 | 拒绝 | 拒绝 | 拒绝 |

泛型参数必须满足所选 derive 的 trait 约束，原有 where clause 会被保留。
Serde 属性仍由 Serde 负责，这些过程宏不会解释 Serde rename 等属性。

## 诊断和失败情况

以下情况会在编译期由 `syn` 生成带源码位置的错误：

- union；
- 对空 enum 使用 `BitPacked`；
- 错误的 `#[bits]` 语法；
- 宽度不在 `1..=128` 范围内；
- 字段缺少选定 trait 的实现。

值和缓冲区仍可能在运行时失败。合法的 `#[bits = 3] u8` 字段如果值为 `8`，
会得到 `BitPacking` 错误，不会被静默截断。输出空间不足会返回
`BufferTooSmall`；输入损坏、非零 padding、未知 tag 和被拒绝的尾随字节都会
返回类型化的 `rustbinary::Error`。

## 生产使用模式

### 分离兼容布局和存储布局

对跨版本边界的 Serde 模型使用 `Fingerprint`，对 frame 内部的紧凑 flags
类型使用 `BitPacked`。不要假定位打包布局和普通 Serde 布局互相兼容。

### 限制不可信输入

`StaticSize` 只适合有限类型的编译期上界，不能替代运行时限制。在网络或存储
边界，反序列化前始终配置字节上限和集合上限。

### 不把 fingerprint 当密码学机制

Fingerprint 用来发现意外 Schema 漂移；加密用于认证 frame；签名用于认证应用
层声明。三者职责不同，不能把兼容性标识当成来源证明。

### 用反射做工具，不做动态解码

`Reflect::SHAPE` 适合诊断、Schema 面板、生成文档和协议检查。它不会动态解码
未知 Rust 类型；解码仍然需要静态选择目标类型。

## 测试和文档

在仓库根目录执行：

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
cargo package -p rustbinary-derive --allow-dirty --no-verify --list
```

该 package 针对 docs.rs 设计。生成代码固定使用 `::rustbinary`，调用方必须
启用对应 runtime feature。仓库根目录的 `examples/metadata.rs` 和
`examples/complete.rs` 会使用真实 runtime 验证这些宏。

## 版本和兼容性

修改字段名、类型、顺序、enum variant 顺序、module path 或位宽都会改变生成
契约。应将这些修改视为 Schema 变更，记录 package 版本和 feature 集合，并为
长期数据保留 golden vectors。宏不会自动迁移 Schema；稳定字段 ID 和迁移应
使用 runtime 的 `schema-evolution` feature。

## 许可证

本 package 使用[Apache License 2.0](../LICENSE)授权。完整法律文本在仓库根目录。
再分发时必须保留许可证和归属声明；项目不提供任何担保，许可证也不授予商标
使用权或暗示版权持有者背书。
