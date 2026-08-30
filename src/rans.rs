//! Static-model rANS entropy coding driven by compile-time schema metadata.
//!
//! This module is a from-scratch implementation of range Asymmetric Numeral
//! Systems (rANS, Duda 2014) with a 64-bit state and 16-bit renormalization.
//! It is the entropy-coding core behind the `entropy` feature and is
//! deliberately **not** a wrapper around zstd, LZ4, or any external codec:
//! there is no C dependency, no dictionary transmission, and the coder is
//! fully `no_std` + `alloc`.
//!
//! # Static models, no dictionary
//!
//! The model is a frequency table over an exact symbol alphabet. Both sides
//! of a link derive the same model deterministically:
//!
//! - [`crate::Model::from_uniform`] over the exact alphabet size (from `#[bits = N]`
//!   ranges, enum cardinality, or primitive alphabets);
//! - [`crate::Model::from_weights`] with caller-supplied priors (still static, still
//!   transmitted implicitly — the decoder reconstructs the same table from
//!   the same weights).
//!
//! [`crate::SchemaModel::from_reflect`] walks a `Reflect` shape and produces one
//! static model per field. Because the schema is compiled into both sides,
//! no frequency table ever crosses the wire. The coder therefore always codes
//! at the information-theoretic rate of the model: an enum with 3 variants
//! costs `log2(3) ≈ 1.585` bits per symbol instead of rounding up to 2.
//!
//! # Determinism and verification
//!
//! Encoding is canonical: the same symbols and models always produce the same
//! bytes, and decoding is its exact inverse. Verification is therefore
//! **hash-free**: after decoding, the decoder re-encodes the decoded symbols
//! with the same models and requires the result to match the frame's stored
//! payload and final state byte-for-byte. A frame is accepted only when it is
//! the canonical encoding of the payload it decodes to.
//!
//! This makes the guarantees exact rather than probabilistic:
//!
//! - **Truncation** fails the state and consumption checks.
//! - **Substitution** (any byte change that leaves the frame decodable)
//!   changes the decoded payload, so the replay differs and the frame is
//!   rejected — unless the corrupted frame happens to be the canonical
//!   encoding of a *different* payload, which no non-authenticated scheme can
//!   distinguish (a hash cannot either: it would simply authenticate the
//!   replaced payload).
//! - **Raw fallback frames** store the literal input bytes and carry no
//!   redundancy, so they are verified only for length consistency; they are
//!   the explicit anti-expansion path and are not suitable as an integrity
//!   boundary.
//!
//! Replay verification is on by default and can be disabled with
//! [`crate::EntropyConfig::without_replay_verification`] for throughput
//! when the transport is authenticated elsewhere. See
//! `tests/entropy_roundtrip.rs` for exhaustive roundtrips and corruption
//! rejection.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Config, Error, Result};

/// rANS state lower bound. The state always lives in `[2^31, 2^47)`.
const RANS_L: u64 = 1 << 31;
/// Total frequency mass of every model.
pub const RANS_M: u32 = 1 << 15;
/// Renormalization base: 16 bits are flushed/refilled at a time.
const RANS_BASE_BITS: u32 = 16;
/// Encoder emits a 16-bit word while `state >= freq << RANS_EMIT_SHIFT`.
const RANS_EMIT_SHIFT: u32 = 32;

const MAGIC: [u8; 4] = *b"RBAN";
const FORMAT_VERSION: u16 = 3;
const FLAG_RAW: u16 = 0x0001;
/// Frame layout: magic(4) + version(2) + flags(2) + count(8) + state(8).
const HEADER_LEN: usize = 24;

fn check_replay(
    state: u64,
    payload: &[u8],
    stored_state: u64,
    stored_payload: &[u8],
) -> Result<()> {
    if state != stored_state || payload != stored_payload {
        return Err(Error::Entropy("entropy frame did not replay canonically"));
    }
    Ok(())
}

/// One static frequency model over an exact symbol alphabet.
///
/// Frequencies are non-zero `u16` values summing to [`RANS_M`]. The model is
/// immutable once built, so it can be constructed once and shared across many
/// frames. Building allocates a 64 KiB slot-to-symbol lookup table.
#[derive(Clone, Debug)]
pub struct Model {
    symbols: u32,
    freq: Vec<u16>,
    cum: Vec<u16>,
    slot_to_symbol: Vec<u16>,
}

impl Model {
    /// Creates a uniform model over `symbols` distinct symbols.
    ///
    /// `symbols` must be in `1..=RANS_M`. Uniform priors are the default
    /// schema-derived distribution: exact-alphabet coding wins whenever the
    /// alphabet is not a power of two.
    pub fn from_uniform(symbols: u32) -> Result<Self> {
        if symbols == 0 || symbols > RANS_M {
            return Err(Error::Entropy("model alphabet must be in 1..=32768"));
        }
        let base = RANS_M / symbols;
        let extra = RANS_M % symbols;
        let mut freq = Vec::with_capacity(symbols as usize);
        for index in 0..symbols {
            freq.push((base + u32::from(index < extra)) as u16);
        }
        Self::from_freqs(freq)
    }

    /// Creates a static model from caller-supplied prior weights.
    ///
    /// Weights are scaled deterministically to sum to [`RANS_M`] using the
    /// largest-remainder method with index tie-breaking, so the decoder
    /// rebuilds the identical table from the identical weights. Every weight
    /// must be positive, and there must be at most [`RANS_M`] of them.
    pub fn from_weights(weights: &[u32]) -> Result<Self> {
        let symbols = weights.len();
        if symbols == 0 || symbols > RANS_M as usize {
            return Err(Error::Entropy(
                "model weights must contain 1..=32768 entries",
            ));
        }
        let total: u64 = weights.iter().map(|&weight| u64::from(weight)).sum();
        if total == 0 {
            return Err(Error::Entropy("model weights must be positive"));
        }
        let scale = u64::from(RANS_M);
        // Floored quota, with a guaranteed floor of one per symbol.
        let mut freq: Vec<u32> = weights
            .iter()
            .map(|&weight| ((u64::from(weight) * scale) / total) as u32)
            .collect();
        for slot in &mut freq {
            *slot = (*slot).max(1);
        }
        // If the floors pushed the sum above M, reduce the largest quotas
        // (ties: lowest index first) but never below one.
        let mut sum: u32 = freq.iter().sum();
        if sum > RANS_M {
            let mut excess = sum - RANS_M;
            let mut order: Vec<usize> = (0..symbols).collect();
            order.sort_by(|&a, &b| freq[b].cmp(&freq[a]).then_with(|| a.cmp(&b)));
            for &index in &order {
                if excess == 0 {
                    break;
                }
                let reducible = freq[index] - 1;
                let reduce = reducible.min(excess);
                freq[index] -= reduce;
                excess -= reduce;
            }
            debug_assert_eq!(excess, 0);
            sum = freq.iter().sum();
        }
        // Distribute the remaining mass to the largest fractional remainders,
        // ties broken by declaration order.
        let deficit = RANS_M - sum;
        let mut order: Vec<usize> = (0..symbols).collect();
        order.sort_by(|&a, &b| {
            let remainder_a = (u64::from(weights[a]) * scale) % total;
            let remainder_b = (u64::from(weights[b]) * scale) % total;
            remainder_b.cmp(&remainder_a).then_with(|| a.cmp(&b))
        });
        for &index in order.iter().take(deficit as usize) {
            freq[index] += 1;
        }
        let freq: Vec<u16> = freq.iter().map(|&value| value as u16).collect();
        Self::from_freqs(freq)
    }

    /// Builds a model from an explicit frequency table summing to [`RANS_M`].
    fn from_freqs(freq: Vec<u16>) -> Result<Self> {
        let symbols = freq.len();
        if symbols == 0 {
            return Err(Error::Entropy("empty model frequency table"));
        }
        let mut cum = Vec::with_capacity(symbols + 1);
        cum.push(0u32);
        for &value in &freq {
            if value == 0 {
                return Err(Error::Entropy("model frequency must be positive"));
            }
            let next = cum.last().copied().unwrap_or(0) + u32::from(value);
            if next > RANS_M {
                return Err(Error::Entropy(
                    "model frequencies exceed the total frequency mass",
                ));
            }
            cum.push(next);
        }
        if cum.last().copied().unwrap_or(0) != RANS_M {
            return Err(Error::Entropy(
                "model frequencies must sum to the total frequency mass",
            ));
        }
        let mut slot_to_symbol = vec![0u16; RANS_M as usize];
        for symbol in 0..symbols {
            let start = cum[symbol] as usize;
            let end = cum[symbol + 1] as usize;
            slot_to_symbol[start..end].fill(symbol as u16);
        }
        Ok(Self {
            symbols: symbols as u32,
            freq,
            cum: cum.iter().map(|&value| value as u16).collect(),
            slot_to_symbol,
        })
    }

    /// Number of distinct symbols in the alphabet.
    pub const fn symbols(&self) -> u32 {
        self.symbols
    }

    /// Total frequency mass (always [`RANS_M`]).
    pub const fn total(&self) -> u32 {
        RANS_M
    }

    /// Cumulative frequency before `symbol` (`0..=RANS_M`).
    pub fn cum(&self, symbol: u32) -> u32 {
        if symbol as usize >= self.cum.len() {
            0
        } else {
            u32::from(self.cum[symbol as usize])
        }
    }

    /// Frequency of `symbol`.
    pub fn freq(&self, symbol: u32) -> u32 {
        if symbol as usize >= self.freq.len() {
            0
        } else {
            u32::from(self.freq[symbol as usize])
        }
    }

    /// Maps a `0..RANS_M` slot to the symbol owning that slot.
    fn symbol_for_slot(&self, slot: u32) -> u32 {
        u32::from(self.slot_to_symbol[slot as usize])
    }
}

impl PartialEq for Model {
    fn eq(&self, other: &Self) -> bool {
        self.symbols == other.symbols && self.freq == other.freq
    }
}
impl Eq for Model {}

/// Forward rANS encoder. The emitted byte stream is reversed on `finish`.
///
/// The encoder owns its output buffer; decode the reverse order on the other
/// side with [`RansDecoder`].
pub struct RansEncoder {
    state: u64,
    bytes: Vec<u8>,
}

impl RansEncoder {
    /// Creates an encoder with the canonical initial state.
    pub fn new() -> Self {
        Self {
            state: RANS_L,
            bytes: Vec::new(),
        }
    }

    /// Encodes one symbol against `model`.
    ///
    /// Returns an error if `symbol` is outside the model's alphabet.
    pub fn put_symbol(&mut self, model: &Model, symbol: u32) -> Result<()> {
        let freq = model.freq(symbol);
        if freq == 0 {
            return Err(Error::Entropy("symbol outside the model alphabet"));
        }
        let cum = model.cum(symbol);
        // Renormalize: flush 16-bit words while the state is too large for
        // the encoded result to stay below 2^47.
        while self.state >= u64::from(freq) << RANS_EMIT_SHIFT {
            self.bytes
                .extend_from_slice(&(self.state as u16).to_le_bytes());
            self.state >>= RANS_BASE_BITS;
        }
        let quotient = self.state / u64::from(freq);
        let remainder = self.state % u64::from(freq);
        self.state = quotient * u64::from(RANS_M) + u64::from(cum) + remainder;
        Ok(())
    }

    /// Finishes coding and returns the final state and the byte stream.
    ///
    /// The byte stream is in emission order (the order the decoder reads it
    /// back, from the end of the frame payload).
    pub fn finish(self) -> (u64, Vec<u8>) {
        (self.state, self.bytes)
    }
}

impl Default for RansEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse-order rANS decoder over a payload produced by [`RansEncoder`].
pub struct RansDecoder<'a> {
    state: u64,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> RansDecoder<'a> {
    /// Creates a decoder from the final encoder state and payload bytes.
    ///
    /// `payload` is the exact byte stream returned by [`RansEncoder::finish`].
    pub fn new(final_state: u64, payload: &'a [u8]) -> Self {
        Self {
            state: final_state,
            bytes: payload,
            pos: payload.len(),
        }
    }

    fn renorm(&mut self) -> Result<()> {
        while self.state < RANS_L {
            if self.pos < 2 {
                return Err(Error::Entropy("truncated rANS payload"));
            }
            self.pos -= 2;
            let word = u16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
            self.state = (self.state << RANS_BASE_BITS) | u64::from(word);
        }
        Ok(())
    }

    /// Decodes the next symbol against `model`.
    pub fn get_symbol(&mut self, model: &Model) -> Result<u32> {
        self.renorm()?;
        let slot = (self.state % u64::from(RANS_M)) as u32;
        let symbol = model.symbol_for_slot(slot);
        let freq = model.freq(symbol);
        let cum = model.cum(symbol);
        let quotient = self.state / u64::from(RANS_M);
        self.state = quotient * u64::from(freq) + u64::from(slot) - u64::from(cum);
        Ok(symbol)
    }

    /// Validates that the stream terminated canonically.
    ///
    /// After decoding the declared symbol count, the state must have returned
    /// to the initial value and every payload byte must have been consumed.
    pub fn finish(self) -> Result<()> {
        if self.state != RANS_L {
            return Err(Error::Entropy("rANS final state did not verify"));
        }
        if self.pos != 0 {
            return Err(Error::Entropy("trailing bytes in rANS payload"));
        }
        Ok(())
    }
}

/// One per-field static model derived from a [`crate::Reflect`] shape.
#[derive(Clone, Debug)]
pub struct FieldModel {
    /// Field name (or `"variant"` for an enum's discriminant model).
    pub name: &'static str,
    /// Static model for the field's symbol alphabet.
    pub model: Model,
}

/// Schema-derived collection of per-field static models.
///
/// Built once from a [`crate::Reflect`] type, this provides the exact
/// alphabets the encoder and decoder both agree on without any transmission.
#[derive(Clone, Debug)]
pub struct SchemaModel {
    fields: Vec<FieldModel>,
}

impl SchemaModel {
    /// Derives one static model per top-level field of `T`.
    ///
    /// A struct yields one model per field; an enum yields a single model
    /// over its variant cardinality (named `"variant"`). Fields whose symbol
    /// alphabet is unknown (`symbols == 0` in the reflected metadata) fall
    /// back to a 256-symbol byte model.
    pub fn from_reflect<T: crate::Reflect>() -> Self {
        match T::SHAPE {
            crate::TypeShape::Struct(fields) => {
                let fields = fields
                    .iter()
                    .map(|field| FieldModel {
                        name: field.name,
                        model: model_for_field(field),
                    })
                    .collect();
                Self { fields }
            }
            crate::TypeShape::Enum(variants) => {
                let model = match Model::from_uniform(variants.len() as u32) {
                    Ok(model) => model,
                    Err(_) => Model::from_uniform(256).expect("byte alphabet is valid"),
                };
                Self {
                    fields: vec![FieldModel {
                        name: "variant",
                        model,
                    }],
                }
            }
        }
    }

    /// Returns the per-field models in declaration order.
    pub fn fields(&self) -> &[FieldModel] {
        &self.fields
    }

    /// Returns the per-field models as a slice (for [`EntropyConfig`]).
    pub fn models(&self) -> Vec<&Model> {
        self.fields.iter().map(|field| &field.model).collect()
    }
}

fn model_for_field(field: &crate::FieldInfo) -> Model {
    let symbols = if field.symbols == 0 {
        256
    } else {
        field.symbols
    };
    Model::from_uniform(symbols)
        .unwrap_or_else(|_| Model::from_uniform(256).expect("byte alphabet is valid"))
}

/// Parsed frame contents: `(count, final_state, is_raw, payload)`.
type UnwrappedFrame<'a> = (u64, u64, bool, &'a [u8]);

/// rANS entropy profile wrapping a [`Config`].
///
/// `EntropyConfig` keeps the resource policies of its base configuration and
/// adds framed, deterministic static-model entropy coding. The frame magic is
/// `RBAN`. Verification is hash-free: the decoder re-encodes the decoded
/// symbols and requires the frame to be canonical (see the module docs), with
/// replay verification on by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyConfig {
    base: Config,
    replay_verification: bool,
    raw_fallback: bool,
}

impl EntropyConfig {
    pub(crate) const fn new(base: Config) -> Self {
        Self {
            base,
            replay_verification: true,
            raw_fallback: true,
        }
    }

    /// Returns the underlying resource profile.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Disables replay verification.
    ///
    /// Without it, decoding still rejects truncated frames (final-state and
    /// consumption checks) but accepts any frame whose corrupted bytes happen
    /// to decode; substitution corruption is no longer detected. Only disable
    /// this when the transport authenticates bytes elsewhere (AEAD, TLS).
    pub const fn without_replay_verification(mut self) -> Self {
        self.replay_verification = false;
        self
    }

    /// Whether replay verification is enabled.
    pub const fn replay_verification(self) -> bool {
        self.replay_verification
    }

    /// Disables the raw (uncompressed) fallback in [`Self::compress`].
    ///
    /// Raw frames store the literal input and therefore carry no substitution
    /// detection — replay verification has nothing to re-encode. For an
    /// integrity boundary, disable the fallback so every frame is coded and
    /// replay-verified, at the cost of never storing the incompressible input
    /// as-is.
    pub const fn without_raw_fallback(mut self) -> Self {
        self.raw_fallback = false;
        self
    }

    /// Whether the raw (uncompressed) fallback is enabled.
    pub const fn raw_fallback(self) -> bool {
        self.raw_fallback
    }

    /// Encodes a sequence of symbols, each with its own model, into one frame.
    ///
    /// `models` and `symbols` must have the same length. Every symbol is coded
    /// with the matching model, so the decoder must replay the same model
    /// slice in the same order.
    pub fn encode_sequence(&self, models: &[&Model], symbols: &[u32]) -> Result<Vec<u8>> {
        if models.len() != symbols.len() {
            return Err(Error::Entropy("models and symbols length mismatch"));
        }
        let mut encoder = RansEncoder::new();
        for (model, &symbol) in models.iter().zip(symbols) {
            encoder.put_symbol(model, symbol)?;
        }
        let (final_state, payload) = encoder.finish();
        self.wrap(final_state, symbols.len() as u64, payload, false)
    }

    /// Decodes a sequence coded by [`Self::encode_sequence`].
    ///
    /// `models` must match the encoder's model slice exactly. When replay
    /// verification is enabled, the frame is accepted only if re-encoding the
    /// decoded symbols reproduces the stored payload and final state.
    pub fn decode_sequence(&self, models: &[&Model], input: &[u8]) -> Result<Vec<u32>> {
        let (count, final_state, raw, payload) = self.unwrap(input)?;
        let count = usize::try_from(count)
            .map_err(|_| Error::Entropy("entropy frame symbol count does not fit usize"))?;
        if count != models.len() {
            return Err(Error::Entropy("entropy frame symbol count mismatch"));
        }
        if raw {
            let expected = count
                .checked_mul(4)
                .ok_or(Error::Entropy("raw entropy frame length overflows"))?;
            if payload.len() != expected {
                return Err(Error::Entropy("raw entropy frame length mismatch"));
            }
            let mut symbols = Vec::with_capacity(count);
            for chunk in payload.chunks_exact(4) {
                symbols.push(u32::from_le_bytes(
                    chunk.try_into().expect("fixed chunk width"),
                ));
            }
            return Ok(symbols);
        }
        let mut decoder = RansDecoder::new(final_state, payload);
        // rANS decodes in the reverse of encode order, so the models must be
        // replayed in reverse and the output must be reversed back.
        let mut symbols = Vec::with_capacity(count);
        for model in models.iter().rev() {
            symbols.push(decoder.get_symbol(model)?);
        }
        symbols.reverse();
        decoder.finish()?;
        if self.replay_verification {
            let mut encoder = RansEncoder::new();
            for (model, &symbol) in models.iter().zip(&symbols) {
                encoder.put_symbol(model, symbol)?;
            }
            let (state, replay) = encoder.finish();
            check_replay(state, &replay, final_state, payload)?;
        }
        Ok(symbols)
    }

    /// Entropy-codes a byte buffer with one model, choosing raw storage when
    /// the coded form is not smaller.
    pub fn compress(&self, input: &[u8], model: &Model) -> Result<Vec<u8>> {
        let mut encoder = RansEncoder::new();
        for &byte in input {
            encoder.put_symbol(model, u32::from(byte))?;
        }
        let (final_state, coded) = encoder.finish();
        // The raw fallback stores the original bytes, not the coded form. It
        // is disabled by `without_raw_fallback` so every frame stays
        // replay-verifiable.
        let raw = self.raw_fallback && coded.len() >= input.len();
        let payload = if raw { input.to_vec() } else { coded };
        self.wrap(final_state, input.len() as u64, payload, raw)
    }

    /// Decompresses a frame produced by [`Self::compress`].
    pub fn decompress(&self, input: &[u8], model: &Model) -> Result<Vec<u8>> {
        let (count, final_state, raw, payload) = self.unwrap(input)?;
        let count = usize::try_from(count)
            .map_err(|_| Error::Entropy("entropy frame length does not fit usize"))?;
        if raw {
            if payload.len() != count {
                return Err(Error::Entropy("raw entropy frame length mismatch"));
            }
            return Ok(payload.to_vec());
        }
        let mut decoder = RansDecoder::new(final_state, payload);
        // rANS decodes in reverse order, so reverse the output back to the
        // original byte order.
        let mut output = Vec::with_capacity(count);
        for _ in 0..count {
            let symbol = decoder.get_symbol(model)?;
            if symbol > 255 {
                return Err(Error::Entropy(
                    "byte-alphabet rANS produced an out-of-range symbol",
                ));
            }
            output.push(symbol as u8);
        }
        output.reverse();
        decoder.finish()?;
        if self.replay_verification {
            let mut encoder = RansEncoder::new();
            for &byte in &output {
                encoder.put_symbol(model, u32::from(byte))?;
            }
            let (state, replay) = encoder.finish();
            check_replay(state, &replay, final_state, payload)?;
        }
        Ok(output)
    }

    /// Wraps a payload in a versioned entropy frame.
    fn wrap(&self, final_state: u64, count: u64, payload: Vec<u8>, raw: bool) -> Result<Vec<u8>> {
        let total = HEADER_LEN
            .checked_add(payload.len())
            .ok_or(Error::SizeLimit { limit: u64::MAX })?;
        self.enforce_byte_limit(total)?;
        // Raw frames carry a zero state so `unwrap` can reject a raw frame
        // with a non-zero state (a corruption marker).
        let stored_state = if raw { 0 } else { final_state };
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        output.extend_from_slice(&if raw { FLAG_RAW } else { 0 }.to_le_bytes());
        output.extend_from_slice(&count.to_le_bytes());
        output.extend_from_slice(&stored_state.to_le_bytes());
        output.extend_from_slice(&payload);
        Ok(output)
    }

    /// Parses and validates a frame, returning
    /// `(count, final_state, is_raw, payload)`.
    fn unwrap<'a>(&self, input: &'a [u8]) -> Result<UnwrappedFrame<'a>> {
        self.enforce_byte_limit(input.len())?;
        let header = input.get(..HEADER_LEN).ok_or(Error::UnexpectedEnd)?;
        if header[..4] != MAGIC {
            return Err(Error::InvalidFrame("entropy magic does not match"));
        }
        if u16::from_le_bytes([header[4], header[5]]) != FORMAT_VERSION {
            return Err(Error::InvalidFrame("unsupported entropy format version"));
        }
        let flags = u16::from_le_bytes([header[6], header[7]]);
        if flags & !FLAG_RAW != 0 {
            return Err(Error::InvalidFrame("unknown entropy frame flags"));
        }
        let count = u64::from_le_bytes(header[8..16].try_into().expect("fixed header width"));
        let final_state =
            u64::from_le_bytes(header[16..24].try_into().expect("fixed header width"));
        let payload = &input[HEADER_LEN..];
        if flags & FLAG_RAW != 0 && final_state != 0 {
            return Err(Error::InvalidFrame(
                "raw entropy frame has a non-zero state",
            ));
        }
        Ok((count, final_state, flags & FLAG_RAW != 0, payload))
    }

    fn enforce_byte_limit(&self, length: usize) -> Result<()> {
        if let Some(limit) = self.base.limit {
            if length as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_model(model: &Model, symbols: &[u32]) {
        let config = EntropyConfig::new(Config::standard());
        let models: Vec<&Model> = core::iter::repeat(model).take(symbols.len()).collect();
        let frame = config.encode_sequence(&models, symbols).unwrap();
        let decoded = config.decode_sequence(&models, &frame).unwrap();
        assert_eq!(decoded, symbols, "roundtrip for model {:?}", model);
    }

    #[test]
    fn uniform_models_roundtrip_exhaustively() {
        for symbols in 1..=64u32 {
            let model = Model::from_uniform(symbols).unwrap();
            assert_eq!(model.symbols(), symbols);
            let mut data = Vec::new();
            for index in 0..(symbols * 3) {
                data.push(index % symbols);
            }
            roundtrip_model(&model, &data);
        }
    }

    #[test]
    fn non_power_of_two_alphabet_beats_ceil_bits() {
        // A 3-symbol alphabet costs log2(3) ~= 1.585 bits/symbol.
        let model = Model::from_uniform(3).unwrap();
        let config = EntropyConfig::new(Config::standard());
        let symbols = [0u32, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2];
        let models: Vec<&Model> = core::iter::repeat(&model).take(symbols.len()).collect();
        let frame = config.encode_sequence(&models, &symbols).unwrap();
        // 12 symbols * 1.585 bits = 19.02 bits -> 3 bytes + 24-byte header.
        assert!(frame.len() < 24 + 12, "frame too large: {}", frame.len());
        assert_eq!(config.decode_sequence(&models, &frame).unwrap(), symbols);
    }

    #[test]
    fn weighted_models_roundtrip_and_scale() {
        let model = Model::from_weights(&[9, 1]).unwrap();
        assert_eq!(model.total(), RANS_M);
        let symbols = [0u32, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        roundtrip_model(&model, &symbols);

        let skewed = Model::from_weights(&[100, 1, 1]).unwrap();
        assert_eq!(skewed.total(), RANS_M);
        assert!(skewed.freq(0) > skewed.freq(1));
        assert!(skewed.freq(1) == skewed.freq(2));
        roundtrip_model(&skewed, &[0, 0, 1, 2, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn skewed_prior_compresses_repetitive_bytes() {
        let model = Model::from_weights(&[255, 1]).unwrap();
        let config = EntropyConfig::new(Config::standard());
        let input = vec![0u8; 256];
        let frame = config.compress(&input, &model).unwrap();
        let decoded = config.decompress(&frame, &model).unwrap();
        assert_eq!(decoded, input);
        // 256 zero bytes at p=255/256 need ~8 bits total; the header dominates.
        assert!(frame.len() < 24 + 16, "frame too large: {}", frame.len());
    }

    #[test]
    fn compress_falls_back_to_raw_when_not_smaller() {
        let model = Model::from_uniform(256).unwrap();
        let config = EntropyConfig::new(Config::standard());
        // Pseudo-random byte data cannot be compressed by a uniform model.
        let input: Vec<u8> = (0..4096)
            .map(|index| ((index * 37) ^ (index >> 3)) as u8)
            .collect();
        let frame = config.compress(&input, &model).unwrap();
        assert!(frame.len() <= HEADER_LEN + input.len());
        // The raw flag must be set exactly when the frame stores raw bytes.
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        assert_eq!(
            flags & FLAG_RAW != 0,
            frame.len() == HEADER_LEN + input.len()
        );
        assert_eq!(config.decompress(&frame, &model).unwrap(), input);
    }

    #[test]
    fn corrupt_frames_are_rejected() {
        // Use compressible data so the frame is definitely rANS-coded (the
        // raw fallback does not validate payload content by design).
        let mut weights = vec![1u32; 256];
        weights[b'a' as usize] = 1000;
        let model = Model::from_weights(&weights).unwrap();
        let config = EntropyConfig::new(Config::standard());
        let input = vec![b'a'; 64];
        let frame = config.compress(&input, &model).unwrap();
        assert!(frame.len() < HEADER_LEN + input.len(), "frame is not coded");

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(config.decompress(&truncated, &model).is_err());

        let mut corrupted = frame.clone();
        let payload_start = HEADER_LEN;
        corrupted[payload_start] ^= 0x5a;
        assert!(config.decompress(&corrupted, &model).is_err());

        let mut wrong_magic = frame.clone();
        wrong_magic[0] = b'X';
        assert!(matches!(
            config.decompress(&wrong_magic, &model),
            Err(Error::InvalidFrame(_))
        ));

        let mut wrong_state = frame.clone();
        wrong_state[16] ^= 1;
        assert!(config.decompress(&wrong_state, &model).is_err());

        // The count field is validated too: a mismatch is a protocol error.
        let mut wrong_count = frame.clone();
        wrong_count[8] ^= 1;
        assert!(config.decompress(&wrong_count, &model).is_err());
    }

    #[test]
    fn replay_verification_catches_substitution() {
        // Compressible data -> a coded frame.
        let mut weights = vec![1u32; 256];
        weights[b'x' as usize] = 1000;
        let model = Model::from_weights(&weights).unwrap();
        let verified = EntropyConfig::new(Config::standard());
        let input = vec![b'x'; 256];
        let frame = verified.compress(&input, &model).unwrap();
        assert!(frame.len() < HEADER_LEN + input.len(), "frame is not coded");
        assert_eq!(verified.decompress(&frame, &model).unwrap(), input);

        // A substitution that leaves the frame decodable is caught by the
        // hash-free replay: the decoded payload re-encodes differently.
        for offset in HEADER_LEN..frame.len() {
            let mut tampered = frame.clone();
            tampered[offset] ^= 0x40;
            let result = verified.decompress(&tampered, &model);
            match result {
                Err(_) => {}
                Ok(decoded) => assert_ne!(decoded, input, "corruption at {offset} is silent"),
            }
        }

        // Disabling replay turns the coded frame into a trust-on-decoding
        // stream: the corruption above may decode to garbage without error.
        let unchecked = verified.without_replay_verification();
        let mut tampered = frame.clone();
        tampered[HEADER_LEN] ^= 0x40;
        if let Ok(decoded) = unchecked.decompress(&tampered, &model) {
            assert_ne!(decoded, input);
        }
    }

    #[test]
    fn without_raw_fallback_keeps_every_frame_coded() {
        let model = Model::from_uniform(256).unwrap();
        let verified = EntropyConfig::new(Config::standard()).without_raw_fallback();
        // Pseudo-random data is incompressible under a uniform model; with the
        // fallback disabled the frame is coded anyway (never stored raw), so
        // it remains replay-verifiable and any substitution is caught.
        let input: Vec<u8> = (0..4096).map(|i| ((i * 37) ^ (i >> 3)) as u8).collect();
        let frame = verified.compress(&input, &model).unwrap();
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        assert_eq!(flags & FLAG_RAW, 0, "raw fallback must be off");
        // The coded form is never replaced by raw bytes, so the frame is
        // always replay-verifiable (coded frames are the verified path).
        assert!(frame.len() >= HEADER_LEN + input.len());
        assert_eq!(verified.decompress(&frame, &model).unwrap(), input);

        // A payload corruption is always caught: either rejected outright, or
        // the decoded payload differs from the original (a corrupted frame can
        // never replay to the original bytes).
        let mut tampered = frame.clone();
        tampered[HEADER_LEN] ^= 0x80;
        match verified.decompress(&tampered, &model) {
            Err(_) => {}
            Ok(bytes) => assert_ne!(bytes, input, "corruption is silent"),
        }
    }

    #[test]
    fn empty_sequence_roundtrips() {
        let config = EntropyConfig::new(Config::standard());
        let frame = config.encode_sequence(&[], &[]).unwrap();
        assert_eq!(
            config.decode_sequence(&[], &frame).unwrap(),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn schema_model_derives_per_field_alphabets() {
        #[allow(dead_code)]
        struct Telemetry {
            kind: TelemetryKind,
            priority: u8,
            level: bool,
            payload: u8,
        }
        impl crate::Reflect for Telemetry {
            const TYPE_NAME: &'static str = "tests::Telemetry";
            const SHAPE: crate::TypeShape = crate::TypeShape::Struct(&[
                crate::FieldInfo {
                    name: "kind",
                    type_name: "TelemetryKind",
                    index: 0,
                    symbols: 0,
                },
                crate::FieldInfo {
                    name: "priority",
                    type_name: "u8",
                    index: 1,
                    symbols: 10,
                },
                crate::FieldInfo {
                    name: "level",
                    type_name: "bool",
                    index: 2,
                    symbols: 2,
                },
                crate::FieldInfo {
                    name: "payload",
                    type_name: "u8",
                    index: 3,
                    symbols: 256,
                },
            ]);
        }

        #[allow(dead_code)]
        enum TelemetryKind {
            Temperature,
            Pressure,
            Humidity,
            Wind,
        }
        impl crate::Reflect for TelemetryKind {
            const TYPE_NAME: &'static str = "tests::TelemetryKind";
            const SHAPE: crate::TypeShape = crate::TypeShape::Enum(&[
                crate::VariantInfo {
                    name: "Temperature",
                    index: 0,
                    fields: &[],
                },
                crate::VariantInfo {
                    name: "Pressure",
                    index: 1,
                    fields: &[],
                },
                crate::VariantInfo {
                    name: "Humidity",
                    index: 2,
                    fields: &[],
                },
                crate::VariantInfo {
                    name: "Wind",
                    index: 3,
                    fields: &[],
                },
            ]);
        }

        let schema = SchemaModel::from_reflect::<Telemetry>();
        let names: Vec<&'static str> = schema.fields().iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["kind", "priority", "level", "payload"]);
        // Enum field: unknown at derive time -> byte fallback (256).
        assert_eq!(schema.fields()[0].model.symbols(), 256);
        // Explicit #[entropy(symbols = 10)].
        assert_eq!(schema.fields()[1].model.symbols(), 10);
        // bool -> 2.
        assert_eq!(schema.fields()[2].model.symbols(), 2);
        // u8 -> 256.
        assert_eq!(schema.fields()[3].model.symbols(), 256);

        let enum_schema = SchemaModel::from_reflect::<TelemetryKind>();
        assert_eq!(enum_schema.fields()[0].name, "variant");
        assert_eq!(enum_schema.fields()[0].model.symbols(), 4);
    }

    #[test]
    fn schema_models_drive_a_sequence() {
        #[allow(dead_code)]
        struct Frame {
            flag: bool,
            lane: u8,
        }
        impl crate::Reflect for Frame {
            const TYPE_NAME: &'static str = "tests::Frame";
            const SHAPE: crate::TypeShape = crate::TypeShape::Struct(&[
                crate::FieldInfo {
                    name: "flag",
                    type_name: "bool",
                    index: 0,
                    symbols: 2,
                },
                crate::FieldInfo {
                    name: "lane",
                    type_name: "u8",
                    index: 1,
                    symbols: 3,
                },
            ]);
        }

        let schema = SchemaModel::from_reflect::<Frame>();
        let field_models = schema.models();
        // One model per symbol: the frame interleaves flag/lane fields.
        let mut models = Vec::new();
        for index in 0..6 {
            models.push(field_models[index % 2]);
        }
        let config = EntropyConfig::new(Config::standard());
        // Interleaved (flag in {0,1}, lane in {0,1,2}) symbols.
        let symbols = [1u32, 2, 0, 1, 1, 0];
        let frame = config.encode_sequence(&models, &symbols).unwrap();
        assert_eq!(config.decode_sequence(&models, &frame).unwrap(), symbols);
    }

    #[test]
    fn invalid_models_and_symbols_are_rejected() {
        assert!(Model::from_uniform(0).is_err());
        assert!(Model::from_uniform(RANS_M + 1).is_err());
        assert!(Model::from_weights(&[]).is_err());
        assert!(Model::from_weights(&[0, 0]).is_err());

        let model = Model::from_uniform(3).unwrap();
        let mut encoder = RansEncoder::new();
        assert!(encoder.put_symbol(&model, 3).is_err());

        let config = EntropyConfig::new(Config::standard());
        let models: Vec<&Model> = core::iter::repeat(&model).take(2).collect();
        let frame = config.encode_sequence(&models, &[0, 1]).unwrap();
        // Mismatched model count must be rejected.
        let one_model = &models[..1];
        assert!(config.decode_sequence(one_model, &frame).is_err());
    }
}
