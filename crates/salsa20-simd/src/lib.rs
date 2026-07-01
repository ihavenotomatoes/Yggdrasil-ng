//! Implementation of the [Salsa] family of stream ciphers.
//!
//! Cipher functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! USE AT YOUR OWN RISK!
//!
//! # Diagram
//!
//! This diagram illustrates the Salsa quarter round function.
//! Each round consists of four quarter-rounds:
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/img/stream-ciphers/salsa20.png" width="300px">
//!
//! Legend:
//!
//! - ⊞ add
//! - ‹‹‹ rotate
//! - ⊕ xor
//!
//! # Example
//! ```
//! use salsa20::Salsa20;
//! // Import relevant traits
//! use salsa20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
//! use hex_literal::hex;
//!
//! let key = [0x42; 32];
//! let nonce = [0x24; 8];
//! let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
//! let ciphertext = hex!("85843cc5 d58cce7b 5dd3dd04 fa005ded");
//!
//! // Key and IV must be references to the `GenericArray` type.
//! // Here we use the `Into` trait to convert arrays into it.
//! let mut cipher = Salsa20::new(&key.into(), &nonce.into());
//!
//! let mut buffer = plaintext.clone();
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, ciphertext);
//!
//! let ciphertext = buffer.clone();
//!
//! // Salsa ciphers support seeking
//! cipher.seek(0u32);
//!
//! // decrypt ciphertext by applying keystream again
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, plaintext);
//!
//! // stream ciphers can be used with streaming messages
//! cipher.seek(0u32);
//! for chunk in buffer.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buffer, ciphertext);
//! ```
//!
//! [Salsa]: https://en.wikipedia.org/wiki/Salsa20

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/salsa20/0.10.2"
)]
// NOTE (fork): upstream sets `#![forbid(unsafe_code)]`. The AVX2 backend needs
// `unsafe` for SIMD intrinsics, so this fork allows it.
#![allow(unsafe_code)]
#![warn(rust_2018_idioms, trivial_casts, unused_qualifications)]

pub use cipher;

use cipher::{
    consts::{U1, U10, U24, U32, U4, U6, U64, U8},
    generic_array::{typenum::Unsigned, GenericArray},
    Block, BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamBackend,
    StreamCipherCore, StreamCipherCoreWrapper, StreamCipherSeekCore, StreamClosure,
};
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod xsalsa;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod sse2;
#[cfg(target_arch = "aarch64")]
mod neon;

// Runtime feature detection (results are cached after the first query).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(avx2_cpuid, "avx2");
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(sse2_cpuid, "sse2");

pub use xsalsa::{hsalsa, XSalsa12, XSalsa20, XSalsa8, XSalsaCore};

/// Salsa20/8 stream cipher
/// (reduced-round variant of Salsa20 with 8 rounds, *not recommended*)
pub type Salsa8 = StreamCipherCoreWrapper<SalsaCore<U4>>;

/// Salsa20/12 stream cipher
/// (reduced-round variant of Salsa20 with 12 rounds, *not recommended*)
pub type Salsa12 = StreamCipherCoreWrapper<SalsaCore<U6>>;

/// Salsa20/20 stream cipher
/// (20 rounds; **recommended**)
pub type Salsa20 = StreamCipherCoreWrapper<SalsaCore<U10>>;

/// Key type used by all Salsa variants and [`XSalsa20`].
pub type Key = GenericArray<u8, U32>;

/// Nonce type used by all Salsa variants.
pub type Nonce = GenericArray<u8, U8>;

/// Nonce type used by [`XSalsa20`].
pub type XNonce = GenericArray<u8, U24>;

/// Number of 32-bit words in the Salsa20 state
const STATE_WORDS: usize = 16;

/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The Salsa20 core function.
pub struct SalsaCore<R: Unsigned> {
    /// Internal state of the core function
    state: [u32; STATE_WORDS],
    /// Number of rounds to perform
    rounds: PhantomData<R>,
}

impl<R: Unsigned> SalsaCore<R> {
    /// Create new Salsa core from raw state.
    ///
    /// This method is mainly intended for the `scrypt` crate.
    /// Other users generally should not use this method.
    pub fn from_raw_state(state: [u32; STATE_WORDS]) -> Self {
        Self {
            state,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> KeySizeUser for SalsaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for SalsaCore<R> {
    type IvSize = U8;
}

impl<R: Unsigned> BlockSizeUser for SalsaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for SalsaCore<R> {
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0] = CONSTANTS[0];

        for (i, chunk) in key[..16].chunks(4).enumerate() {
            state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[5] = CONSTANTS[1];

        for (i, chunk) in iv.chunks(4).enumerate() {
            state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[8] = 0;
        state[9] = 0;
        state[10] = CONSTANTS[2];

        for (i, chunk) in key[16..].chunks(4).enumerate() {
            state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        state[15] = CONSTANTS[3];

        Self {
            state,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> StreamCipherCore for SalsaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u64::MAX - self.get_block_pos();
        rem.try_into().ok()
    }
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        // x86 / x86_64: AVX2 (8-way) -> SSE2 (4-way) -> scalar, chosen at
        // runtime. The `force-*` features pin one backend for benchmarking or
        // testing. Exactly one cfg block below is compiled per configuration,
        // so `f` is consumed exactly once.
        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "force-soft"))]
        {
            f.call(&mut Backend(self));
        }
        #[cfg(all(
            any(target_arch = "x86", target_arch = "x86_64"),
            feature = "force-sse2",
            not(feature = "force-soft")
        ))]
        {
            sse2::inner::<R, _>(&mut self.state, f);
        }
        #[cfg(all(
            any(target_arch = "x86", target_arch = "x86_64"),
            feature = "force-avx2",
            not(any(feature = "force-soft", feature = "force-sse2"))
        ))]
        {
            avx2::inner::<R, _>(&mut self.state, f);
        }
        #[cfg(all(
            any(target_arch = "x86", target_arch = "x86_64"),
            not(any(feature = "force-soft", feature = "force-sse2", feature = "force-avx2"))
        ))]
        {
            if avx2_cpuid::get() {
                avx2::inner::<R, _>(&mut self.state, f);
            } else if sse2_cpuid::get() {
                sse2::inner::<R, _>(&mut self.state, f);
            } else {
                f.call(&mut Backend(self));
            }
        }

        // aarch64: NEON (4-way) is part of the baseline ISA.
        #[cfg(target_arch = "aarch64")]
        {
            neon::inner::<R, _>(&mut self.state, f);
        }

        // Any other architecture: scalar.
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        {
            f.call(&mut Backend(self));
        }
    }
}

impl<R: Unsigned> StreamCipherSeekCore for SalsaCore<R> {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> u64 {
        (self.state[8] as u64) + ((self.state[9] as u64) << 32)
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u64) {
        self.state[8] = (pos & 0xffff_ffff) as u32;
        self.state[9] = ((pos >> 32) & 0xffff_ffff) as u32;
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> Drop for SalsaCore<R> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<R: Unsigned> ZeroizeOnDrop for SalsaCore<R> {}

// The scalar fallback is unused on targets that always have a SIMD backend
// (e.g. aarch64 / NEON); silence the resulting dead-code warning there.
#[allow(dead_code)]
struct Backend<'a, R: Unsigned>(&'a mut SalsaCore<R>);

impl<'a, R: Unsigned> BlockSizeUser for Backend<'a, R> {
    type BlockSize = U64;
}

impl<'a, R: Unsigned> ParBlocksSizeUser for Backend<'a, R> {
    type ParBlocksSize = U1;
}

impl<'a, R: Unsigned> StreamBackend for Backend<'a, R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let res = run_rounds::<R>(&self.0.state);
        self.0.set_block_pos(self.0.get_block_pos() + 1);

        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[inline]
#[allow(clippy::many_single_char_names)]
pub(crate) fn quarter_round(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    state: &mut [u32; STATE_WORDS],
) {
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}

#[inline(always)]
fn run_rounds<R: Unsigned>(state: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut res = *state;

    for _ in 0..R::USIZE {
        // column rounds
        quarter_round(0, 4, 8, 12, &mut res);
        quarter_round(5, 9, 13, 1, &mut res);
        quarter_round(10, 14, 2, 6, &mut res);
        quarter_round(15, 3, 7, 11, &mut res);

        // diagonal rounds
        quarter_round(0, 1, 2, 3, &mut res);
        quarter_round(5, 6, 7, 4, &mut res);
        quarter_round(10, 11, 8, 9, &mut res);
        quarter_round(15, 12, 13, 14, &mut res);
    }

    for (s1, s0) in res.iter_mut().zip(state.iter()) {
        *s1 = s1.wrapping_add(*s0);
    }
    res
}

/// Shared helpers for the SIMD backends' differential tests.
#[cfg(test)]
pub(crate) mod test_util {
    use super::{run_rounds, CONSTANTS, STATE_WORDS};
    use cipher::consts::U10;

    /// Build the Salsa20/20 initial state the way `SalsaCore::new` does.
    pub(crate) fn salsa20_state(key: &[u8; 32], nonce: &[u8; 8]) -> [u32; STATE_WORDS] {
        let mut state = [0u32; STATE_WORDS];
        state[0] = CONSTANTS[0];
        for (i, chunk) in key[..16].chunks(4).enumerate() {
            state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        state[5] = CONSTANTS[1];
        for (i, chunk) in nonce.chunks(4).enumerate() {
            state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        state[10] = CONSTANTS[2];
        for (i, chunk) in key[16..].chunks(4).enumerate() {
            state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        state[15] = CONSTANTS[3];
        state
    }

    /// Scalar reference Salsa20/20 keystream for one block at a given counter.
    pub(crate) fn scalar_block(state: &[u32; STATE_WORDS], counter: u64) -> [u8; 64] {
        let mut s = *state;
        s[8] = counter as u32;
        s[9] = (counter >> 32) as u32;
        let res = run_rounds::<U10>(&s);
        let mut out = [0u8; 64];
        for (chunk, val) in out.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        out
    }
}
