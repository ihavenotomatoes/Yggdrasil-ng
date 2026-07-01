//! AVX2 backend for the Salsa20 core (fork addition).
//!
//! Layout: "one state word per 256-bit register, eight blocks across the lanes".
//! Register `v[w]` holds word `w` of 8 consecutive-counter blocks, so Salsa20's
//! quarter-round is pure vertical SIMD (add / xor / rotate) with no in-round
//! shuffles. A single transpose at the end writes the 8 output blocks. The
//! keystream is byte-identical to the scalar backend (verified by the tests
//! below); only the speed differs.

use cipher::{
    consts::{U64, U8},
    Block, BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
};
use core::marker::PhantomData;

use super::{run_rounds, Unsigned, STATE_WORDS};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Number of blocks generated per AVX2 group.
const PAR_BLOCKS: usize = 8;

/// Entry point used by `SalsaCore::process_with_backend` when AVX2 is present.
///
/// Builds a [`Backend`] from the current core state, drives the cipher closure,
/// then writes the advanced 64-bit block counter back into `state`.
#[inline]
pub(crate) fn inner<R, F>(state: &mut [u32; STATE_WORDS], f: F)
where
    R: Unsigned,
    F: StreamClosure<BlockSize = U64>,
{
    let counter = (state[8] as u64) | ((state[9] as u64) << 32);
    let mut backend = Backend::<R> {
        state: *state,
        counter,
        _pd: PhantomData,
    };
    f.call(&mut backend);
    state[8] = backend.counter as u32;
    state[9] = (backend.counter >> 32) as u32;
}

struct Backend<R: Unsigned> {
    /// Snapshot of the core state. The counter words (8, 9) are ignored; the
    /// live block position is tracked in `counter`.
    state: [u32; STATE_WORDS],
    /// Block position of the next block to generate.
    counter: u64,
    _pd: PhantomData<R>,
}

impl<R: Unsigned> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U8;
}

impl<R: Unsigned> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        // Single-block tail (fewer than 8 blocks left): scalar avoids AVX2 setup.
        let mut state = self.state;
        state[8] = self.counter as u32;
        state[9] = (self.counter >> 32) as u32;
        let res = run_rounds::<R>(&state);
        self.counter += 1;
        for (chunk, val) in block.chunks_exact_mut(4).zip(res.iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut ParBlocks<Self>) {
        // SAFETY: `inner` is only reached after a positive AVX2 runtime check,
        // so the AVX2 target feature is available on this CPU.
        unsafe { keystream8::<R>(&self.state, self.counter, blocks) };
        self.counter += PAR_BLOCKS as u64;
    }

    #[inline(always)]
    fn gen_tail_blocks(&mut self, blocks: &mut [Block<Self>]) {
        // Final 1..8 whole blocks. Generating a full 8-block AVX2 group into a
        // scratch and copying the needed ones still beats running the scalar
        // core per block.
        let n = blocks.len();
        if n == 0 {
            return;
        }
        let mut scratch = ParBlocks::<Self>::default();
        // SAFETY: see `gen_par_ks_blocks`.
        unsafe { keystream8::<R>(&self.state, self.counter, &mut scratch) };
        for (dst, src) in blocks.iter_mut().zip(scratch.iter()) {
            dst.copy_from_slice(src);
        }
        self.counter += n as u64;
    }
}

// `#[target_feature]` forbids `#[inline(always)]`; `#[inline]` is the strongest
// hint allowed, and the helpers below do get folded into `keystream8`.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl7(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 25))
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl9(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 9), _mm256_srli_epi32(x, 23))
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl13(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 13), _mm256_srli_epi32(x, 19))
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotl18(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32(x, 18), _mm256_srli_epi32(x, 14))
}

/// One Salsa20 quarter-round applied to all 8 lanes at once.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn quarter_round(v: &mut [__m256i; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[b] = _mm256_xor_si256(v[b], rotl7(_mm256_add_epi32(v[a], v[d])));
    v[c] = _mm256_xor_si256(v[c], rotl9(_mm256_add_epi32(v[b], v[a])));
    v[d] = _mm256_xor_si256(v[d], rotl13(_mm256_add_epi32(v[c], v[b])));
    v[a] = _mm256_xor_si256(v[a], rotl18(_mm256_add_epi32(v[d], v[c])));
}

/// Generate 8 keystream blocks for counters `counter..counter+8` into `blocks`.
#[target_feature(enable = "avx2")]
unsafe fn keystream8<R: Unsigned>(
    state: &[u32; STATE_WORDS],
    counter: u64,
    blocks: &mut ParBlocks<Backend<R>>,
) {
    // Broadcast each state word across the 8 lanes; words 8/9 hold per-lane
    // (little-endian split) block counters.
    let mut v = [_mm256_setzero_si256(); STATE_WORDS];
    for w in 0..STATE_WORDS {
        v[w] = _mm256_set1_epi32(state[w] as i32);
    }
    let mut lo = [0i32; 8];
    let mut hi = [0i32; 8];
    for j in 0..8 {
        let cj = counter.wrapping_add(j as u64);
        lo[j] = cj as u32 as i32;
        hi[j] = (cj >> 32) as u32 as i32;
    }
    v[8] = _mm256_setr_epi32(lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], lo[7]);
    v[9] = _mm256_setr_epi32(hi[0], hi[1], hi[2], hi[3], hi[4], hi[5], hi[6], hi[7]);

    let orig = v;

    for _ in 0..R::USIZE {
        // column rounds
        quarter_round(&mut v, 0, 4, 8, 12);
        quarter_round(&mut v, 5, 9, 13, 1);
        quarter_round(&mut v, 10, 14, 2, 6);
        quarter_round(&mut v, 15, 3, 7, 11);
        // diagonal rounds
        quarter_round(&mut v, 0, 1, 2, 3);
        quarter_round(&mut v, 5, 6, 7, 4);
        quarter_round(&mut v, 10, 11, 8, 9);
        quarter_round(&mut v, 15, 12, 13, 14);
    }

    for w in 0..STATE_WORDS {
        v[w] = _mm256_add_epi32(v[w], orig[w]);
    }

    // Transpose lanes -> blocks. `tmp[w]` holds word `w` for each of the 8 blocks.
    let mut tmp = [[0u32; 8]; STATE_WORDS];
    for w in 0..STATE_WORDS {
        _mm256_storeu_si256(tmp[w].as_mut_ptr() as *mut __m256i, v[w]);
    }
    for blk in 0..8 {
        let out = &mut blocks[blk];
        for word in 0..STATE_WORDS {
            out[word * 4..word * 4 + 4].copy_from_slice(&tmp[word][blk].to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::keystream8;
    use crate::test_util::{salsa20_state, scalar_block};
    use crate::{Key, Nonce, Salsa20};
    use cipher::consts::{U10, U64, U8};
    use cipher::generic_array::GenericArray;
    use cipher::{KeyIvInit, StreamCipher};

    // The AVX2 8-block keystream must match the scalar reference exactly, for a
    // range of base counters (including ones that exercise the 32-bit carry into
    // the high counter word).
    #[test]
    fn avx2_matches_scalar_blocks() {
        if !crate::avx2_cpuid::get() {
            return; // no AVX2 on this CPU
        }
        let key = [7u8; 32];
        let nonce = [0x42u8; 8];
        let state = salsa20_state(&key, &nonce);

        for &base in &[0u64, 1, 7, 8, 100, (u32::MAX as u64) - 3, 1u64 << 32] {
            let mut blocks =
                GenericArray::<GenericArray<u8, U64>, U8>::default();
            unsafe { keystream8::<U10>(&state, base, &mut blocks) };
            for j in 0..8 {
                let expected = scalar_block(&state, base + j as u64);
                assert_eq!(
                    blocks[j].as_slice(),
                    &expected[..],
                    "block mismatch at base={base}, lane={j}"
                );
            }
        }
    }

    // End-to-end: the public `Salsa20` cipher (which dispatches through the AVX2
    // par-block path plus the scalar tail and counter write-back) must produce
    // the same keystream as an independent block-by-block scalar computation,
    // over a length that spans multiple 8-block groups and a partial tail.
    #[test]
    fn avx2_public_api_matches_scalar_stream() {
        if !crate::avx2_cpuid::get() {
            return; // no AVX2 on this CPU
        }
        let key = [0x24u8; 32];
        let nonce = [0x11u8; 8];

        const LEN: usize = 8 * 64 * 3 + 130; // 3 full AVX2 groups + partial tail
        let mut buf = [0u8; LEN];
        let kref = Key::from_slice(&key);
        let nref = Nonce::from_slice(&nonce);
        Salsa20::new(kref, nref).apply_keystream(&mut buf);

        let state = salsa20_state(&key, &nonce);
        let mut expected = [0u8; LEN];
        for (b, ksblk) in expected.chunks_mut(64).enumerate() {
            let blk = scalar_block(&state, b as u64);
            ksblk.copy_from_slice(&blk[..ksblk.len()]);
        }
        assert_eq!(&buf[..], &expected[..]);
    }
}
