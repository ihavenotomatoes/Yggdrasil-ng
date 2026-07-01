//! SSE2 backend for the Salsa20 core (fork addition).
//!
//! Same "one state word per lane, blocks across the lanes" layout as the AVX2
//! backend, but 4 blocks wide (128-bit registers). Used on x86 CPUs without
//! AVX2 (SSE2 is baseline on x86_64). Keystream is byte-identical to the scalar
//! backend (verified by the tests below).

use cipher::{
    consts::{U4, U64},
    Block, BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
};
use core::marker::PhantomData;

use super::{run_rounds, Unsigned, STATE_WORDS};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Number of blocks generated per SSE2 group.
const PAR_BLOCKS: usize = 4;

/// Entry point used by `SalsaCore::process_with_backend` when SSE2 (but not
/// AVX2) is selected.
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
    state: [u32; STATE_WORDS],
    counter: u64,
    _pd: PhantomData<R>,
}

impl<R: Unsigned> BlockSizeUser for Backend<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> ParBlocksSizeUser for Backend<R> {
    type ParBlocksSize = U4;
}

impl<R: Unsigned> StreamBackend for Backend<R> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
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
        // SAFETY: this backend is only reached when SSE2 is present (baseline on
        // x86_64; runtime-checked on x86).
        unsafe { keystream4::<R>(&self.state, self.counter, blocks) };
        self.counter += PAR_BLOCKS as u64;
    }

    #[inline(always)]
    fn gen_tail_blocks(&mut self, blocks: &mut [Block<Self>]) {
        let n = blocks.len();
        if n == 0 {
            return;
        }
        let mut scratch = ParBlocks::<Self>::default();
        // SAFETY: see `gen_par_ks_blocks`.
        unsafe { keystream4::<R>(&self.state, self.counter, &mut scratch) };
        for (dst, src) in blocks.iter_mut().zip(scratch.iter()) {
            dst.copy_from_slice(src);
        }
        self.counter += n as u64;
    }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl7(x: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32(x, 7), _mm_srli_epi32(x, 25))
}
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl9(x: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32(x, 9), _mm_srli_epi32(x, 23))
}
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl13(x: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32(x, 13), _mm_srli_epi32(x, 19))
}
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl18(x: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32(x, 18), _mm_srli_epi32(x, 14))
}

/// One Salsa20 quarter-round applied to all 4 lanes at once.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn quarter_round(v: &mut [__m128i; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[b] = _mm_xor_si128(v[b], rotl7(_mm_add_epi32(v[a], v[d])));
    v[c] = _mm_xor_si128(v[c], rotl9(_mm_add_epi32(v[b], v[a])));
    v[d] = _mm_xor_si128(v[d], rotl13(_mm_add_epi32(v[c], v[b])));
    v[a] = _mm_xor_si128(v[a], rotl18(_mm_add_epi32(v[d], v[c])));
}

/// Generate 4 keystream blocks for counters `counter..counter+4` into `blocks`.
#[target_feature(enable = "sse2")]
unsafe fn keystream4<R: Unsigned>(
    state: &[u32; STATE_WORDS],
    counter: u64,
    blocks: &mut ParBlocks<Backend<R>>,
) {
    let mut v = [_mm_setzero_si128(); STATE_WORDS];
    for w in 0..STATE_WORDS {
        v[w] = _mm_set1_epi32(state[w] as i32);
    }
    let mut lo = [0i32; 4];
    let mut hi = [0i32; 4];
    for j in 0..4 {
        let cj = counter.wrapping_add(j as u64);
        lo[j] = cj as u32 as i32;
        hi[j] = (cj >> 32) as u32 as i32;
    }
    v[8] = _mm_setr_epi32(lo[0], lo[1], lo[2], lo[3]);
    v[9] = _mm_setr_epi32(hi[0], hi[1], hi[2], hi[3]);

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
        v[w] = _mm_add_epi32(v[w], orig[w]);
    }

    let mut tmp = [[0u32; 4]; STATE_WORDS];
    for w in 0..STATE_WORDS {
        _mm_storeu_si128(tmp[w].as_mut_ptr() as *mut __m128i, v[w]);
    }
    for blk in 0..4 {
        let out = &mut blocks[blk];
        for word in 0..STATE_WORDS {
            out[word * 4..word * 4 + 4].copy_from_slice(&tmp[word][blk].to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::keystream4;
    use crate::test_util::{salsa20_state, scalar_block};
    use cipher::consts::{U10, U4, U64};
    use cipher::generic_array::GenericArray;

    // SSE2 4-block keystream must match the scalar reference exactly, including
    // base counters that cross the 32-bit carry into the high counter word.
    #[test]
    fn sse2_matches_scalar_blocks() {
        if !crate::sse2_cpuid::get() {
            return; // no SSE2 on this CPU
        }
        let key = [9u8; 32];
        let nonce = [0x21u8; 8];
        let state = salsa20_state(&key, &nonce);

        for &base in &[0u64, 1, 3, 4, 99, (u32::MAX as u64) - 2, 1u64 << 32] {
            let mut blocks = GenericArray::<GenericArray<u8, U64>, U4>::default();
            unsafe { keystream4::<U10>(&state, base, &mut blocks) };
            for j in 0..4 {
                let expected = scalar_block(&state, base + j as u64);
                assert_eq!(
                    blocks[j].as_slice(),
                    &expected[..],
                    "block mismatch at base={base}, lane={j}"
                );
            }
        }
    }

    // End-to-end SSE2 path (par-blocks + tail + counter write-back). Only runs
    // when the crate is built with `--features force-sse2`, which pins the
    // public cipher to this backend.
    #[cfg(feature = "force-sse2")]
    #[test]
    fn sse2_public_api_matches_scalar_stream() {
        use crate::{Key, Nonce, Salsa20};
        use cipher::{KeyIvInit, StreamCipher};

        let key = [0x33u8; 32];
        let nonce = [0x44u8; 8];

        const LEN: usize = 4 * 64 * 5 + 77; // several SSE2 groups + partial tail
        let mut buf = [0u8; LEN];
        Salsa20::new(Key::from_slice(&key), Nonce::from_slice(&nonce)).apply_keystream(&mut buf);

        let state = salsa20_state(&key, &nonce);
        let mut expected = [0u8; LEN];
        for (b, ksblk) in expected.chunks_mut(64).enumerate() {
            let blk = scalar_block(&state, b as u64);
            ksblk.copy_from_slice(&blk[..ksblk.len()]);
        }
        assert_eq!(&buf[..], &expected[..]);
    }
}
