//! NEON backend for the Salsa20 core (fork addition), aarch64 only.
//!
//! Same "one state word per lane, blocks across the lanes" layout as the SSE2
//! backend (4 blocks wide, 128-bit `uint32x4_t`). NEON is part of the aarch64
//! baseline ISA, so no runtime detection is needed. Keystream is byte-identical
//! to the scalar backend (verified by the aarch64-only tests below).

use cipher::{
    consts::{U4, U64},
    Block, BlockSizeUser, ParBlocks, ParBlocksSizeUser, StreamBackend, StreamClosure,
};
use core::marker::PhantomData;

use core::arch::aarch64::*;

use super::{run_rounds, Unsigned, STATE_WORDS};

/// Number of blocks generated per NEON group.
const PAR_BLOCKS: usize = 4;

/// Entry point used by `SalsaCore::process_with_backend` on aarch64.
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
        // SAFETY: NEON is mandatory on aarch64.
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
#[target_feature(enable = "neon")]
unsafe fn rotl7(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<7>(x), vshrq_n_u32::<25>(x))
}
#[inline]
#[target_feature(enable = "neon")]
unsafe fn rotl9(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<9>(x), vshrq_n_u32::<23>(x))
}
#[inline]
#[target_feature(enable = "neon")]
unsafe fn rotl13(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<13>(x), vshrq_n_u32::<19>(x))
}
#[inline]
#[target_feature(enable = "neon")]
unsafe fn rotl18(x: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<18>(x), vshrq_n_u32::<14>(x))
}

/// One Salsa20 quarter-round applied to all 4 lanes at once.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn quarter_round(
    v: &mut [uint32x4_t; STATE_WORDS],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
) {
    v[b] = veorq_u32(v[b], rotl7(vaddq_u32(v[a], v[d])));
    v[c] = veorq_u32(v[c], rotl9(vaddq_u32(v[b], v[a])));
    v[d] = veorq_u32(v[d], rotl13(vaddq_u32(v[c], v[b])));
    v[a] = veorq_u32(v[a], rotl18(vaddq_u32(v[d], v[c])));
}

/// Generate 4 keystream blocks for counters `counter..counter+4` into `blocks`.
#[target_feature(enable = "neon")]
unsafe fn keystream4<R: Unsigned>(
    state: &[u32; STATE_WORDS],
    counter: u64,
    blocks: &mut ParBlocks<Backend<R>>,
) {
    let mut v = [vdupq_n_u32(0); STATE_WORDS];
    for w in 0..STATE_WORDS {
        v[w] = vdupq_n_u32(state[w]);
    }
    let mut lo = [0u32; 4];
    let mut hi = [0u32; 4];
    for j in 0..4 {
        let cj = counter.wrapping_add(j as u64);
        lo[j] = cj as u32;
        hi[j] = (cj >> 32) as u32;
    }
    v[8] = vld1q_u32(lo.as_ptr());
    v[9] = vld1q_u32(hi.as_ptr());

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
        v[w] = vaddq_u32(v[w], orig[w]);
    }

    let mut tmp = [[0u32; 4]; STATE_WORDS];
    for w in 0..STATE_WORDS {
        vst1q_u32(tmp[w].as_mut_ptr(), v[w]);
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

    // NEON 4-block keystream must match the scalar reference exactly. Runs only
    // on aarch64 hardware (this module is aarch64-only).
    #[test]
    fn neon_matches_scalar_blocks() {
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
}
