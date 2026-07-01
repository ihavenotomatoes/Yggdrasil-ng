# salsa20-simd

A fork of the RustCrypto [`salsa20`](https://crates.io/crates/salsa20) crate
(v0.10.2) that adds **SIMD backends** for the Salsa20 core keystream:

| target | backend | blocks/group |
|---|---|---|
| x86 / x86_64 (AVX2) | AVX2 | 8 |
| x86 / x86_64 (SSE2) | SSE2 | 4 |
| aarch64 | NEON | 4 |
| everything else | scalar (upstream) | 1 |

Backends use a "one state word per SIMD lane, N blocks across the lanes" layout
(no in-round shuffles; a single transpose when writing out). On x86 the backend
is chosen at runtime via `cpufeatures` (AVX2 → SSE2 → scalar); on aarch64 NEON
is part of the baseline ISA. The keystream is **byte-identical** to the scalar
implementation, so this is a drop-in replacement and stays wire-compatible with
any other Salsa20/XSalsa20 implementation.

The package name is intentionally kept as **`salsa20`** so it can transparently
replace the crates.io crate via Cargo's patch mechanism.

## Why

Upstream `salsa20` has no SIMD; its keystream is a portable scalar loop, while
e.g. Go's `x/crypto` ships hand-written assembly. This fork closes that gap:
roughly **2× the scalar throughput on x86 (AVX2)** and a measured **~+50% on
aarch64 (NEON)**, which matters when you are actually crypto-bound (multi-gigabit
links, many parallel flows) or CPU/battery-limited (mobile).

## Usage

Add a patch to the **workspace root** `Cargo.toml` of whatever ultimately
depends on `salsa20` (directly or transitively):

```toml
[patch.crates-io]
salsa20 = { path = "path/to/salsa20-simd" }
# or, from a git checkout:
# salsa20 = { git = "https://github.com/<you>/<repo>", branch = "salsa20-simd" }
```

## Correctness

```bash
cargo test -p salsa20            # differential tests vs the scalar core + Salsa20 KAT
```

Tests check the SIMD keystream against the scalar reference across many block
counters (including 32-bit carry boundaries) and end-to-end through the public
cipher API. NEON is additionally covered by aarch64-only tests. Force a specific
backend for benchmarking/testing with the `force-soft` / `force-sse2` /
`force-avx2` features.

## Status / upstreaming

This is a fork intended to be contributed back to
[RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers).
Licensed, like the original, under **MIT OR Apache-2.0**.
