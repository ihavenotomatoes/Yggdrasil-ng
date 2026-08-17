# Peer Liveness

Yggdrasil-ng uses a per-peer **read deadline** after non-keepalive frames are sent.
If the remote peer stays silent for too long, the link is torn down
(`ironwood: operation timed out`). Any received frame resets the probe counter.

The policy is controlled by the nested TOML table `[peer_liveness]`.

## Defaults (fixed mode)

By default the daemon runs in **fixed** mode:

```toml
[peer_liveness]
adaptive = false
fixed_secs = 15
probe_count = 3
```

- Interval = fixed_secs (15 s).
- After probe_count consecutive silent intervals the peer is disconnected.
- Total silence budget ≈ fixed_secs × probe_count (45 s with the defaults).
- Sticky floor / EWMA / penalty logic is disabled.

This matches the conservative behaviour expected on most links and is the
recommended starting point.

## Enabling adaptive mode

```toml
[peer_liveness]
adaptive = true
fixed_secs = 15          # ignored while adaptive = true
min_secs = 5             # healthy / initial sticky floor
problem_min_secs = 15    # sticky floor after a real timeout
max_secs = 30
base_secs = 2
rtt_mult = 8
probe_count = 3
```

## How the adaptive interval is computed

`T = clamp(base_secs + rtt_mult × ewma + penalty, sticky_floor, max_secs)`

- Sticky floor starts at min_secs (5 s).
- On a final liveness timeout (all probe_count probes exhausted) the floor
rises to at least problem_min_secs (15 s) and never snaps back.
- Intermediate probe misses only re-arm the deadline; they do not raise the floor.
- EWMA is updated from arm→reply samples; slow samples never raise the floor.
- Penalty is applied on final timeout and slowly decays on healthy samples.
- Per-peer state (floor, EWMA, penalty) is keyed by public key and survives
reconnects.

Total silence budget ≈ current T × probe_count
(e.g. cold ~15 s, after sticky ~45 s with the defaults above).

## Configuration reference
| Key | Type | Defalut | Meaning |
|-----|------|---------|---------|
| adaptive | bool | false | false = fixed interval; true = sticky adaptive floor |
| fixed_secs | u64 | 15 | Exact interval when adaptive = false |
| min_secs | u64 | 5 | Initial / healthy adaptive floor |
| problem_min_secs |u64 | 15 | Sticky floor after a real timeout |
| max_secs, | u64 | 30 | Upper clamp for the adaptive interval |
| base_secs | u64 | 2 | Base component of the adaptive formula |
| rtt_mult | u32 | 8 | Multiplier for EWMA(arm→reply) |
| probe_count | u32 | 3 | Consecutive silent intervals before disconnect |