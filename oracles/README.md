# TEMPEST algebraic-ground-truth oracles

Executed order-theory and field-theory oracles for the Soroban host, plus the X-1
WASM detector. Adapted from the T3MP3ST discipline: **a finding is graded against a
committed ground-truth oracle (the algebraic axioms), not a self-report.** A violation
is a concrete, reproducible tuple.

Method: reverse-engineer the Soroban *language* (host `rs-soroban-env`) to extract the
semantic edge a contract dev doesn't know exists, then confirm it by execution. Two axioms:
**everything that receives input is attack surface; everything that communicates is attack surface.**

Verified against host revision **`c212b91`** (`c212b91259abc86e6e9910b3694232df5a2a767f`).

## What the oracles establish (all executed, not inferred)

| layer | oracle | verdict | evidence |
|---|---|---|---|
| **order** | `Compare<Val>` total order | **SOUND** | 0 axiom violations across **14,152,509 triples** (hand + recursive fuzz) |
| **field** | TZ-02b scalar aliasing | **BROKEN** | `s` and `s+r` → distinct U256 keys, identical `Fr`, identical curve point |
| **field** | FAULT-1 two moduli | **BROKEN** | `r ≠ 0` as u256 but `fr(r) == fr(0)` — one `U256Val` type, two moduli |
| **field** | TZ-05 subgroup omission | **BROKEN** | non-subgroup point: `g1_add` validation accepts, `g1_mul`/pairing reject |
| **auth** | AX-03 classic always-MEDIUM | **BROKEN** | signer weight == MED authorizes a Soroban op though HIGH threshold unmet |

**The mathematical foundation splits: order theory is closed, field theory cracks in three places.**
Order-theory soundness matches the host's own `compare_obj_to_small` + `host_obj_discriminant_order`
tests; the fuzz oracle extends them to nested Vecs + many values and confirms.

Caveat (honest): all confirmations are at the **host layer**. Contract-level victims still
need a deployed contract that derives nullifiers via `fr_*`/`g1_mul` — a grep of the local
59-wasm corpus found **0 crypto carriers**, so these are host-confirmed but victim-pending.

## Files

- `tempest_soroban_env_c212b91.patch` — the 5 oracles as a re-appliable patch (they call
  `pub(crate)` host fns, so they must live inside the crate). Touches
  `soroban-env-host/src/host/comparison.rs` (order) and `.../test/bls12_381.rs` (field).
- `order_oracle.rs.ref` / `field_oracle.rs.ref` — readable extracts of the oracle source.
- `run_oracles.sh` — applies the patch to a pinned checkout and runs `cargo test tempest`.
- `detectors/x1_disassembler.py` — pure-Python WASM code-section disassembler; locates
  `try_call` sites and reads the tag-check window (no wasm tooling needed).
- `detectors/x1_scan.py` — X-1 detector: flags contracts whose `try_call` result is NOT
  tag-checked before use (handles i32/i64/Void encodings). Empirical: all 14 local
  try_call carriers check the tag — SDK-compiled contracts are disciplined; X-1 risk is
  in non-standard SDKs / hand-rolled handling.

## Run

```bash
# oracles (needs the rs-soroban-env checkout at c212b91)
./run_oracles.sh [path-to-rs-soroban-env]     # default: ~/sorohunter/hunt/rs-soroban-env

# X-1 detector over a wasm corpus (run from a dir with rs-soroban-env/soroban-env-common/env.json reachable)
python3 detectors/x1_scan.py
```

## Next

1. Port field oracles to the **public `Env` host-function API** (`bls12_381_g1_mul`,
   `bls12_381_g1_add`, `bls12_381_fr_*`) so they become a standalone crate instead of a
   patch — removes the pub(crate) coupling.
2. Fetch the 219 uncovered census codebases + the $221M value-holder, grep for crypto
   carriers, to find a real victim for TZ-02b / TZ-05 / FAULT-1.
3. Point the same oracle discipline at the remaining ring-theory surface (FAULT-2
   trunc-div + `rem_euclid` signed fixed-point).
