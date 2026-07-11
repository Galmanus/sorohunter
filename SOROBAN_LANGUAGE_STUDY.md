# Soroban Language Deconstruction — Deep Study v0.1

**Method (Manuel, 11/07/2026):** reverse-engineer the Soroban host (`rs-soroban-env`) not to find a host bug, but to extract the **semantic edge the contract dev doesn't know exists**, then turn each edge into a fork-validated detector run against the 1352 live contracts. Template = the `Fr` bug (TZ-02): not a host bug, a comparison-without-normalization that a contract *relying on that semantic* trusts.

**Two axioms:**
1. **everything that receives input is attack surface** → value model, collections, storage, arithmetic, crypto
2. **everything that communicates is attack surface** → auth, cross-contract/frames, budget/metering

**Ground truth:** host checkout `~/sorohunter/hunt/rs-soroban-env`, master **c212b91** (`c212b91259abc86e6e9910b3694232df5a2a767f`, committed 2026-07-08). Every claim below cited `file:line@c212b91` + official doc URL. Verified-in-source separated from inferred-exploitability.

**Generator:** a class is real when the semantics the host **actually implements** diverges from what the doc/dev **assumes**. Novelty judged against the existing `SOROBAN_ATTACK.md` matrix (TA-01..05, TE-01..03, TP-01..02, TD-01..02, TS-01..02, TM-01, TZ-01..04).

---

## SCORECARD — 8 surfaces, 16 new/sharpened classes, 13 banked negatives

| # | Class | Surface | Verdict | Sev | Verified | Cite |
|---|---|---|---|---|---|---|
| TC-01 | Cross-type Map key non-collision (type-tag identity) | input/collections | **NEW** | high | src | compare.rs:146-151, metered_map.rs:198-224 |
| FAULT-1 | `u256` = two moduli (arith mod-2²⁵⁶ vs silent field-reduce) | input/arith+crypto | **NEW** | high | src | metered_scalar.rs:63,67,110,114 |
| TZ-05 | BLS `g1_add`/`g2_add` skip subgroup check (CROWN) | input/crypto | **NEW** | high | src+test | host.rs:3186-3187, bls12_381.rs:217-241, test:1660-1666 |
| TZ-02b | Scalar representative aliasing → nullifier malleability | input/crypto | **NEW** | high | src | metered_scalar.rs:60-71,108-119 |
| AX-03 | Classic-account auth always checks MEDIUM threshold | comms/auth | **NEW (undoc)** | high | src | account_contract.rs:247-254 |
| AX-01 | Custom-account `__check_auth` NOT run in simulation | comms/auth | **NEW (undoc)** | high | src | auth.rs:2764-2799 |
| X-1 | `try_call` error-swallowing / silent continuation | comms/xcontract | **NEW** | high | src | host.rs:2643-2679 |
| X-2 | `require_auth` = attacker callback (sibling-CEI break) | comms/xcontract | **NEW** | high | src | account_contract.rs:160-174, frame.rs:937-954 |
| PRNG-1 | Same-tx prng gamble grindable by selective-abort retry | comms/budget | **NEW** | high | src+doc | prng.rs:44-66, frame.rs:371 |
| AX-05 | Auth tree does NOT pin sibling order + single-use nodes | comms/auth | **NEW** | med-high | src | auth.rs:1991-2011 |
| TS-01b | Writing a key does NOT bump its TTL (silent non-refresh) | input/storage | **NEW** | med-high | src | data_helper.rs:521-560 |
| TS-02a | Footprint-downgrade abort (footprint ∉ signed auth) | comms/storage | **NEW** | med | src+infer | storage.rs:146-158,905-919 |
| FC-1 | Non-canonical `SymbolSmall` aliasing (latent) | input/value | **NEW** | low-med | src | symbol.rs:156-165,410-428 |
| FC-2 | Two disagreeing `Symbol` comparators (tag vs byte order) | input/value | **NEW** | med | src | symbol.rs:132-152 vs host_object.rs:129-136 |
| TZ-06 | `map_fp_to_g1`/`map_fp2_to_g2` skip cofactor clearing | input/crypto | **NEW** | med | src | host.rs:3224-3226, bls12_381.rs:632 |
| FAULT-3 | `_checked_` arith family returns `VOID`, not trap | input/arith | **NEW-adj** | low-med | src | num.rs:61-67 |
| AX-04 | `require_auth_for_args` omitted-critical-arg replay | comms/auth | sharpen TA-04 | med-high | src | host.rs:3604-3644, auth.rs:1125-1136 |
| FAULT-2 | Trunc-div + `rem_euclid` breaks signed fixed-point | input/arith | sharpen TM-01 | med | src | host.rs:1615-1623 |
| X-3 | No `msg.sender` primitive (any caller-id is forgeable) | comms/xcontract | sharpen TD-01 | struct | src | env.json + host.rs:1350-1358 |
| X-4 | Direct-invoker implicit auth (auto-authorizes any fn) | comms/xcontract | maps TD-02 | — | src | auth.rs:1187-1199 |
| TS-01a/c | Instance = single-TTL blob; temp/persist extend asymmetry | input/storage | sharpen TS-01 | — | src | storage.rs:33-70,535-547,623-625 |

### Banked negatives (do NOT emit — would be false positives)
- **TC-02 / FC-3 / NEG-2:** small↔object numeric compare is value-canonical, test-enforced (`comparison.rs:644-672`). The Fr class does **not** generalize to representation-split map keys.
- **AX-06:** temp-storage nonce cannot replay post-archival — TTL coupled to signature expiry (`auth.rs:2592-2603,2948-2989`).
- **TN-1/2/3:** in enforcing mode the contract never observes an archival boundary mid-logic; `has()`≡`get()`; out-of-footprint = hard error not silent absence; no in-host autorestore race.
- **X-5:** `Ok(Error)` cross-frame spoofing of non-Contract subsystem errors is denied (`frame.rs:463-498`).
- **PRNG-2:** seed is `sha256(txset)` + apply-order, HMAC-unbiased — NOT ledger-readable. Do not flag "predictable seed."
- **NEG-1:** all 256-bit host arith **traps** on overflow (`ArithDomain`), never wraps (`num.rs:39-46`).
- **ECDSA:** secp256r1/k1 reject high-s (`crypto/mod.rs:185-193`) — no s-malleability. **ed25519** uses `verify_strict` (`mod.rs:89`).
- **BN254 disanalogy:** G1 `add` with `CheckOnCurve` is safe because BN254 h=1; the identical code path is a vuln on BLS12-381 (h₁≈2⁷⁶). Curve-condition TZ-05.
- **MET-1/MET-2:** prng range-charge over-estimate and shadow-mode non-RAII scope are both bounded/immaterial (unlike the auth recording-mode sibling).

---

## AXIOM 1 — everything that receives input is attack surface

### Collections & comparison
**TC-01 (NEW, high).** Map key identity is the host `Compare<Val>` total order, which orders **by type tag first**, comparing payloads only when tags match. `U32(5)`, `U64(5)`, `I128(5)`, `Symbol("5")` are four distinct slots, never deduped (`compare.rs:146-151`; `metered_map.rs:168-224@c212b91`). Doc warns `Map<K,V>` from untrusted args isn't guaranteed to hold type `K` (docs.rs/soroban-sdk Map). **Exploit:** allowlist/nonce/balance map keyed on a `Val`-typed arg written under one type, read under a fixed type → guarded entry invisible, or two "same" ids that never collide (double-claim/replay). Detector: contract with a `Val`/generically-typed map key where write and read paths can use different `Val` types.

### Value model — Symbols
**FC-1 (NEW, latent).** `SymbolSmall::try_from_body` validity gate checks only the top two body bits, not that 6-bit codes are left-packed; decoder skips interior zero codes rather than rejecting (`symbol.rs:156-165,410-428`). Multiple `Val` payloads decode to the same string, all `is_good`. **Neutralized** at every host boundary checked (dispatch decodes to `SymbolStr` `vm.rs:285`; storage re-emits canonical; `Compare` decodes). Reachable only if a contract does raw-bit `Symbol` equality (`shallow_eq`/payload) vs SDK compare. **Unverified link:** guest `soroban-sdk` `Symbol: PartialEq` impl (not in this repo).
**FC-2 (NEW, med).** `Compare<Symbol>` orders by tag first (all ≤9-char `SymbolSmall` sort below all >9-char `SymbolObject`), but the canonical map-key path is byte-lexicographic across the boundary (`symbol.rs:132-152` vs `host_object.rs:129-136`). `"aaaaaaaaaa"` vs `"b"` → opposite orders. Contract enforcing a sorted/monotonic Symbol invariant via the wrong helper accepts out-of-order entries.

### Arithmetic & numerics
**FAULT-1 (NEW, high).** Same `U256Val` type is arithmetic mod-2²⁵⁶ under `u256_*` but **silently reduced mod the ~254-bit field prime** under `bls12_381_fr_*`/`bn254_fr_*` (`metered_scalar.rs:63,67,110,114`). A verifier that range-checks a `U256` via `u256_*` and also feeds it to `fr_*` holds two inconsistent notions of the "same" number → nullifier/commitment collision. This is the Fr template at the conversion layer.
**FAULT-2 (sharpen TM-01).** `i256_div` truncates toward zero (not floor); the only modulo exposed is `rem_euclid` (non-negative remainder) (`host.rs:1615-1623`). Fires on in-range values, no overflow — corrupts signed fixed-point in lending/AMM.
**FAULT-3 (NEW-adj, low-med).** Plain `i256_add` traps on overflow (`ArithDomain`); `i256_checked_add` returns `Val::VOID` (`num.rs:61-67`). A binding that doesn't guard `is_void` coerces the sentinel and takes the "safe" branch instead of reverting. Canonical Rust SDK handles it; risk highest for non-standard SDKs.

### Crypto (the Fr generalized)
**TZ-05 — subgroup omission on BLS add (CROWN, NEW, high).** `bls12_381_g1_add`/`g2_add` use `CheckOnCurve` — **no subgroup check** — while `mul`/`msm`/`pairing` use `CheckOnCurveAndInSubgroup` (`host.rs:3186-3187` vs `:3200`; gate `bls12_381.rs:217-241`). Deliberate and **test-asserted** that a non-subgroup point passes `g1_add` (`test/bls12_381.rs:1660-1666`). BLS12-381 G1 cofactor h₁≈2⁷⁶, G2≈2³⁰⁵ → torsion points exist. **Exploit:** aggregate-signature/accumulator contract combining keys via repeated `g1_add`, then byte-comparing the aggregate (no pairing on it) — attacker adds a low-order torsion point to hit a target byte-value, forging membership. Containment: mul/msm/pairing all re-reject, so only bites when the add-output is consumed without a subgroup-checked op. **CAP-0059 lists subgroup error as a condition for `g1_add` — spec-vs-code discrepancy; read the CAP directly before publishing as "spec violation" vs "doc lag."**
**TZ-02b — scalar aliasing / nullifier malleability (NEW, high).** `from_u256val` silently reduces mod r (`from_le_bytes_mod_order`, `metered_scalar.rs:60-71,108-119`); infinitely many U256 reps `s+k·r` collapse to one Fr. Contract storing raw-U256 nullifiers but deriving the point via `g1_mul(base, s)`: spend with `s`, re-spend with `s+r` → new dedup key, identical point → double-spend. The dual of TZ-02 (reduction present but not surfaced). *Isomorphism:* same structure as FP `NaN`/`-0.0` in hashing — two bit-patterns, one value. *Disanalogy:* reduction is exact and adversary-chosen (`s+k·r` for any k), not a fixed small alias set.
**TZ-06 — cofactor omission in map-to-curve (NEW, med).** `map_fp_to_g1`/`map_fp2_to_g2` do SWU+isogeny but **no cofactor clearing**; only `hash_to_g1/g2` clears (`host.rs:3224-3226`; `bls12_381.rs:632`). Dev rolling custom hash-to-curve as `sha256→fp→map_fp_to_g1` gets a non-subgroup point.

---

## AXIOM 2 — everything that communicates is attack surface

### Authorization
**AX-03 — always-MEDIUM threshold (NEW, high, undocumented).** Every `require_auth` on a `G...` account hardcodes `ThresholdIndexes::Med` (`account_contract.rs:247-254`). No path to low/high. A treasury assuming its classic "high threshold" protects large Soroban token transfers is wrong — medium-meeting signers authorize any `require_auth`.
**AX-01 — `__check_auth` elided in simulation (NEW, high, undocumented).** Recording mode's `emulate_authentication` returns `Ok(())` for `ScAddress::Contract` without invoking `__check_auth` (`auth.rs:2764-2799`); the policy runs only at consensus. A smart-wallet spend-cap passes simulation for an over-cap withdrawal; front-end gating on "simulated ok" relays a tx that reverts. Both AX-01/03 absent from the official authorization page.
**AX-02 — multisig sim single-sig (NEW, med).** `emulate_authentication` synthesizes one zero signature and suppresses the threshold failure (`auth.rs:2743-2757`); recording CPU estimate undercounts ~(M-1) ed25519 verifies → `ResourceLimitExceeded` at consensus → liveness DoS on multisig wallets.
**AX-05 — sibling-order laxity + single-use nodes (NEW, med-high).** The tree enforces parent→child nesting and exact `(contract,fn,args)` equality, but among siblings greedily consumes the first non-exhausted match (`auth.rs:1991-2011`). Signing `{transfer(A), transfer(B)}` doesn't pin A-before-B; identical repeated sub-calls need N separate nodes (loop footgun).
**AX-04 — omitted-critical-arg replay (sharpen TA-04).** `require_auth`/`_for_args` take contract+fn from the current frame; only `args` is dev-controlled (`host.rs:3604-3644`, `auth.rs:1125-1136`). `require_auth_for_args(user, (amount,))` on `fn withdraw(user, amount, to)` leaves `to` out of the signed payload → replay with a different `to`.

### Cross-contract & frames
**X-1 — `try_call` error-swallowing (NEW, high).** A failed sub-call returns an `Error` **Val** to the caller; the caller frame is not rolled back (`host.rs:2643-2679`). Vault doing `try_call(token,"transfer")` and branching only on a decoded success struct (never `Val::is_error`) moves funds without the transfer settling. Sharper than generic unchecked-return because the host actively converts trap→value at a defined boundary. Detector: `try_call` result not `is_error`-checked.
**X-2 — `require_auth` as attacker callback (NEW, high).** Verifying a custom-account address runs its `__check_auth` via `call_n_internal` with `SelfAllowed` (`account_contract.rs:160-174`) — attacker Wasm executes inside your frame before your effects land. True reentry A→token→A is blocked (`frame.rs:946-954`, docs right about *that*), but `__check_auth` freely calls any sibling contract and observes your half-updated state → cross-contract CEI break, zero direct reentry. This is "where self-reentrancy IS exploitable," reframed correctly.
**X-3 — no `msg.sender` (sharpen TD-01, structural).** The entire context/call/address host surface has **no** caller getter (`env.json` enumerated; `get_current_contract_address` = frame top only, `host.rs:1350-1358`). Any "who called me" logic that isn't `require_auth` is definitionally forgeable — the address arg is data, not provenance.
**X-4 — direct-invoker implicit auth (maps TD-02).** `require_auth(X)` returns `Ok(true)` unconditionally when X is the direct caller, no fn/args predicate (`auth.rs:1187-1199`). A trusted router R that can be made to call V with attacker args grants attacker R's full authority over V.

### Storage & metering (communication across the state/rent boundary)
**TS-01b — write does not bump TTL (NEW, med-high).** Overwrite reuses the old `live_until_ledger`; only `extend_ttl` moves it (`data_helper.rs:521-560`). A nonce/lock/session written every call but never extended expires from *first* write, then reads absent → reopened replay/reentry window. No attacker to create the hole, only to walk it.
**TS-02a — footprint-downgrade abort (NEW, med).** Footprint is not in the signed auth preimage; a relayer marks a key `ReadOnly` and the contract's write hard-fails with non-recoverable `ExceededLimit` (`storage.rs:146-158,905-919`) → surgical DoS of specific transitions. **Unverified link:** "footprint ∉ auth scope" — confirm against xdr `HashIdPreimage` + `auth.rs` signed-payload construction.
**TS-01a/c (sharpen TS-01).** Instance storage is one blob under a single TTL, whole ScMap (de)serialized per access — grief by force-growing it. Temp over-extension errors while persistent silently clamps (`storage.rs:535-547,623-625`); host itself flags the nonce-replay linkage.
**PRNG-1 — grindable single-tx gamble (NEW, high).** Each retry is a new tx with a new base seed; caller observes the draw and re-submits until favorable, cost = fee only. Host documents the mitigation is contract-side commit/reveal, not a host guarantee (`prng.rs:44-66`; frame PRNG `frame.rs:371`). Victims: lottery/mint/game. Detector: `prng_*` call → value-transfer/mint in the **same** invocation with no prior storage-committed seed.

---

## Priority for detector-building (next step)

**Tier 1 — build detectors now (verified host mechanism + scannable contract pattern):**
1. **X-1 try_call error-swallowing** — grep WASM for `try_call` result not passed through an `is_error` check.
2. **TZ-05 BLS subgroup omission** — grep for `g1_add`/`g2_add` host-fn imports NOT co-occurring with `pairing_check`/`mul`/`msm`. Curve-condition (BLS only, not BN254 G1).
3. **PRNG-1 grinding** — `prng_*` + same-invocation settlement, no committed-seed read.
4. **TC-01 cross-type map key** — `Val`/generic map key with type-divergent write/read paths.
5. **TZ-02b nullifier aliasing** — raw-U256 nullifier store + point derived via `fr_*`/`g1_mul`.

**Tier 2 — high value but need one confirmation first:**
- **AX-01/AX-03** (undocumented, high) — the strongest *disclosure* items; both fully source-verified. Fork-demonstrate the sim-vs-consensus divergence.
- **TS-01b** — write-doesn't-refresh-TTL; needs a contract that writes-without-extend on a nonce/lock.
- **TS-02a** — confirm footprint ∉ signed preimage in xdr before shipping as CVE-class.
- **TZ-05 spec status** — read CAP-0059 directly: spec violation vs doc lag changes the disclosure framing.

**Falsifiable predictions:**
- TZ-05: any deployed BLS contract that aggregates via `g1_add`/`g2_add` and consumes the result without a later `mul`/`msm`/`pairing` is exploitable. Zero such contracts → theoretical-only.
- PRNG-1: across the 15-contract sorohunter corpus, the detector fires on ≥1 game/lottery/mint iff any call `prng_*` at all; zero prng users → park as forward-looking.
- X-1: grep the corpus for `try_call` without `is_error` — expect ≥1 hit in any non-trivial DeFi contract.

**Honest ceiling:** every "exploit sketch" above is verified at the host layer but **inferred at the contract layer** — none is fork-demonstrated yet. The matrix columns are earned only when a fork PoC executes the transition on a real contract. This study tells the hunter *where to point*, not that a live contract *is* broken.
