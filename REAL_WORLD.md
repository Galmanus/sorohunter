# Real-world evidence

The synthetic `bench/` proves the *mechanism*. This proves the tool works on
**real and realistic contracts** — the claim that actually matters. Three parts:
precision on real correct code, recall on realistic bugs, and live acquisition
from testnet. Run on 2026-07-10.

## 1. Precision on real Stellar contracts (0 false positives)

sorohunter was pointed at **11 of Stellar's own `soroban-examples`** — canonical,
correctly-authored production-grade contracts — via `sorohunter probe`:

```
token (SEP-41), atomic_swap, timelock, single_offer, liquidity_pool,
mint-lock, auth, increment, ttl, groth16_verifier, upgradeable_contract
```

Result across the 39 single-function probes:

| verdict | count | meaning |
|---|---|---|
| held | 23 | function enforced auth — aborted under empty auth |
| view | 12 | read-only, correctly not flagged |
| skipped | 4 | unsynthesizable arg (see caveats) |
| **finding (breach/chain/hijack)** | **0** | **zero false positives** |
| deploy-failed | 0 | every contract deployed (constructor args synthesized) |

The load-bearing cases:
- **token** (SEP-41): `mint`, `burn`, `set_admin`, `approve`, `transfer_from`, `burn_from` all **held** (auth enforced); `balance`/`name`/`symbol`/`decimals`/`allowance` correctly classed read-only. Not one false alarm on the flagship token.
- **upgradeable_contract**: its `upgrade` is admin-gated → **held**, and the TP-01 detector did **not** hijack it. A real upgrade pattern, correctly left alone. This is the TP-01 precision control on real code.

Reproduce:
```bash
git clone --depth 1 https://github.com/stellar/soroban-examples
# build each example to wasm (cargo generate-lockfile first, pins a working ethnum), then:
python3 sorohunter/cli.py probe <path>/*.wasm
```

## 2. Recall on realistic bugs (real contracts, one line removed)

Two of the real contracts were given the single most common real-world mistake —
**one `admin.require_auth()` line deleted** — and rebuilt:

| contract | injected bug | sorohunter |
|---|---|---|
| `vuln_token` (real SEP-41, `mint` auth removed) | anyone can mint | **flags `mint` (TA-01)** — every other function still held |
| `vuln_upgradeable` (real upgradeable, `upgrade` auth removed) | anyone can swap code | **flags `upgrade` (TP-01)** — `version` still a view |

It caught the one injected bug in each and flagged nothing else — recall *and*
precision on real-shaped code, not a toy.

## 3. Live testnet acquisition (read-only fetch + local fork)

`vuln_vault` was deployed to **Stellar testnet** and scanned with the read-only
`scan` path, which fetches the public ABI + WASM from the live network and probes
a local fork — never touching the deployed contract:

- Contract: [`CDXSRD4BMJDQPL6XR67FXA7KEYGUOJWZF6TTYAUPS3YMNK5JTQYXXYPD`](https://stellar.expert/explorer/testnet/contract/CDXSRD4BMJDQPL6XR67FXA7KEYGUOJWZF6TTYAUPS3YMNK5JTQYXXYPD) (testnet)
- Result: `withdraw` → **BREACH** (TA-01), `deposit` → held, `balance` → view.

The full loop — acquire real network bytecode → probe → executed finding —
works end to end.

## Honest caveats (what this does *not* claim)

- **Not a found-in-the-wild 0-day.** The vulnerable cases are realistic bugs I *injected* into real contracts. The claim is "zero false positives on real correct code + catches realistic bugs," not "found a live exploit." A real disclosure would follow the coordinated path, not a README.
- **Precision-biased by design.** Probes use crude default args (amount = 1, fresh addresses, single-shot). This is why it does not false-positive — and also why it can **false-negative**: a bug reachable only after specific state or specific args won't be caught by a one-shot probe. It is a fast first-pass, not a replacement for an audit.
- **`muxed_address` unsynthesizable (4 skips).** The SEP-23 muxed-address type isn't synthesizable yet, so e.g. token's `transfer(address, muxed_address, i128)` is honestly skipped rather than probed with a bogus value. Roadmap: add muxed_address synthesis.
- **`scan` findings are candidates.** `scan` fresh-deploys the fetched WASM, so a finding on a live contract is a candidate pending state-fork confirmation (`stellar snapshot`) before any disclosure.
