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

## 4. Real production protocols, read-only — and the false positive it caught

Pointed `scan` (read-only fetch + local fork) at **15 real third-party contracts
I did not write** — 7 live **mainnet** (Blend pool / backstop / pool-factory,
Comet BLND:USDC, Soroswap factory / router, Aquarius AMM) and 8 on **testnet**
(Aquarius testnet router + recent public deploys). Result: **zero real findings.**
A 30-function AMM (Comet) and a 20-function router probe entirely to held / view.
Real, uncontrolled production code, no false alarms. (Read-only throughout:
`scan` fetches the public WASM and probes a local fork; it never touches the
deployed contract.)

**The one thing that flagged — and why it made the tool better.** On the first
pass, Soroswap's `initialize` came up as a missing-auth `BREACH`. It was a **false
positive**, for a structural reason worth stating plainly: `scan` fresh-deploys
the fetched WASM, and on a *fresh* deploy `initialize` has not run yet, so it
succeeds — while on the live contract it is already initialized and guarded. I
did **not** report a Soroswap bug. Instead the tool now runs a **re-init test**
on any initializer-shaped breach: call it a second time under empty auth.
Soroswap's `initialize` **reverts** on the second call (guarded), so it is
reclassified `init-guarded` — a fresh-deploy artifact, not a finding. A contract
whose initializer runs *twice* is a real re-initialization bug (TA-03), and is
kept. This is the value of running on real contracts: it surfaced a systematic
false-positive class and forced the fix that stops the tool from crying wolf —
the exact failure mode that destroys a security tool's credibility.

## 5. Economic drain detection against real reserves (precision + recall)

The `econ <id>` mode goes past auth: it measures **real value movement**. In a
lazy fork (real on-chain state) it identifies the contract's tokens (via getters
+ instance storage), reads the contract's **real reserves**, probes each mutating
function under empty auth, and flags any that **reduce the contract's real token
balance** — an unauthenticated drain of real liquidity, confirmed against forked
state.

- **Precision — Comet (real BLND:USDC AMM, mainnet):** tokens found (BLND + USDC),
  real reserves read (~7.4T USDC / ~707T BLND), 20 mutating functions probed →
  **0 false drains**. A correctly-authed production AMM does not leak.
- **Recall — a planted-vuln pool (`recall/drain_pool`, testnet):** a pool holding
  50 XLM whose `steal()` transfers reserves out with no `require_auth`. The
  detector read the real 500,000,000-stroop balance and flagged
  `steal(address, i128)` → **[DRAIN]** "reduced the contract's real balance …
  unauthenticated value extraction, CONFIRMED." (Pool `CC4DZ4JF…`, native XLM SAC.)

Both sides on real contracts: silent on a real AMM, fires on a real drain. This
is the class where the money-bugs live, measured — not asserted.

*Scope, honestly:* this catches **unauthenticated** drains of real reserves. An
**authorized-but-broken-accounting** economic bug (e.g. a swap that returns more
than it takes, where the attacker *does* sign) needs attacker-authorized
invariant-fuzzing over a sequence — the next layer, built on this same
real-reserve measurement.

## Honest caveats (what this does *not* claim)

- **Not a found-in-the-wild 0-day.** The vulnerable cases are realistic bugs I *injected* into real contracts. The claim is "zero false positives on real correct code + catches realistic bugs," not "found a live exploit." A real disclosure would follow the coordinated path, not a README.
- **Precision-biased by design.** Probes use crude default args (amount = 1, fresh addresses, single-shot). This is why it does not false-positive — and also why it can **false-negative**: a bug reachable only after specific state or specific args won't be caught by a one-shot probe. It is a fast first-pass, not a replacement for an audit.
- **`muxed_address` unsynthesizable (4 skips).** The SEP-23 muxed-address type isn't synthesizable yet, so e.g. token's `transfer(address, muxed_address, i128)` is honestly skipped rather than probed with a bogus value. Roadmap: add muxed_address synthesis.
- **`scan` findings are candidates.** `scan` fresh-deploys the fetched WASM, so a finding on a live contract is a candidate pending state-fork confirmation (`stellar snapshot`) before any disclosure.
