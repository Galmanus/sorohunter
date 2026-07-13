# sorohunter

```
                                  ⠄⠄⠄⠄⠄⠄⣠⢿⡄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⡿⣄
                                  ⠄⠄⠄⠄⠄⣰⢳⡌⣿⢀⣀⣀⣀⠄⠄⠄⠄⢀⣀⣀⡀⡞⢠⣎⣆
                                  ⠄⠄⠄⠄⢸⣣⣿⣧⠛⠉⠉⠄⠈⠉⠉⠉⠉⠉⠁⠈⠉⠁⢴⣧⣌⡆
                                  ⠄⠄⠄⠄⣾⣻⠛⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢛⣿⣷
                                  ⠄⠄⠄⠄⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢰⣿⣿
                                  ⠄⠄⠄⠄⣿⣷⡤⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢹⣾⣿⣿
                                  ⠄⠄⠄⠄⡿⣏⣧⣤⣀⣀⠄⠄⠄⣺⠄⢠⡏⠄⠄⠄⣀⣤⣤⣽⣿⣿
                                  ⠄⠄⠄⢰⢷⣿⢿⣷⣉⠛⣻⣦⣀⡿⠄⠈⠃⠰⣶⣞⠋⣉⣿⠗⠉⣿⡇
                                  ⠄⠄⠄⣾⣸⣯⡴⠈⠙⠛⠛⠋⠁⠄⠬⠭⣗⡀⠹⠿⣿⣫⡅⠄⣠⣿⣿
                                  ⠠⣤⡶⢿⣗⣿⣿⣦⠄⠄⠄⠄⠄⠐⠒⠒⠚⢯⡀⠸⣿⣿⣧⣾⣿⣿⣿⣦⣤⠄
                                  ⠄⠄⠉⠻⣿⣿⣿⣿⣿⣓⢀⣴⣿⣿⣿⣿⣤⣶⡆⣰⣿⣿⣿⣿⣿⣿⠟⠉
                                  ⠄⠄⠄⢀⣿⠙⣿⣿⣿⡛⡿⠛⠛⢻⣿⡿⠛⠛⠋⠘⣻⣿⣿⣿⠋⣿⡀
                                  ⣀⣴⣞⣉⣀⣢⢹⣿⣿⣷⡅⠄⢀⣨⣿⣇⣀⡀⠄⣸⣿⣿⣿⡇⣰⣟⣉⣓⣤⣀
                                  ⠉⠉⠉⠉⠉⠻⣦⡻⣿⣿⣿⣦⣿⣿⣿⡿⢿⣿⣾⣿⣿⣿⣿⣷⠏⠉⠉⠉⠉
                                  ⠄⠄⠄⠄⠄⣰⠋⣹⣦⣝⡻⠿⣿⣿⡿⠿⠿⠿⢻⣿⣿⣿⡿⠻⣆
                                  ⠄⠄⠄⠄⣼⡷⠟⠛⠙⠻⣿⠷⣶⣶⣶⣶⣶⣶⣿⣿⠟⠋⠛⠲⢮⣧
                                  ⠄⠄⠄⠄⠁⠄⠄⠄⠄⠄⢸⢀⡴⠋⠉⠉⠹⢇⢀⡇⠄⠄⠄⠄⠄⠄⠁
                                  ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⡟⠁⠄⠄⠄⠄⠈⢻⡇
                                  sorohunter · it bites what it finds
```

**The fork-validated detector layer for the [Soroban ATT&CK](SOROBAN_ATTACK.md).**

sorohunter points generic, ABI-driven adversary probes at deployed Stellar/Soroban
contracts, executes each attack technique step-by-step in a **local `soroban-sdk`
fork**, and reports every finding as the **exact invocation sequence that produced
it** — an executed proof, not an inference. It never signs or sends a transaction
to a live network.

Two things live in this repo:

1. **The hunter** — an ABI-driven, fork-validated detector engine (Python reference
   + a self-contained Rust binary) that runs eleven adversary techniques against a
   contract's public WASM and confirms each finding by execution.
2. **The oracle layer** — [`oracles/`](oracles/): executed *algebraic* ground-truth
   oracles that reverse-engineer the Soroban host itself (`rs-soroban-env`) to prove
   language-level fault classes, plus a pure-Python WASM detector. Born from the
   [language deconstruction study](SOROBAN_LANGUAGE_STUDY.md).

> Status: research tool, public, MIT. Precision-first and honestly scoped — read
> [What the benchmark measures](#what-the-benchmark-measures--and-what-it-does-not)
> before quoting any number.

---

## Table of contents

- [The one invariant: fork-validation](#the-one-invariant-fork-validation)
- [The legal perimeter (a code invariant)](#the-legal-perimeter-a-code-invariant)
- [The two axioms](#the-two-axioms)
- [Architecture](#architecture)
- [Shipped detectors (the full inventory)](#shipped-detectors-the-full-inventory)
- [The auth-bypass provers — smart accounts / passkey wallets](#the-auth-bypass-provers--smart-accounts--passkey-wallets)
- [The Soroban ATT&CK matrix](#the-soroban-attck-matrix)
- [The oracle layer — language deconstruction](#the-oracle-layer--language-deconstruction)
- [CLI usage](#cli-usage)
- [What the benchmark measures — and what it does not](#what-the-benchmark-measures--and-what-it-does-not)
- [Ecosystem-scale hunting](#ecosystem-scale-hunting)
- [Real-world evidence](#real-world-evidence)
- [Repository layout](#repository-layout)
- [Build & run](#build--run)
- [Honesty & scope](#honesty--scope)
- [Positioning](#positioning)
- [Documents](#documents)

---

## The one invariant: fork-validation

**A finding is a run, not a guess.** Every technique executes in a local
`soroban-sdk` `Env` against the target's public WASM. A call that drains, seizes,
or corrupts the forked contract is a finding; a call that holds the line is not.

There is no inference step, so there is no inference false-positive — the class of
error that taxes LLM-only scanners. Where the tool cannot execute (cryptographic /
business-logic classes), it says so and marks the technique **manual**, never
guessing.

Two fork depths:

- **ABI-fork** (`bench`, `probe`) — deploy the WASM into a fresh local `Env` and
  synthesize inputs from its declared interface. Proves auth/logic classes.
- **state-fork** (`scan --fork`) — pull the contract's **real on-chain state** via
  RPC (lazily) into the local `Env`, so a finding is confirmed against actual
  balances and storage, not a blank deployment. This is what lets `drain`,
  `greed`, `roundtrip`, `oracle`, and `counterfeit` assert real value movement.

## The legal perimeter (a code invariant)

Recon is **read-only acquisition** (RPC `getLedgerEntries` / `stellar contract
fetch`). Everything else runs in a **local fork**. **No transaction is ever signed
or sent to a live network** — there is no code path that submits to a non-local
endpoint. Live exploitation of mainnet is a crime and is off the table by
construction. This is the line between a tool and an incident, and it is enforced
in the harness, not in a policy doc.

## The two axioms

The method is two sentences:

1. **Everything that receives input is attack surface** — value encoding,
   collections, storage, arithmetic, crypto.
2. **Everything that communicates is attack surface** — authorization,
   cross-contract calls, budget/metering.

Every detector and every oracle is an instance of one of these.

---

## Architecture

```
   target WASM (public, read-only)
          │
          ▼
   ┌──────────────┐   stellar contract info interface --output json
   │  ABI parse   │   → typed probe plan (function_v0, inputs[].type_)
   └──────┬───────┘
          ▼
   ┌──────────────┐   synth Vals from declared types; invoke by symbol under
   │  fork engine │   empty / attacker / scoped auth; classify by event- and
   │ (soroban Env)│   state-delta against forked state
   └──────┬───────┘
          ▼
   ┌──────────────┐   verdict per fn: BREACH / CHAIN / HIJACK / DRAIN / GREED /
   │  report      │   REDIRECT / ROUNDTRIP / REPLAY / ORACLE / COUNTERFEIT /
   │              │   REINIT  — or held / view / init-guarded (NOT findings)
   └──────────────┘
```

**Two implementations, proven at parity:**

- **`sorohunter/` (Python reference)** — `abi.py` (ABI → probe plan), `cli.py`
  (`bench` / `scan` / `probe`), `report.py` (precision/recall vs ground truth).
  Small, readable, the spec of record.
- **`soro/` (Rust, binary `sorohunter`)** — the same pipeline consolidated into one
  self-contained binary running `bench` / `probe` / `scan` / `roundtrip`
  **in-process** (no subprocess-per-probe). Modules: `abi.rs`, `engine.rs`,
  `fork.rs`, `rpc.rs`, `econ.rs`, `cve.rs`, `report.rs`, `main.rs`. **29 Rust
  tests**, parity with the Python reference proven on real contracts.
- **`harness/` (Rust)** — the low-level fork executor: loads WASM, synthesizes
  typed `Val`s, invokes dynamically by symbol, classifies via event/state diff.

---

## Shipped detectors (the full inventory)

Each verdict below is **fork-validated**: it is emitted only when the described
invocation actually executes against the forked contract. `held`, `view`,
`init-guarded`, `clean` are explicit **non-findings** (the precision controls).

| Verdict | Technique | What it proves (executed) |
|---|---|---|
| **BREACH** | TA-01 missing `require_auth` | a state mutation succeeded and emitted an event **under empty auth** — a state change with no signature |
| **CHAIN** | TE-01 composition | a `foothold()` under empty auth seized control, **unlocking a gated `target()`** for the attacker — the PoC is the executed two-step sequence |
| **HIJACK** | TP-01 unprotected upgrade / TA-02 admin setter | `update_current_contract_wasm` (or an admin/owner setter) reachable under empty auth — code is swapped for an attacker payload and control is **confirmed via the payload's marker** (`pwned=1337`), or the admin is reassigned to the attacker |
| **REINIT** | TA-03 initializer re-entry | an `initialize` / constructor is callable **more than once** under empty auth — re-set the admin |
| **DRAIN** | OBJ-DRAIN | a call under empty auth **reduced the contract's real token balance** — unauthenticated value extraction, confirmed against forked state |
| **GREED** | OBJ-GREED | a call paid the attacker **from a zero position under the attacker's own authorization** (no privileged signer) — broken accounting / unchecked payout |
| **REDIRECT** | TA-05 caller-supplied-address trust | an authorized caller sent value to an **attacker-supplied recipient that never signed** — the injected-recipient / agent-payment class |
| **ROUNDTRIP** | OBJ-ROUNDTRIP | a legitimate user running `f()` then `g()` ended **richer than their starting stake with no offsetting loss** — the value-conservation invariant is broken (rounding-in-favor / swap-math) |
| **ORACLE** | OBJ-LIE (TE-03) | a payout **trusted the return value of an unvalidated caller-supplied contract** reporting a manipulated price — oracle/price manipulation, no allowlist |
| **COUNTERFEIT** | OBJ-COUNTERFEIT | the contract **accepted a planted counterfeit token** (its transfer moves nothing, its balance lies) as real value — fake-deposit / balance-inflation |
| **REPLAY** | TS-01 invariant-decay | a one-shot guard in **temporary storage** is silently deleted after its TTL; the call **succeeds again** once the ledger advances past it — double-claim / nonce-reuse, specific to temporary (a persistent guard is not flagged) |

Everything else in the [matrix](SOROBAN_ATTACK.md) (TA-04, TE-02, TP-02, TD-01/02,
TS-02, TM-01, and the cryptographic/ZK tactic TZ-01..04) is **roadmap** (mechanical)
or **manual** (cryptographic/business-logic) — marked honestly there.

---

## The auth-bypass provers — smart accounts / passkey wallets

Every detector above screens business functions under `mock_all_auths()`, which
**skips `__check_auth` entirely**. A separate stage does the opposite: it runs a
smart account's *real* `__check_auth` via `try_invoke_contract_check_auth` (no
mock) and proves an authorization bypass **by execution**. This is the highest-
value target class on Soroban — a bug in a widely-replicated passkey/wallet kit
ripples to every wallet built on it. Full write-up and honest limits in
[`AUTH_BYPASS.md`](AUTH_BYPASS.md).

| Mode | Class | What it proves (executed) |
|---|---|---|
| `--checkauth` | ignores / type-confuses the signature | a forgery battery (void, empty, zero-64, garbage-64, wrong-type) that **no honest signer produces** is accepted → `Ok(())` = bypass. Zero false positives by construction |
| `--replay` | signature not bound to payload (synthetic 96-byte ABI) | one genuine `(msg, sig)` pair authorizes a **different** payload — the binding bug, on a controlled fixture ABI |
| `--realauth` | real passkey-kit **ed25519** signer branch | deploys the actual `Signer`-constructor wasm and drives its genuine `__check_auth` with a real ed25519 signature in the target's own `Signatures(Map<SignerKey,Signature>)` type |
| `--realauth-p256` | real passkey-kit **secp256r1 / WebAuthn** signer branch | forges a genuine WebAuthn assertion (authenticatorData + clientDataJSON + ECDSA-secp256r1) and tests cross-payload replay — the swig-wallet #143 challenge-binding class, where the bug that actually ships lives |

Ground truth is a set of paired safe-vs-vuln fixtures in [`bench/`](bench/) gated by
`tests/test_checkauth.py` and `tests/test_realauth.py`: the `good_account` /
`bound_passkey` controls **must** show zero bypass (if they ever flag, the prover
is worthless), while `blind_account`, `void_guard_account`, `unbound_account`, and
`unbound_passkey` each carry a distinct planted bug the prover reads specifically.
`--realauth-p256` has been run against the only mainnet wasm the census found that
exports `__check_auth` (a passkey-kit smart wallet): the encoder **reaches its real
secp256r1 `__check_auth`** (a genuine assertion is accepted) and the wallet
correctly **holds** — a grounded result on real code, not a fixture. Zero real
bypasses found so far; see [`AUTH_BYPASS.md`](AUTH_BYPASS.md) for why that is a
census-coverage question, not a capability one.

---

## The Soroban ATT&CK matrix

[`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md) is the taxonomy: tactics × techniques,
each anchored to a real Soroban footgun / CVE / EVM (SWC) analog, with
shipped-vs-roadmap status per cell. [`KILLCHAIN.md`](KILLCHAIN.md) reads the same
matrix as a kill chain — a traversal from reconnaissance to objective.

The Cryptographic/ZK tactic (TZ-01 underconstrained, TZ-02 `Fr` modular-reduction,
TZ-03 trusted-setup, TZ-04 Fiat-Shamir/proof-replay) is the differentiator from any
EVM framework, and is where the oracle layer below now provides **executed**
evidence.

---

## The oracle layer — language deconstruction

Beyond auditing individual contracts, [`oracles/`](oracles/) attacks the **Soroban
host itself** — the trusted engine every contract runs on. The premise: the host is
a manual of footguns. Where its actual semantics diverge from what a contract
developer assumes, that gap is a vulnerability class. The oracles grade the host
against **algebraic ground truth** (the axioms of the structure it claims to
implement), so a violation is a concrete, reproducible tuple — executed, not
self-reported.

Verified against host revision `c212b91`:

| Layer | Oracle | Result | Meaning |
|---|---|---|---|
| **order theory** | `Compare<Val>` total order | **SOUND** | 0 axiom violations across **14.1M triples** (hand + recursive fuzz) — the ordering consensus depends on is closed |
| **field theory** | TZ-02b scalar aliasing | **BROKEN** | `s` and `s+r` → distinct U256 keys, identical `Fr`, identical curve point (double-spend primitive) |
| **field theory** | FAULT-1 two moduli | **BROKEN** | one `U256Val` type is mod-2²⁵⁶ under `u256_*` but mod-`r` under `fr_*` |
| **field theory** | TZ-05 subgroup omission | **BROKEN** | a non-subgroup point is accepted by `g1_add` validation but rejected by `g1_mul` / pairing |
| **auth** | AX-03 classic always-MEDIUM | **BROKEN** | a classic account authorizes a Soroban op at the MEDIUM threshold — the HIGH threshold is unreachable |

Honest scope: these are confirmed at the **host layer**. A contract-level victim
needs a deployed contract that actually stands on the crack — and an ecosystem
sweep (below) currently finds the vulnerable surface is real but **not yet
value-bearing** (few crypto carriers, no high>med treasuries). The oracles are
detectors ready for when that value arrives, and executed proof today.

Also in `oracles/`: **`x1_scan.py`** — a pure-Python WASM import + code-section
disassembler that detects the **X-1 `try_call` error-swallowing** class (a failed
sub-call returns an `Error` *value* the caller may not check). It handles the
i32/i64/Void tag-check encodings; empirically, SDK-compiled contracts are
disciplined here.

See [`SOROBAN_LANGUAGE_STUDY.md`](SOROBAN_LANGUAGE_STUDY.md) for the full study —
16 new/sharpened classes and 13 banked negatives, each cited `file:line@sha`.

---

## CLI usage

**Python reference:**

```bash
# 1) benchmark against the controlled ground-truth corpus
cd bench && stellar contract build && cd ..
python3 sorohunter/cli.py bench

# 2) probe a local WASM file
python3 sorohunter/cli.py probe path/to/contract.wasm

# 3) scan a deployed contract (read-only acquisition, ABI-fork)
python3 sorohunter/cli.py scan CBQD...  --network mainnet
```

**Rust binary (`soro/`, in-process, faster):**

```bash
cd soro && cargo build --release
BIN=./target/release/sorohunter

$BIN bench                         # ground-truth corpus, precision/recall
$BIN probe path/to/contract.wasm   # probe a local WASM
$BIN scan  CBQD... mainnet         # read-only acquire + ABI-fork
$BIN scan  CBQD... mainnet --fork  # STATE-FORK: pull real on-chain state via RPC
$BIN roundtrip CBQD... mainnet     # value-conservation (broken-math) lens
```

**Auth-bypass provers (`harness/`, runs the real `__check_auth`):**

```bash
cd harness && cargo build --release && cd ..
BIN=./harness/target/release/harness

$BIN --checkauth      <wasm> <out.json> <ctor_csv>   # forgery battery on __check_auth
$BIN --replay         <wasm> <out.json> <ctor_csv>   # cross-payload replay (synthetic ABI)
$BIN --realauth       <wasm> <out.json>              # real passkey-kit ed25519 branch
$BIN --realauth-p256  <wasm> <out.json>              # real passkey-kit secp256r1 / WebAuthn branch
```

`scan --fork` is what upgrades an ABI finding to a value finding: it lazily fetches
the real ledger entries so `drain` / `greed` / `roundtrip` assert against actual
balances.

---

## What the benchmark measures — and what it does not

```
$ sorohunter bench
  vuln_vault          withdraw             BREACH   (TA-01 missing-auth)
  safe_vault          clean
  chain_vault         set_admin->withdraw  CHAIN    (TE-01 composition)
  safe_chain_vault    clean                (foothold gated — FP control held)
  upgrade_vault       upgrade              HIJACK   (TP-01 code hijack)
  safe_upgrade_vault  clean                (upgrade gated — FP control held)
  precision 100% · recall 100% (tp 3, fp 0, fn 0)
```

**Read this honestly.** These figures are **precision-first, measured against a
controlled ground-truth corpus** (`bench/`, `ground_truth.json`): planted vulns
(missing-auth drain, composition chain, upgrade hijack) plus clean decoys — two of
which (`safe_chain_vault`, `safe_upgrade_vault`) are **false-positive controls**
that look vulnerable but are correctly left alone. Additional corpus contracts
(`liar_oracle`, `liar_token`, `attacker_pwn`) back the oracle/counterfeit/hijack
detectors.

They say: *the shipped detectors catch their planted bugs and raise zero false
alarms on the decoys.* They are **not** a general-auditor detection rate, and are
**not** comparable to broad benchmarks (e.g. EVMBench's ~47% autonomous ceiling):
this measures specific, scoped techniques against ground truth we control.

**Precision on the decoys is the load-bearing property** — a false positive on a
live protocol would burn the exact credibility this tool is built to earn. The
corpus grows with each shipped technique.

Probes deploy real contracts too: the harness synthesizes `__constructor` args
(Protocol 22+) and a deploy that traps is caught, not fatal. Precision is biased
over recall by design — crude default args never cry wolf but can miss a bug that
needs specific state (see [`REAL_WORLD.md`](REAL_WORLD.md) caveats, incl. the
unsynthesizable `muxed_address` skip).

---

## Ecosystem-scale hunting

[`hunt/`](hunt/) is the acquisition + census layer that turns the per-contract
detectors into an ecosystem sweep — all read-only:

- **census** (`census_arsenal.py`, `harvest_active.py`) — enumerate live contract
  instances and distinct WASM codebases from the network.
- **value ranking** (`acquire_by_value.py`, `lever.sh`) — rank codebases by the USD
  value they custody, so effort follows exposure.
- **corpus sweep** (`corpus_arsenal_sweep.py`, `roundtrip_sweep.sh`) — run the
  detectors across the acquired corpus, unaudited-first.
- **CVE fingerprinting** (`cve_fingerprint.py`) — match known SDK/host advisories.

A recent sweep covered 1,352 live instances across 278 distinct codebases and 173
fetched WASMs — used to answer, honestly, *where the value actually is* (in
single-key vaults/tokens, not yet in the sophisticated surfaces the newest classes
target).

---

## Real-world evidence

[`REAL_WORLD.md`](REAL_WORLD.md) records the three legs, run on real code:

- **Precision:** pointed at **11 of Stellar's own `soroban-examples`** (token
  SEP-41, liquidity pool, upgradeable, …) → **0 false positives**; a real
  admin-gated `upgrade` is correctly left alone (the TP-01 precision control).
- **Recall:** real token/upgradeable contracts with **one `require_auth` line
  removed** → caught exactly the injected bug (TA-01 / TP-01), nothing else.
- **Live acquisition:** deploy + read-only `scan` caught the bug in **bytecode
  fetched from the network**.

Plus 15 real third-party mainnet/testnet contracts (Blend / Comet / Soroswap /
Aquarius) scanned with **0 false findings**, including an `initialize` FP caught and
fixed before it could cry wolf on a real protocol.

---

## Repository layout

```
sorohunter/
├── README.md                      # this file
├── SOROBAN_ATTACK.md              # the tactics × techniques matrix (taxonomy)
├── KILLCHAIN.md                   # the matrix read as a kill chain
├── SPEC.md                        # design spec
├── REAL_WORLD.md                  # real-contract precision/recall/live evidence
├── SOROBAN_LANGUAGE_STUDY.md      # host deconstruction: 16 classes, 13 negatives
│
├── sorohunter/                    # Python reference (abi, cli, report)
├── soro/                          # Rust binary `sorohunter` (in-process, 29 tests)
├── harness/                       # Rust fork executor
├── bench/                         # ground-truth corpus + ground_truth.json
│
├── oracles/                       # algebraic ground-truth oracles + X-1 detector
│   ├── README.md
│   ├── run_oracles.sh
│   ├── tempest_soroban_env_c212b91.patch
│   ├── order_oracle.rs.ref / field_oracle.rs.ref
│   └── detectors/x1_scan.py, x1_disassembler.py
│
├── hunt/                          # ecosystem-scale acquisition + census (read-only)
└── tests/                         # pytest (test_abi, test_report)
```

## Build & run

Requirements: Rust (1.84+ recommended), `stellar` CLI (23+), Python 3.10+.

```bash
git clone https://github.com/Galmanus/sorohunter && cd sorohunter

# Python reference
python3 -m pytest                          # unit tests
cd bench && stellar contract build && cd ..
python3 sorohunter/cli.py bench

# Rust binary
cd soro && cargo build --release && cargo test
./target/release/sorohunter bench

# Oracle layer (needs an rs-soroban-env checkout at c212b91)
cd oracles && ./run_oracles.sh
```

## Honesty & scope

Non-negotiables, because the value of this tool is its credibility:

- **Fork-validated or manual — never inferred.** If a class can't be executed, it's
  marked manual, not guessed.
- **Precision-first metrics, ground-truth-scoped.** No general-auditor rate is
  claimed. A false positive on a live protocol is the one unrecoverable error.
- **Read-only, local-fork-only, never sends a transaction.** Enforced in code.
- **`scan` on a fresh-deployed WASM yields a *candidate*** — confirm against a
  state-fork (`scan --fork` / `stellar snapshot`) before any disclosure. Never touch
  the live contract.
- **Negatives are shipped too.** The language study banks 13 proven-safe classes and
  the ecosystem sweep reports *no value-bearing victim* where that is the truth — a
  false disclosure would burn more than it earns.

## Positioning

sorohunter is an **assurance layer + reference capture**, not bounty mining — the
AI-security tooling field has essentially no smart-contract coverage and none for
Soroban, and this session's sweeps confirmed empirically that the newest classes
have no value-bearing target yet. The deliverable is the *proven tooling* and the
*taxonomy*: security infrastructure for the ecosystem, ready for the value that
follows.

## Documents

- [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md) — the taxonomy (tactics × techniques)
- [`KILLCHAIN.md`](KILLCHAIN.md) — the kill chain through the matrix
- [`REAL_WORLD.md`](REAL_WORLD.md) — real-contract evidence
- [`SOROBAN_LANGUAGE_STUDY.md`](SOROBAN_LANGUAGE_STUDY.md) — host deconstruction
- [`oracles/README.md`](oracles/README.md) — the algebraic ground-truth oracles
- [`SPEC.md`](SPEC.md) — design spec


---

**License:** MIT · **Repo:** https://github.com/Galmanus/sorohunter
