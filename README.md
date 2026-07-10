# sorohunter

**The fork-validated detector layer for the [Soroban ATT&CK](SOROBAN_ATTACK.md).**
It points generic, ABI-driven probes at the agentic-payments contract class on
Stellar (mandates, escrow, settlement, constitutional contracts) in a **local
fork**, executes adversary techniques step by step, and reports each finding
with the invocation sequence that produced it as an **executed PoC**. The
surface no one audits, done the one way that stays legal.

- **Taxonomy:** [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md) — tactics × techniques, shipped-vs-roadmap per cell.
- **Real-world evidence:** [`REAL_WORLD.md`](REAL_WORLD.md) — 0 false positives across 11 real Stellar `soroban-examples`, recall on injected bugs, a live testnet scan.
- **Design:** [`SPEC.md`](SPEC.md). **A kill chain as a path through the matrix:** [`KILLCHAIN.md`](KILLCHAIN.md).

## What "fork-validated" means (and why it matters)

A finding is a **run**, not a guess. Every technique executes in a local
`soroban-sdk` `Env` against the target's public WASM; a call that drains or
seizes the forked contract is a finding, a call that holds the line is not.
There is no inference step, so there is no inference false-positive — the class
of error that caps AI scanners at a 20-40% false-positive tax. Recon is
read-only acquisition; **no transaction is ever signed or sent to a live
network.** That is the line between a tool and a crime, and it is a code
invariant in the harness.

## Shipped techniques (3 of the matrix)

- **TA-01 — missing `require_auth`.** A state mutation succeeds under empty auth. The invocation is the PoC. *(EVM analog: SWC-105 / OWASP-SC access control — the #1 Soroban footgun.)*
- **TE-01 — composition chain (admin capture → drain).** The differentiator: some vaults are **clean to any single-function probe** yet fall to a two-step chain. sorohunter proposes candidate chains (address-setter × gated action) and confirms each **by executing it in one fork** — foothold under empty auth, then the gated action as the seized principal.
- **TP-01 — unprotected upgrade (code hijack).** A reachable `update_current_contract_wasm` under empty auth. sorohunter uploads an attacker payload, swaps the target's code with it under empty auth, and **confirms control by calling the payload's marker** — a fresh-deploy single-fn probe misses it (a zero-hash swap just errors), the technique detector proves it.

The rest of the [matrix](SOROBAN_ATTACK.md) (TA-02..05, TP-02, TD, TS, and the
cryptographic/ZK tactic) is roadmap or manual, marked honestly there.

## What the benchmark measures — and what it does not

```bash
cd bench && stellar contract build && cd ..   # build the corpus (once)
python3 sorohunter/cli.py bench
#   precision 100% · recall 100% (tp 3, fp 0, fn 0)
#     vuln_vault          withdraw             (TA-01 missing-auth)
#     safe_vault          clean
#     chain_vault         set_admin->withdraw  (TE-01 composition)
#     safe_chain_vault    clean                (foothold gated — FP control held)
#     upgrade_vault       upgrade              (TP-01 code hijack)
#     safe_upgrade_vault  clean                (upgrade gated — FP control held)
```

**Read this honestly.** These figures are **precision-first, measured against a
controlled ground-truth corpus** of 6 contracts: three planted vulns (a missing-
auth drain, a composition chain, an upgrade hijack) and three clean decoys (two
of which are false-positive controls for the composition and upgrade detectors).
They say: *the three shipped detectors catch their planted bugs and raise zero
false alarms on the decoys, including on contracts that look vulnerable but are
not.* They are **not** a general-auditor
detection rate, and are not comparable to broad benchmarks (e.g. EVMBench's
~47% autonomous ceiling): this measures two specific, scoped techniques against
ground truth we control. Precision on the decoys is the load-bearing property —
a false positive on a live protocol would burn the exact credibility this is
built to earn. The corpus grows with each shipped technique.

```bash
python3 -m pytest -q                          # ABI parser + evaluation logic (14 tests)
python3 sorohunter/cli.py probe path/to/contract.wasm            # run the engine on local wasm file(s)
python3 sorohunter/cli.py scan <CONTRACT_ID> --network testnet   # read-only acquire + local fork
```

Probes deploy real contracts too: the harness synthesizes `__constructor` args
(Protocol 22+) and a deploy that traps is caught, not fatal. Precision is
biased over recall by design — crude default args never cry wolf, but can miss a
bug that needs specific state (see [`REAL_WORLD.md`](REAL_WORLD.md) caveats,
incl. the unsynthesizable `muxed_address` skip).

## Design

- **ABI (`sorohunter/abi.py`)** — parses `stellar contract info interface --output json` into a probe plan; flags non-synthesizable args instead of probing with a bogus value.
- **Harness (`harness/`, Rust)** — the generic prober. Single-fn mode invokes each function under empty auth and classifies by event-diff (held / breach / view). `--chain` mode executes a two-step privilege chain in one fork and confirms composition by execution. One harness, any contract.
- **Chain proposer (`cli.py:probe_chains`)** — proposes candidate chains (heuristic: address-setter foothold × held gate) and lets the harness **confirm by execution**; only a drained fork becomes a finding, so the heuristic cannot raise a false positive.
- **Report (`sorohunter/report.py`)** — scores verdicts against ground truth (precision/recall) and renders md+json.

## Honest limits

- **3 techniques shipped** (TA-01, TE-01, TP-01). The rest of the Soroban ATT&CK is roadmap (mechanical) or manual (the cryptographic/ZK tactic — that is verifier/circuit review, not fork-sim). Status is marked per cell in [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md).
- `scan` fresh-deploys the fetched WASM, so a finding on a real contract is a **candidate** — confirm against a state-fork (`stellar snapshot`) before any disclosure. Never touch the live contract.
- The event-diff misses a mutation that emits no event (this is *why* the composition detector checks the downstream gated action, not just events); an erroring view is classed `held`, not `view` (harmless — not a false positive).
- The chain proposer is heuristic in *what it tries*; it is exact in *what it confirms* (execution). Coverage of chains it does not propose is a roadmap item.

## Roadmap

Sequenced by the [matrix](SOROBAN_ATTACK.md): more Access techniques (TA-02
unprotected admin setter, TA-03 initializer re-entry), Persistence (TP-01
unprotected upgrade), Storage/TTL (TS-01), then state-fork execution for real
targets, and the **proof-carrying finding ledger** — anchor each confirmed
finding on-chain (hash of PoC + technique-ID + target + timestamp + signature)
as an immutable, timestamped, verifiable "found-first" record. The reputation
engine.

## Attribution & posture

Defensive security research: find bugs in a sandbox, disclose them responsibly,
never touch live funds. The legal perimeter is enforced in code, not promised.
