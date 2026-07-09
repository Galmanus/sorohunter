# sorohunter

**An adversarial hunter for agentic Soroban contracts.** It points generic,
ABI-driven probes at the agentic-payments contract class on Stellar (mandates,
escrow, settlement, constitutional contracts) via local fork-simulation, and
reports missing-authorization bugs with an executed PoC. The surface no one
audits, done the one way that stays legal.

See [`SPEC.md`](SPEC.md) for the full design.

## The idea in one breath

A missing `require_auth` on a Soroban contract means anyone can drain it. It is
the number-one bug and it is ABI-drivable: for every function a contract
exports, synthesize args from its published types, invoke it **under empty
authorization** in a local fork, and watch. A call that changes state (emits an
event) with no signature is a finding, and the invocation itself is the PoC. A
call that aborts held the line. A call that returns without changing anything is
a read-only view, not a finding.

The tool only ever reads a contract's **public** ABI and WASM and runs it in a
**local** `Env`. It never sends a transaction to any network. That is the line
between a tool and a crime, and it is a code invariant here.

## Run

```bash
# 1. build the benchmark corpus (once)
cd bench && stellar contract build && cd ..

# 2. prove precision on the corpus (planted vuln + clean decoy)
python3 sorohunter/cli.py bench
#   precision 100% · recall 100% (tp 1, fp 0, fn 0)
#     vuln_vault     findings: withdraw
#     safe_vault     findings: clean

# 3. point it at a real public contract (read-only acquire + local fork)
python3 sorohunter/cli.py scan <CONTRACT_ID> --network testnet
```

## Why benchmark first

Pointing an imprecise hunter at live protocols burns the exact reputation this
is meant to build. So v1 proves precision/recall on a corpus we control — a
contract with a planted missing-auth `withdraw` and a correctly-authed decoy —
before it earns the right to flag anything real. This is the T3MP3ST discipline:
no executed PoC, no finding; measured against ground truth.

## Tests

```bash
python3 -m pytest -q          # ABI parser + evaluation logic
```

## Design

- **ABI (`sorohunter/abi.py`)** — parses `stellar contract info interface
  --output json` into a probe plan; flags non-synthesizable args (custom
  structs, collections) instead of probing with a bogus value.
- **Harness (`harness/`, Rust)** — the generic prober. Loads a WASM, synthesizes
  `Val`s from the ABI types, invokes each function by symbol under empty auth,
  and classifies via an event-diff (held / breach / view). This is what makes
  one harness work on any contract.
- **Report (`sorohunter/report.py`)** — scores verdicts against ground truth
  (precision/recall) and renders md+json.

## Honest limits (v1)

- `scan` fresh-deploys the fetched WASM, so a breach on a real contract is a
  **candidate** — confirm against a state-fork (`stellar snapshot`) before any
  disclosure. Never touch the live contract.
- The event-diff misses a mutation that emits no event, and an erroring view is
  classed `held` rather than `view` (harmless: not a false positive). Both are
  refinements, not blockers.
- One probe class (missing-auth). Overflow, unprotected-upgrade, storage/TTL,
  state-machine, and cross-contract are roadmap.

## Roadmap

- **Proof-carrying finding ledger:** anchor each confirmed finding on-chain
  (hash of PoC + target + timestamp + signature) — an immutable, timestamped,
  verifiable "found-first" record. The reputation engine.
- State-fork execution for real targets; more probe classes; an LLM
  source-reader for business-logic probes; wrap Scout/OZ as a static layer.
