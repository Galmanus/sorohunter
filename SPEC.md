# sorohunter — adversarial hunter for agentic Soroban contracts

**Point autonomous adversarial probes at the agentic-payments contract class on
Stellar (mandates, escrow, settlement, constitutional contracts), via local
fork-simulation, with executed PoC. The surface no one audits, done the one way
that stays legal.**

Status: v1 design. Standalone. Part of the path to being the Stellar security
reference; the on-chain proof-carrying finding ledger (the "agent DNA" applied
to findings) is v2 (see Roadmap).

---

## 1. The wedge

- **Target class:** agentic contracts — the surface Manuel pioneered
  (`agent-escrow`, `settlement_gate`, `lineage_registry`). Nobody audits it yet.
- **Method:** generic, ABI-driven adversarial probes run in a **local fork** of
  the contract, never against the live contract. Executed PoC or it is not a
  finding (the T3MP3ST discipline).
- **v1 proof:** a benchmark corpus (planted-vuln + clean decoy) proving the
  engine catches real missing-auth and does **not** false-positive. Precision
  first, because pointing an imprecise hunter at public contracts burns the
  exact reputation this is meant to build.

## 2. Legal perimeter — enforced in code, not discipline

- The tool only ever: `stellar contract info interface --output json` (ABI,
  read-only) and `stellar contract fetch` (WASM, read-only), then deploys the
  fetched WASM into a **local `Env`**. It runs their public code in our sandbox.
- There is **no code path** that submits an attack transaction to any non-local
  network. Probing happens exclusively in-process against a local ledger.
- Disclosure is manual and coordinated (Immunefi Stellar, SDF Audit Bank, or
  direct-to-project with a deadline). The tool never contacts a target owner.
- This is the line between "tool" and "crime". It is a code invariant here.

## 3. ABI source (verified)

`stellar contract info interface --id <C> --network <net> --output json` returns
an array of `SCSpecEntry`. We use `function_v0`:

```json
{ "name": "head",
  "inputs": [ { "name": "genesis_hash", "type_": { "bytes_n": { "n": 32 } } } ],
  "outputs": [ ... ] }
```

`type_` is a bare string for primitives (`"address"`, `"u32"`, `"i128"`,
`"bool"`, `"symbol"`, `"string"`, `"bytes"`, `"void"`) or an object for
composites (`{"bytes_n":{"n":N}}`, `{"vec":...}`, `{"option":...}`,
`{"tuple":...}`, `{"map":...}`, `{"udt":{"name":...}}`).

## 4. The generic auth probe (v1's single, highest-value class)

Missing `require_auth` = anyone drains. It is the number-one Soroban bug and it
is ABI-drivable. For each exported function:

1. **Synthesize args from the ABI types** — Address → a generated account,
   BytesN\<N\> → N zero bytes, u32/u64 → 0, i128/u128 → 1, bool → false,
   symbol/string → "x", bytes → empty, vec → empty. A function with a `udt`
   (custom struct/enum) arg is **skipped with a note** in v1 (unsynthesizable),
   not silently dropped.
2. **Invoke under empty auth** — `env.set_auths(&[])`, then dynamic
   `try_invoke_contract` by symbol with the synthesized `Vec<Val>`.
3. **Classify with a state-change signal** (the precision mechanism):
   - call **aborts** → the function enforces auth → **held**.
   - call **succeeds and emits an event** (state change without a signature) →
     **missing-auth candidate** → BREACH (executed PoC = the invocation).
   - call **succeeds with no event** → a read-only view → **no finding**.

The event-diff is what separates a legit view from an unauthorized mutation. Its
honest limit: a mutation that emits no event could be missed; a view that emits
an event could false-positive. So a real-target finding is a **candidate** a
human confirms before disclosure. On the benchmark (whose contracts emit events
on state change, as the escrow does) the signal is clean, which is what proves
the mechanism.

## 5. Architecture (v1)

```
acquire (python)          fork-sim + probe (rust)        report (python)
------------------        -----------------------        ------------------
contract-id / wasm  --->  load WASM into Env       --->  killchain-style
+ ABI json          |     synth args from ABI            md + json
(stellar CLI)        |     invoke under empty auth        precision/recall
                     |     event-diff classify            on the benchmark
                     +---> emit verdicts.json  ----------+
```

- **Benchmark instantiation:** for corpus contracts we own the constructor, so
  fresh `env.register(wasm, ctor_args)` works and we know ground truth.
- **Real-target instantiation (v1.1, wired not shipped):** arbitrary public
  contracts have unknown constructor args, so real targets need a **state fork**
  (`stellar snapshot create --address` → `Env::from_ledger_snapshot_file`),
  which yields an already-initialized instance. The acquire path (ABI + WASM
  fetch) is built in v1; snapshot-fork execution is the immediate next step.

## 6. Components + build order

| # | file | responsibility | lang |
|---|---|---|---|
| 1 | `sorohunter/abi.py` | parse `--output json` → probe plan `[{fn, arg_types, ...}]` | py |
| 2 | `harness/` (Rust) | load WASM, synth Vals from arg_types, dynamic invoke under empty auth, event-diff classify, emit verdicts | rust |
| 3 | `bench/` | 2-3 Soroban contracts: planted missing-auth + clean decoy (+ ground truth) | rust |
| 4 | `sorohunter/report.py` | rollup + md/json (reuse escrow-adversary/killchain shape) | py |
| 5 | `sorohunter/cli.py` | `sorohunter bench` and `sorohunter scan <id>` (acquire→harness→report) | py |
| 6 | `README.md` | one-command run | — |

TDD the verifiable-logic pieces (abi parser, arg-type mapping, verdict
classification). The Rust harness is proven against the benchmark corpus:
catches the planted vuln, clears the decoy.

## 7. Done criteria (v1, binary)

- [ ] `sorohunter bench` runs the engine over the corpus with one command.
- [ ] the planted missing-auth contract is flagged (breach, executed PoC).
- [ ] the clean decoy is NOT flagged (no false positive).
- [ ] a `report.md` reads as a draft: what was probed, precision/recall, evidence.
- [ ] the ABI parser handles the real `--output json` of a deployed contract.
- [ ] no code path targets a non-local network (legal invariant holds).

## 8. Reuse

escrow-adversary (the P4 auth probe → generalized; the Rust-probe / Python-report
split), killchain.py (rollup/report shape), the soroban skill's vuln taxonomy,
the stellar CLI (ABI/WASM fetch, proven).

## 9. Roadmap (explicitly out of v1)

- **v2 — proof-carrying finding ledger (the reputation play):** anchor each
  confirmed finding on-chain via the skernel mechanism (hash of PoC + target +
  timestamp + signature). An immutable, timestamped, verifiable "found-first"
  record. This is the "agent DNA applied to findings" — how the track record
  becomes unforgeable, and the real engine of becoming the reference.
- More probe classes: integer overflow, unprotected upgrade
  (`update_current_contract_wasm`), storage-key collision, TTL/archival,
  cross-contract return trust, state-machine ordering.
- Real-target snapshot-fork execution (v1.1).
- LLM source-reader for business-logic probes; swarm parallelism (T3MP3ST-style).
- Wrap Scout/OZ static detectors as a complementary arsenal layer.
- The hunter as a skernel-governed sovereign mind (constitution: "only fork-sim,
  never the live contract"; findings signed by its constitutional key).
