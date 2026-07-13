# Soroban ATT&CK — v0.1 (proposed)

A tactics × techniques catalog of adversary behavior against Soroban/Stellar
smart contracts. sorohunter is the **fork-validated detector layer** under it:
where a technique is mechanically decidable, sorohunter executes it in a local
`Env` fork and emits an executed PoC; where it is a cryptographic or business-
logic property, the matrix marks it manual.

**Status: v0.1, proposed — not an adopted standard.** This is a first taxonomy,
grounded in real Soroban footguns, public exploits, and CVEs (anchored per
technique), plus EVM analogs (SWC / OWASP Smart Contract Top 10) where the class
transfers. It earns authority by fidelity + executability, not by breadth of
observed campaigns.

**Disanalogy to MITRE ATT&CK (stated, not hidden).** MITRE ATT&CK derives its
authority from thousands of *observed, attributed* real-world intrusions.
Soroban is young; the public-exploit base is thin. So this matrix cannot lean on
campaign breadth — its authority has to come from (a) fidelity to the real bug
classes the Soroban runtime actually exposes and (b) every mechanical technique
being demonstrable as an *executed* fork transition, not an inferred one. Rows
that are aspirational are marked so.

**The invariant.** Every mechanical detector runs only in a local fork against
PUBLIC WASM; recon is read-only acquisition. No transaction is ever signed or
sent to any live network. This is defensive research producing disclosable,
executed proof — a code invariant in the harness, not a promise.

---

## The matrix

| Reconnaissance | Initial Access | Privilege Escalation | Persistence | Auth-Bypass / Evasion | Resource / Storage | Cryptographic Failure | Impact |
|---|---|---|---|---|---|---|---|
| TR-01 ABI/WASM acquire | **TA-01 missing `require_auth`** ✅ | **TE-01 admin capture→drain** ✅ | **TP-01 unprotected upgrade** ✅ | TD-01 auth-subject confusion | TS-01 TTL/archival assumption | TZ-01 underconstrained circuit | OBJ-DRAIN |
| TR-02 classify contract | **TA-02 unprotected admin setter** ✅ | TE-02 allowlist/registry poison | TP-02 admin seize+lock | TD-02 cross-contract auth propagation | TS-02 storage-exhaustion / TTL-bump grief | TZ-02 Fr modular-reduction bypass | OBJ-MINT |
| TR-03 state/role map | TA-03 initializer re-entry | TE-03 oracle/config poison | | | TM-01 unchecked `i128` arithmetic | TZ-03 trusted-setup / VK misuse | OBJ-BRICK |
| TR-04 dep & upgrade-hook discovery | TA-04 auth-arg scope mismatch | | | | | TZ-04 Fiat-Shamir / proof-replay | OBJ-SEIZE |
| | **TA-05 caller-supplied-address trust** ✅ | | | | | | OBJ-CENSOR |
| | **TA-06 unrestricted `transfer_from`** ✅ | | | | | | |

✅ = sorohunter ships a fork-validated detector today. All others: roadmap (mechanical) or manual (cryptographic/business-logic).

---

## Technique catalog

### Reconnaissance
- **TR-01 ABI/WASM acquisition** — read the public interface + bytecode, enumerate exported fns + arg types + synthesizability. *sorohunter: shipped (`abi.py`).*
- **TR-02 contract classification** — vault / escrow / mandate / token-SAC / AMM / registry / upgradeable. Roadmap.
- **TR-03 state & role mapping** — admin/owner keys, allowlists, config/oracle fields. Roadmap.
- **TR-04 dependency & upgrade-hook discovery** — caller-supplied token/SAC addresses, `update_current_contract_wasm` presence. Roadmap.

### Initial Access — the unauthorized state transition (the foothold)
- **TA-01 missing `require_auth` on a state mutation** — the #1 Soroban footgun; EVM analog SWC-105 / OWASP-SC "access control." A mutation succeeds under empty auth. *Detector: fork-invoke under empty auth, event/state delta > 0 → BREACH.* **sorohunter: SHIPPED.**
- **TA-02 unprotected admin setter** — `set_admin` / `transfer_ownership` / `add_allowlist` reachable under empty/weak auth. Fork-detectable. **sorohunter: SHIPPED** (`probe_hijack`, `hijack` verdict — injects the attacker under empty auth and reads the admin getter before/after; catches silent setters the event-delta `breach` probe misses; proven live on the `admin_capture` testnet fixture).
- **TA-03 initializer re-entry** — un-guarded `initialize` / `__constructor` re-sets admin. Classic Soroban re-init. Fork-detectable. Roadmap.
- **TA-04 auth-arg scope mismatch** — `require_auth` present but `require_auth_for_args` scope does not bind the sensitive args. Fork-detectable with arg-mutation. Roadmap.
- **TA-06 unrestricted `transfer_from`** — contract calls `token.transfer_from(self, victim, ..., amount)` spending a victim's standing allowance without `victim.require_auth()`, so anyone can trigger the pull. The static linters flag this by pattern (CoinFabrik Scout's `unrestricted-transfer-from`) but cannot confirm exploitability; sorohunter's economic detectors (`drain`/`greed`) watch only the *contract's* and *attacker's* balances, so a third-party victim's loss slips past. *Detector (`--allowance`): mint a victim, have the victim grant the contract a standing allowance, then invoke the fn under EMPTY auth — a real balance drop on the victim with no victim signature is the executed proof. Validated on `unauth_pull` (drained 1000→0) vs `auth_pull` (`require_auth` reverts → held), 0 false positives.* **sorohunter: SHIPPED.**
- **TA-05 caller-supplied-address trust** — contract acts on an address/token the attacker passes without binding auth to it. Anchor: prompt-injection-into-authorized-payment class (Bankr/Grok ~$150-180K, MCP router drain $500K — the agent *was* authorized). Fork-detectable. **sorohunter: SHIPPED** (`probe_redirect`, `redirect` verdict — decoupled authorizer/recipient injection: one scoped-auth caller, attacker as unbound recipient; orthogonal to `greed` by the self-pay guard; proven live on the `redirect_vault` testnet fixture).

### Privilege Escalation / Composition — the actual chain
- **TE-01 admin capture → privileged drain/mint** — TA-02 foothold, then invoke the legit admin-only path; both steps executed in one fork. *Detector: the harness proposes candidate chains (address-setter × held-gate) and confirms by execution — validated on `chain_vault` (drained) vs `safe_chain_vault` (foothold gated → not flagged), 0 false positives.* **sorohunter: SHIPPED.**
- **TE-02 allowlist / registry poisoning** — add attacker to an allowlist unauth, then use the legitimate gated path. Roadmap.
- **TE-03 oracle / config poisoning** — set a price/config field unauth, then trigger a legit path that pays out on the poisoned value. Roadmap.

### Persistence / Control
- **TP-01 unprotected upgrade** — `update_current_contract_wasm` reachable under empty auth → swap logic → arbitrary control. *Detector: the harness uploads an attacker payload, invokes the candidate upgrade fn under empty auth with the payload's hash, and confirms the hijack only if the code actually swaps (the payload's marker executes). Validated on `upgrade_vault` (hijacked) vs `safe_upgrade_vault` (gated → not flagged).* **sorohunter: SHIPPED.**
- **TP-02 admin seize + lock** — rotate admin to attacker and remove others. Roadmap.

### Auth-Bypass / Evasion
- **TD-01 auth-subject confusion** — `require_auth` on an attacker-controlled subject rather than the fund owner. Roadmap.
- **TD-02 cross-contract auth propagation** — sub-invocation auth not re-scoped; a call chain carries authorization it should not. Roadmap.

### Resource / Storage (Soroban-native)
- **TS-01 TTL / archival assumption** — logic assumes temporary storage persists, or an archived entry can be resurrected into stale state. Soroban-specific (instance/persistent/temporary + TTL). Roadmap.
- **TS-02 storage-exhaustion / TTL-bump griefing** — resource DoS via forced writes / TTL bumps. Roadmap.
- **TM-01 unchecked `i128` arithmetic** — over/underflow where `overflow-checks` is off or the bug is logic-level. EVM analog SWC-101. Roadmap.

### Cryptographic Failure (ZK-contract subclass — Soroban-native, and Nethermind's turf)
These are **not** fork-decidable — they are circuit/verifier soundness review. The matrix includes them because Soroban ships native BN254/BLS12-381/Poseidon2 host functions (Protocol 25/26), so ZK contracts are a first-class Soroban target, and this is where the verifier-audit demand actually is.
- **TZ-01 underconstrained circuit** — a missing constraint lets a forged witness satisfy the proof. The dominant, silent ZK vuln class. *sorohunter: manual (ZK review).*
- **TZ-02 Fr modular-reduction bypass** — improper field-element reduction in a BN254/BLS12-381 verifier. Anchor: **CVE-2026-32322**. Manual.
- **TZ-03 trusted-setup / verifying-key misuse** — single-contributor setup, or a `gamma==delta` VK collapse. Anchors: **Vayyl** guards the Veil-Cash/FoomCash VK bug; **Poseidon V1 banned, CVE-2026-32129**. Manual.
- **TZ-04 Fiat-Shamir / proof-replay** — transcript weakness, or an on-chain proof stolen and replayed because it is not sender-anchored (the SDAS sender-anchoring result). Manual.

### Impact / Objective
Every confirmed chain terminates in a realized, fork-executed objective attached to the PoC: **OBJ-DRAIN** (funds out), **OBJ-MINT** (supply/balance forged), **OBJ-BRICK** (freeze/DoS), **OBJ-SEIZE** (admin captured), **OBJ-CENSOR** (selective block).

---

## How sorohunter maps

sorohunter is the executable substrate: for every mechanical technique it aims
to ship a fork-validated detector so a finding is an executed transition, never
an inferred one. Today: **7 detectors shipped — TA-01 (missing-auth), TE-01
(composition chain), TP-01 (unprotected upgrade), OBJ-DRAIN (unauthenticated
economic drain), OBJ-GREED (authorized-but-unearned payout), TA-02 (admin
capture), TA-05 (injected-recipient / caller-supplied-address trust)**,
ground-truth-measured; the rest are the roadmap,
sequenced by prevalence (Access → Composition → Persistence → Storage). The
cryptographic tactic is deliberately marked manual —
that is ZK-review work (Manuel's slippay-zk / verifier-audit lane), not fork-sim,
and it is what ties the matrix to the Nethermind verifier wedge.

## How the taxonomy operationalizes

Owning a credible, evidence-grounded, executable Soroban ATT&CK is
reference-capture: sorohunter is the tool that operationalizes the matrix. The
proof-carrying finding ledger (on-chain hash of PoC + technique-ID + target +
timestamp + signature) turns each confirmed detection into a public, timestamped
"found-first" record keyed by technique — the reputation engine.
