# Ingress ATT&CK — v0.1 (proposed)

A tactics × techniques catalog of the **web2 → web3 ingress boundary**: the
off-chain surfaces that hold a *standing on-chain capability* and are therefore
the entry points through which an attacker reaches an on-chain effect. This is
the sibling of [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md): that map catalogs
adversary behavior *inside* the contract; this one catalogs how the attacker
*gets there* from the off-chain side. Together they are one kill chain, from the
weakest link (web2) to the objective (on-chain, irreversible).

sorohunter is again the executable layer under it: where an ingress technique
terminates in a contract call, sorohunter feeds the contract the adversarial
ingress payload and **executes** it in a local `Env` fork, emitting a PoC; where
the technique is a pure off-chain compromise, the matrix marks it manual.

**Status: v0.1, proposed — not an adopted standard.** First taxonomy, grounded in
real Stellar/Soroban wallet and infra footguns plus the transferable web2 classes
(OWASP Web / API Top 10), anchored per technique where a public incident exists.
It earns authority by fidelity + executability, not by breadth of campaigns.

## The two disanalogies (stated, not hidden)

- **vs MITRE ATT&CK.** Same caveat as the Soroban map: MITRE leans on thousands of
  observed, attributed intrusions; the Stellar smart-wallet exploit base is thin.
  Authority here comes from fidelity to the real trust boundaries the stack
  exposes and from every mechanical cell being an *executed* fork transition.
- **vs web2 appsec (OWASP).** The individual vuln classes here (SSRF, forged
  webhook, dependency compromise, session-binding failure) are **not new** — OWASP
  owns them. What is new is the **blast-radius mapping**: in web2 an SSRF ends in a
  data breach with a remediation window; the *same* SSRF that reaches a
  fee-sponsor key ends in a mainnet drain with **no chargeback and no rollback**.
  This map's contribution is the `OBJ-*` column — the on-chain, irreversible
  consequence — which neither MITRE nor OWASP attaches to this boundary. The
  novelty is the impact, not the technique.

## The invariant (the axiom, pushed one ring out)

sorohunter's on-chain axiom is *everything that communicates is surface*. The
ingress map is the same axiom past the contract boundary:

> **The chain verifies the message it receives; it cannot verify the off-chain
> context that produced it.** Therefore every off-chain component that *produces*,
> *submits*, or is *trusted-as-truth-by* an on-chain-privileged message is inside
> the trusted computing base (TCB) of the on-chain system — whether or not anyone
> modeled it there. This map enumerates that unacknowledged TCB.

**Disanalogy to a classical TCB:** in a classical TCB you own the components. Here
half of them are third parties (RPC provider, oracle, relay, CI runner) that are
*adversarial-by-default* and trusted with no contract. Nobody put the RPC
provider in the threat model, but it is in the TCB.

## The bounding principle (what keeps this finite, not "all of web2")

A surface is **in scope** iff it holds a **standing on-chain capability** — one of:

1. a **signing key or signer role** (custody, co-signer, MPC share, recovery/add-signer),
2. a **submission / fee-sponsor authorization** (relayer, bundler, meta-tx, paymaster),
3. a **trusted-caller / allowlist** entry the contract acts on,
4. an **oracle / feed write** the contract or app reads as truth,
5. **upgrade / admin authority**,
6. a **gate whose pass unlocks an on-chain effect** (KYC/payment/compliance callback).

Read-only surfaces with no on-chain privilege are **out**. Without this cut the
map is the whole internet and unfalsifiable; with it, the ingress TCB of any given
system is finite and enumerable.

**Legal invariant (mirror of the Soroban map).** This is analysis. Any probing
runs only against systems you own or are authorized to test; sorohunter's fork
layer executes only against PUBLIC wasm and signs no live transaction.

---

## The matrix

Columns = ingress classes (off-chain surfaces with standing on-chain capability).
Cells = techniques. Grade per cell:
**● FORK-PROVABLE** (terminates in a contract call sorohunter can execute with an
adversarial payload — shipped or mechanical roadmap) ·
**◐ HYBRID** (off-chain compromise whose on-chain effect is fork-provable once the
payload is in hand) ·
**○ MANUAL** (pure off-chain / infra compromise; conventional appsec proof).

| Client / Ceremony | Relay / Submission | Key Custody | Trusted Feed | Off-chain Gate | Infra Endpoint | Deploy / Gov Ops | Impact |
|---|---|---|---|---|---|---|---|
| **IC-01 challenge/payload not bound** ● ✅ | IR-01 unintended sponsored tx ◐ | IK-01 co-signer / MPC compromise ○ | IF-01 oracle feed manipulation ◐ | IA-01 forged/replayed webhook ◐ | IN-01 malicious RPC forges state ○ | IO-01 CI/CD holds mainnet key ○ | OBJ-DRAIN |
| IC-02 origin / RP-ID not checked ◐ | IR-02 fee-sponsor drain/grief ○ | IK-02 key in logs / env / CI ○ | IF-02 indexer/subgraph lies ○ | **IA-02 gate not enforced on-chain** ● | IN-02 RPC eclipse / censorship ○ | **IO-02 admin dashboard weak auth** ◐ | OBJ-SEIZE |
| IC-03 tx tampered pre-sign ◐ | IR-03 relay substitutes/reorders ○ | **IK-03 add-signer / recovery abuse** ◐ | IF-03 stale / rollback feed ○ | IA-03 callback race / double-credit ○ | IN-03 gateway holds signing key ○ | IO-03 multisig ceremony surface ○ | OBJ-MINT |
| IC-04 blind signing (no confirm) ○ | | | | | | | OBJ-BRICK |
| | | | | | | | OBJ-MISLEAD |

✅ = a fork-validated detector ships in sorohunter today. Three ingress cells are
already executable — they are existing sorohunter detectors, reframed as
boundary detectors (see *How sorohunter maps*).

---

## Technique catalog

### Client / Ceremony (IC) — the surface that constructs and signs
- **IC-01 challenge / payload not bound** — the signed WebAuthn assertion (or its
  reconstructed `clientDataJSON`) is not tied to the on-chain payload being
  authorized; a genuine assertion for A authorizes B. Anchor: **swig-wallet #143**.
  **● FORK-PROVABLE — SHIPPED** (`--realauth-p256`).
- **IC-02 origin / RP-ID not validated** — an assertion produced under a phishing
  origin is accepted because origin/rpId is not enforced (on-chain or in the RP).
  ◐ Hybrid.
- **IC-03 tx tampered before signing** — a compromised frontend or malicious wallet
  SDK dependency alters recipient/amount between construction and the user's blind
  approval. The injected recipient is then on-chain fork-provable (ties to
  **TA-05**). ◐ Hybrid.
- **IC-04 blind signing** — the device never shows the user the actual op being
  authorized; a UX/protocol gap, not a code bug. ○ Manual.

### Relay / Submission (IR) — the surface that submits on your behalf
- **IR-01 unintended sponsored tx** — a relayer/paymaster (e.g. launchtube-style)
  submits and sponsors an operation the user never intended, because the session
  or challenge is not bound to the submitted op. ◐ Hybrid.
- **IR-02 fee-sponsor drain / grief** — the sponsor's authorization is abused to
  exhaust its balance or grief users. ○ Manual.
- **IR-03 relay substitution / reordering** — the relay is trusted to submit
  faithfully and does not (MEV-adjacent, or malicious relay). ○ Manual.

### Key Custody (IK) — off-chain holders of signer power
- **IK-01 co-signer / MPC-node compromise** — an off-chain co-signer or MPC share
  is compromised and forges authorization directly. ○ Manual.
- **IK-02 key material in logs / env / CI** — a signing key leaks through
  operational surface. ○ Manual.
- **IK-03 add-signer / recovery abuse** — the recovery or `add_signer` flow adds an
  attacker key under weak auth (the passkey-kit account-management surface). Ties
  to **TA-02** on-chain. ◐ Hybrid (the add-signer call is fork-provable).

### Trusted Feed (IF) — surfaces trusted as truth
- **IF-01 oracle feed manipulation** — the off-chain API the oracle pulls is
  manipulated, poisoning the on-chain price/config a legit path pays out on. Ties
  to **TE-03**. ◐ Hybrid.
- **IF-02 indexer / subgraph lies** — the dApp trusts an indexer for state; a lying
  indexer makes the user act on false state. `OBJ-MISLEAD`. ○ Manual.
- **IF-03 stale / rollback feed** — a feed serves stale or rolled-back data past a
  validity window. ○ Manual.

### Off-chain Gate (IA) — callbacks that unlock on-chain effects
- **IA-01 forged / replayed webhook** — a KYC / payment / Pix / off-ramp callback is
  forged or replayed to unlock an on-chain mint/transfer. Anchor: payment-webhook
  forgery (directly relevant to a Pix→on-chain ramp). ◐ Hybrid.
- **IA-02 gate not enforced on-chain** — the on-chain effect is reachable without
  the off-chain gate having actually passed: the gate is advisory, the contract
  path is open. **● FORK-PROVABLE** (reachability under empty/weak auth is the
  TA-01/TA-05 family — sorohunter already executes this shape).
- **IA-03 callback race / idempotency** — a non-idempotent callback double-credits.
  ○ Manual.

### Infra Endpoint (IN) — the plumbing trusted for state and submission
- **IN-01 malicious / compromised RPC** — the node endpoint returns forged state;
  the app/user acts on a lie. `OBJ-MISLEAD`. ○ Manual.
- **IN-02 RPC eclipse / censorship** — selective withholding of state or tx. ○ Manual.
- **IN-03 gateway holds a signing key** — an API gateway signs/submits privileged
  ops; its compromise is a direct on-chain capability. ○ Manual.

### Deploy / Governance Ops (IO) — the surfaces with the most power
- **IO-01 CI/CD holds a mainnet key** — a deploy/upgrade key lives in a CI runner or
  GH Actions secret; a supply-chain or secret leak poisons a deploy. ○ Manual.
- **IO-02 admin dashboard weak auth** — an ops dashboard triggers a privileged
  on-chain action behind weak/no auth. Ties to **TA-02**. ◐ Hybrid.
- **IO-03 multisig ceremony surface** — a signer's laptop or a blind co-sign step is
  the real weak link in a "secure" multisig. ○ Manual.

### Impact / Objective
Shared with the Soroban map, plus one: **OBJ-DRAIN**, **OBJ-SEIZE**, **OBJ-MINT**,
**OBJ-BRICK**, **OBJ-CENSOR**, and **OBJ-MISLEAD** (the chain/contract is correct;
the user or app acts on off-chain-forged truth). Every confirmed ingress chain
terminates in one of these — and unlike web2, none of them roll back.

---

## How sorohunter maps

The map does not start at zero: three ingress cells are **already executed**
detectors, reframed as boundary detectors.

- **IC-01** (challenge/payload not bound) = `--realauth-p256`, the secp256r1 /
  WebAuthn binding prover. **Shipped.** See [`AUTH_BYPASS.md`](AUTH_BYPASS.md).
- **IC-03 / IA-02** (injected recipient / gate not enforced) = **TA-05**
  caller-supplied-address trust (`probe_redirect`, `redirect` verdict). **Shipped.**
- **IK-03 / IO-02** (add-signer / admin-dashboard effect) = **TA-02** unprotected
  admin setter (`probe_hijack`, `hijack` verdict). **Shipped.**

For every other mechanical (●/◐) cell the goal is the same as the on-chain map:
ship a fork-validated detector so a finding is an executed transition, not an
inference. The ○ MANUAL cells are conventional appsec / infra review — the map's
job there is to make sure they are *in the threat model at all*, which today they
are not.

## Instantiating the chain per project (the sorohunter `ingress` mode)

The taxonomy above is the *grammar*. The tool's job is to read a concrete
project and emit **that project's sentence** — its actual ingress TCB, graded and
partly proven — not a generic checklist. This is a new sorohunter mode:

```
sorohunter ingress <project_root> --network mainnet --contracts C...,C...
```

It builds a **capability graph** for the target:

- **On-chain end (automated, already proven).** Extend the existing recon
  (TR-01..04): for each contract, resolve who holds power — admin/owner keys,
  signer roles, allowlists, oracle addresses read as truth, upgrade authority,
  fee-sponsor grants. This is the set of *on-chain capabilities* and, per
  capability, the `OBJ-*` blast radius (what it can actually do). sorohunter
  already computes this by fork.
- **Off-chain end (automated discovery, signature-based).** Walk the repo/config
  for the surfaces that hold or produce those capabilities: WebAuthn/passkey call
  sites, relay/launchtube/paymaster config, hardcoded RPC endpoints, webhook
  route handlers, oracle/indexer clients, and CI secrets (`.github/workflows`,
  `.env` schemas, `wrangler.toml`, serverless configs). Pattern-based — so this
  half has the same false-positive/negative profile as any static scan, and is
  labeled *discovery*, not proof.
- **The join (the high-value, semi-automated step).** Match an off-chain
  key/address in the repo or config to an on-chain role. When the address is in
  config, this is automatic and is where the sharpest findings live ("this
  backend key **is** the admin of contract C → an IK/IO edge with `OBJ-SEIZE`").
  When the key lives in a vault the tool cannot see, the edge is emitted as
  *unresolved*, never silently dropped.
- **Grade + prove.** Each edge that terminates in a reachable contract call is
  handed to the fork layer and **executed** with an adversarial ingress payload
  (● cells: IC-01 via `--realauth-p256`, IC-03/IA-02 via `redirect`, IK-03/IO-02
  via `hijack`). Pure off-chain edges are flagged for manual review (○ cells).

**Output:** the project's filled ingress matrix — every edge with its class,
grade, `OBJ-*` blast radius, and (for ● edges) an executed PoC — plus an explicit
**"surfaces I could not see"** list.

**The completeness failure mode, named (the discipline that keeps it honest).**
This map is only as complete as its inputs. A third-party relay whose code you do
not have, an RPC provider, an oracle backend — the tool cannot see them, and it
must say so. It reports *what it mapped* and *what it could not reach*; it never
implies the graph is the whole TCB. This mirrors sorohunter's on-chain invariant
(`deploy-failed` is never reported as `held`): an unseen surface is reported as
unseen, never as absent.

## The falsifier (the afternoon that decides if this has teeth)

Take **one** real Stellar system and enumerate its complete ingress TCB under the
bounding principle — every off-chain surface holding a standing on-chain
capability. Candidates: a passkey wallet + its relay, or a Pix on/off-ramp.
**Test:** if the map surfaces **≥1 entry point that neither a contract audit nor a
standard web2 pentest would have flagged**, the taxonomy is load-bearing. If every
cell it produces is already owned by one of those two disciplines, it is a
checklist, not a contribution. This is the experiment that promotes the map from
proposal to reference.

## Worked example — a Pix→USDC ramp (falsifier run)

The falsifier was run against a real Pix→USDC ramp (the author's own product, so
authorization is not in question). The point is defensive: enumerate the ingress
TCB and check whether it surfaces a cell that neither a Soroban contract audit nor
a standard web2 pentest would flag. It did.

**What the system does right (the classic cell is closed by design).** Settlement
does **not** move money: it observes an on-chain payment and reconciles it against
an order (`verifySettlement(payment, order, settledTxHashes)` — checks binding,
consented recipient, value, and replay), and the wallet contract already bounded
the transfer. An authority gate verifies an ed25519 merchant signature and
hard-denies any money movement. So **IA-01 "forged webhook releases funds" is not
reachable** — a forged payment callback cannot release value, because release is
on-chain-bounded, not callback-driven. A contract audit and a web2 pentest both
pass here, correctly.

**The cell they both miss — IF-01 / IF-03 (trusted feed, no integrity).** The
BRL→USD rate is fetched from a single unauthenticated third-party endpoint
(`open.er-api.com`) with a hardcoded fallback on failure. That rate is locked at
order creation and directly determines the USDC amount a user receives. There is
no signature, no multi-source median, and no sanity bound.

- **Blast radius `OBJ-DRAIN` / mispricing.** Whoever controls that number —
  endpoint compromise, MITM, DNS hijack, or the provider returning a manipulated
  value — controls the fiat→on-chain-value conversion, irreversibly. The stale
  variant is its own lever: a DoS on the rate endpoint forces every conversion
  onto the fixed fallback, transactable at a chosen moment.
- **Why the contract audit misses it:** the on-chain contracts are correct; they
  move exactly the USDC amount they are told. The defect is off-chain.
- **Why the web2 pentest misses it:** "app calls a public FX API with a fallback"
  reads as a price display, not as *the pricing oracle for on-chain settlement*.
  The blast-radius mapping is the seam neither discipline owns.

**A second, unconfirmed cell — IN-01 (RPC/feed trust).** `verifySettlement` is a
pure function over the `payment` object it is handed. Its safety rests on the
caller sourcing that object from an authentic Horizon; a payment read from an
attacker-controlled RPC or a service-role-writable DB row that matches on
memo/destination/amount would pass → `mark_paid` with no real payment
(`OBJ-MISLEAD`). Emitted as *unresolved* pending a trace of the caller.

**Honest caveat (and it argues for the method).** The rate cell's blast radius
activates fully only when a first-party settlement anchor is live; today the route
passes through a third-party on-ramp, so the rate is a pricing/measurement layer.
But the map flags the cell *before* it becomes load-bearing — which is the entire
reason to map ingress pre-incident. A contract audit on the day the anchor ships
would still miss it; so would a web2 pentest.

**Verdict: the falsifier passes** — one entry point, anchored in code, invisible to
both incumbent disciplines. The map is load-bearing, not a poster. Fix direction
(for the mapped system, not applied here): rate integrity via multi-source median
+ a sanity bound + rejecting `stale` at order creation; and settlement reading
`payment` only from a pinned/authenticated Horizon.

## Why this matters

The Soroban map made sorohunter "the adversary taxonomy + the fork-validated
detector layer." The ingress map extends the claim to the part **nobody owns**:
the seam between web2 and web3, visible to neither web3 audit tooling (which stops
at the contract) nor web2 appsec (which does not know the impact is on-chain and
irreversible). The two-map kill chain is the deliverable; the moat is that mapping
it credibly requires one person who holds both threat models at once.
