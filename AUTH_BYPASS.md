# Auth-bypass prover (`harness --checkauth`)

sorohunter's specialization: **prove smart-account authorization bypass by
execution**, not by inference. This is the moat component. Everything else in
the engine screens business functions under `mock_all_auths()`; this stage does
the opposite, and it is the only stage that runs a contract's real
`__check_auth`.

## The class

A Soroban smart account (custom account) implements `__check_auth(payload,
signature, contexts)`. It is the entire authorization surface: whoever
`__check_auth` says is authorized, is authorized. The high-severity bug is an
implementation that returns `Ok(())` for a request that carries no valid
signature. One such bug in a widely-replicated implementation (e.g. a passkey
wallet kit) ripples to every wallet built on it.

## Why the rest of the engine can't find it

`env.mock_all_auths()` **skips `__check_auth` entirely** — the host stops asking
the account whether a call is authorized. Any "bypass" found under a mocked auth
is a phantom: the authorization logic never ran. The prover therefore uses
`Env::try_invoke_contract_check_auth`, which invokes the real `__check_auth`
with **no mock**, and reads its actual verdict.

## How it proves a bypass (and why it has zero false positives)

The prover submits a battery of signatures that **no honest signer would ever
produce** for the payload — an unauthenticated, forged, or type-confused blob:

| hypothesis    | what it is                          |
|---------------|-------------------------------------|
| `void`        | no signature at all                 |
| `empty-bytes` | a zero-length `Bytes`               |
| `zero-64`     | 64 zero bytes                       |
| `garbage-64`  | 64 bytes of `0xAB`                  |
| `int-0`       | the integer `0` (wrong type)        |

Each runs against a realistic auth context (a `transfer` on the account) and an
empty context. A correct account **rejects every one of them**. So:

- **`Ok(())` from any hypothesis = BYPASS** (the account authorized garbage).
- A clean run has **zero false positives by construction**: there is no honest
  signature in the battery, so a correct account cannot pass. This is not a
  claim — it is proven by the `good_account` fixture on every run.

## Ground truth (fixtures in `bench/`)

| fixture               | `__check_auth`                        | verdict       | bypasses |
|-----------------------|---------------------------------------|---------------|----------|
| `good_account`        | correct ed25519 verify (FP control)   | `held`        | 0 / 10   |
| `blind_account`       | `Ok(())` unconditionally              | `auth-bypass` | 10 / 10  |
| `void_guard_account`  | rejects only a void signature         | `auth-bypass` | 8 / 10   |

`void_guard` is the precision test: the prover rejects exactly its `void` probes
and flags the 8 non-void ones — it reads the specific bug, it does not merely
detect a stub. `tests/test_checkauth.py` codifies all three as a regression gate;
the `good_account` assertion is load-bearing (if it ever bypasses, the prover is
worthless and must not ship a finding).

## Run

```
# build (Rust toolchain + wasm32v1-none target required)
(cd harness && cargo build --release)
(cd bench && cargo build --release --target wasm32v1-none \
     -p good_account -p blind_account -p void_guard_account)
cp bench/target/wasm32v1-none/release/{good,blind,void_guard}_account.wasm soro/assets/

# probe a __check_auth-exporting wasm (ctor_csv describes the constructor args)
harness/target/release/harness --checkauth <wasm> <out.json> "bytes_n:32"
```

Constructor shapes handled: none, one `BytesN<32>` (ed25519 signer), one
`BytesN<65>` (secp256r1 / passkey signer), one `Address` (admin). Other shapes
fall back to generic arg synthesis and may fail to deploy.

## Second prover: `--replay` (the passkey / signature-binding class)

`--checkauth` throws forgeries at an account that ignores its signature. A real
passkey wallet does the opposite — it verifies a genuine signature — so the
forgery battery finds nothing on it. Its bug is subtler: it may verify the
assertion but never bind it to the payload being authorized. `--replay` targets
exactly that class.

The move `--checkauth` cannot make: **we hold the signer key** (our own fixture,
or any account whose test signer we control), so we produce ONE genuinely valid
ed25519 signature and ask two questions a forgery battery never can.

1. **Positive path** — is a valid signature accepted for its own payload? (This
   closes the old "rejection path only" limit below.)
2. **Cross-payload replay** — is that *same valid pair* accepted for a
   *different* payload B? An account that binds `msg == signature_payload`
   rejects it; one that doesn't authorizes B with a signature meant for A.

Signature ABI probed: a 96-byte `msg[0..32] || sig[32..96]` blob. This is the
executable analogue of a passkey wallet that reconstructs `clientDataJSON` from
attacker-supplied fields and verifies against that instead of the challenge the
protocol demanded (cf. swig-wallet #143).

| fixture             | `__check_auth`                              | verdict         | bypasses |
|---------------------|---------------------------------------------|-----------------|----------|
| `bound_account`     | verify ed25519 **and** assert msg==payload  | `held`          | 0 / 3    |
| `unbound_account`   | verify ed25519, never checks the binding    | `replay-bypass` | 1 / 3    |
| `good_account`      | raw `BytesN<64>` ABI (mismatched shape)     | `inconclusive`  | 0 / 3    |

`bound` and `unbound` are the load-bearing pair: **both** verify a real signature
(the `forgery-control` probe rejects garbage on both) and **both** accept the
valid pair for its own payload (`positive-path`). They differ on one line — the
`msg == signature_payload` check. So a `replay-bypass` reads the binding bug
specifically, not a parse failure or a missing verify. `good_account` uses a
different signature ABI, so the prover reports `inconclusive` (no valid baseline)
rather than inventing a verdict — codified in `tests/test_replay.py`.

```
(cd bench && cargo build --release --target wasm32v1-none \
     -p unbound_account -p bound_account -p good_account)
cp bench/target/wasm32v1-none/release/{unbound,bound,good}_account.wasm soro/assets/
harness/target/release/harness --replay <wasm> <out.json> "bytes_n:32"
```

## Third prover: `--realauth-p256` (the real passkey / WebAuthn branch)

`--replay` and `--realauth` (ed25519) prove the machinery, but a correct
`ed25519_verify(pk, payload, sig)` binds the signature to the payload by
construction — so on the ed25519 branch the cross-payload probe is nearly
vacuous. The bug that actually ships in passkey wallets lives on the
**secp256r1 / WebAuthn** branch (swig-wallet #143): a wallet that verifies the
ECDSA assertion over `sha256(authenticatorData || sha256(clientDataJSON))` but
never checks that `clientDataJSON.challenge` decodes to the `signature_payload`
it is authorizing. `--realauth-p256` targets exactly that.

The prover holds a p256 key, deploys the target via its `Signer::Secp256r1`
branch, and forges a genuine WebAuthn assertion (real authenticatorData +
clientDataJSON carrying `challenge = base64url(payload)` + a real
ECDSA-secp256r1 signature, low-S normalized). Three probes:

1. **positive** — a genuine assertion for payload A is accepted for A (proves the
   real `__check_auth` was reached and the encoder matches the wasm's ABI/digest
   byte-for-byte).
2. **forgery-control** — the same assertion with a garbage 64-byte signature is
   rejected (proves the account cryptographically verifies).
3. **cross-payload replay** — the genuine A-assertion (its `clientDataJSON` still
   encodes challenge A) is presented to authorize a DIFFERENT payload B. A wallet
   that binds the challenge rejects it; one that doesn't authorizes B — BYPASS.

| fixture           | `__check_auth`                                        | verdict         | bypasses |
|-------------------|-------------------------------------------------------|-----------------|----------|
| `bound_passkey`   | verify assertion **and** assert challenge == payload  | `held`          | 0 / 3    |
| `unbound_passkey` | verify assertion, never checks the challenge binding  | `replay-bypass` | 1 / 3    |

`bound`/`unbound` differ by exactly one block (the challenge check), both verify
the same ECDSA assertion (`forgery-control` rejects garbage on both) and both
accept the valid assertion for its own payload (`positive-path`) — so a
`replay-bypass` reads the binding bug specifically, not a parse/verify failure.
`tests/test_realauth.py` codifies both, with `bound_passkey` as the load-bearing
FP gate.

**Landed on the real target.** Run against the only mainnet wasm the census found
that exports `__check_auth` (a passkey-kit smart wallet, hash `ecd990…`), the
encoder reaches its genuine secp256r1 `__check_auth` (positive-path accepted),
rejects the forgery, and rejects the cross-payload replay → **`held`**. That is a
grounded result on real mainnet code, on the branch that matters — not a fixture,
and no longer `deploy-failed`.

```
(cd bench && cargo build --release --target wasm32v1-none \
     -p bound_passkey -p unbound_passkey)
cp bench/target/wasm32v1-none/release/{bound,unbound}_passkey.wasm soro/assets/
harness/target/release/harness --realauth-p256 <wasm> <out.json>
```

## Honest limits (what this does NOT yet do)

- **`--replay` needs a signer we control.** It fabricates the valid signature
  from a known key, so it applies to fixtures and to differential testing of a
  target's *implementation* (recompile with a test signer), not to a live
  mainnet account whose key we do not hold. Against an unknown-key target it can
  only report `inconclusive`. A field version would need a *captured* legitimate
  signature (observable on-chain) to replay — not yet wired.
- **`--realauth-p256` needs a signer we control.** It deploys the target with
  its own p256 key and forges assertions against that key. It therefore probes a
  target's *implementation* (the challenge-binding property is a property of the
  code, key-independent — valid differential testing), not a specific live
  mainnet account whose credential we do not hold. A field version that flags a
  *live* account would need a *captured* legitimate assertion (observable
  on-chain) to replay — not yet wired.
- **`--realauth-p256` challenge check is substring-based.** The probe embeds
  `challenge = base64url(payload)` in a standard `webauthn.get` clientDataJSON. A
  wallet that binds the challenge by a different scheme than "clientDataJSON
  contains the base64url payload" could in principle read as bound while binding
  differently; the reached-and-held result on the `ecd990` wasm shows the
  standard scheme matches real passkey-kit, but exotic encoders are untested.
- **`--checkauth` is rejection-path only** for the classes it covers (it still
  does not construct a valid signature for the *blob* battery; `--replay` and
  `--realauth-p256` do that for the binding class). A `held` from `--checkauth`
  still means "rejected every forgery," not "authorization is fully correct."
- **Constructor reach.** The provers deploy the no-ctor, single-ed25519,
  single-secp256r1, single-Address, and full `Signer` (Ed25519/Secp256r1
  branches) shapes. A contract with a validating constructor or an exotic arg
  shape is still skipped — reported as `deploy-failed`, never as `held`.
