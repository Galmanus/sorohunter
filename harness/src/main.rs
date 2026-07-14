//! sorohunter fork-sim harness — generic auth prober + composition + upgrade.
//!
//! Every mode deploys the target into a local Env and probes it under empty
//! auth. Real contracts (Protocol 22+) carry a `__constructor` with args, so the
//! harness synthesizes constructor args and deploys with them; a deploy that
//! traps (unsynthesizable args, or a validating constructor) is caught, not
//! fatal. Nothing ever touches a live network.
//!
//! Single-fn mode:  <wasm> <out_json> <ctor_csv> "<fn>:<types>" [more fns...]
//! Chain mode:      --chain <wasm> <out_json> <ctor_csv> "<foothold>:<t>" "<target>:<t>"
//! Upgrade mode:    --upgrade <wasm> <attacker_wasm> <out_json> <ctor_csv> "<fn>:<t>"
//! (ctor_csv is the constructor's arg types, comma-separated, or "" for none.)

use std::panic::{catch_unwind, AssertUnwindSafe};

use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short,
    testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke},
    Address, Bytes, BytesN, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

/// Vendored passkey-kit (smart-wallet) types, copied structurally from the
/// target's published contract interface. Because `#[contracttype]` derives the
/// exact same Val/XDR encoding from identical definitions, values built here
/// decode byte-for-byte into the deployed wasm's own `Signer` / `Signatures`
/// types. This is what lets `--realauth` deploy the real mainnet wasm (via its
/// Ed25519 signer branch) and drive its genuine `__check_auth` — instead of
/// bouncing off `deploy-failed` because the generic synth path cannot build a
/// `Signer` enum.
mod passkey {
    use soroban_sdk::{contracttype, Address, Bytes, BytesN, Map, Vec};

    #[contracttype]
    #[derive(Clone)]
    pub struct SignerExpiration(pub Option<u32>);

    #[contracttype]
    #[derive(Clone)]
    pub struct SignerLimits(pub Option<Map<Address, Option<Vec<SignerKey>>>>);

    #[contracttype]
    #[derive(Clone)]
    pub struct Secp256r1Signature {
        pub authenticator_data: Bytes,
        pub client_data_json: Bytes,
        pub signature: BytesN<64>,
    }

    #[contracttype]
    #[derive(Clone)]
    pub struct Signatures(pub Map<SignerKey, Signature>);

    #[contracttype]
    #[derive(Clone)]
    pub enum SignerStorage {
        Persistent,
        Temporary,
    }

    #[contracttype]
    #[derive(Clone)]
    pub enum Signer {
        Policy(Address, SignerExpiration, SignerLimits, SignerStorage),
        Ed25519(BytesN<32>, SignerExpiration, SignerLimits, SignerStorage),
        Secp256r1(Bytes, BytesN<65>, SignerExpiration, SignerLimits, SignerStorage),
    }

    #[contracttype]
    #[derive(Clone)]
    pub enum SignerKey {
        Policy(Address),
        Ed25519(BytesN<32>),
        Secp256r1(Bytes),
    }

    #[contracttype]
    #[derive(Clone)]
    pub enum Signature {
        Policy,
        Ed25519(BytesN<64>),
        Secp256r1(Secp256r1Signature),
    }
}

fn synth(env: &Env, t: &str, attacker: Option<&Address>) -> Option<Val> {
    if t == "address" {
        return Some(match attacker {
            Some(a) => a.clone().into_val(env),
            None => Address::generate(env).into_val(env),
        });
    }
    if let Some(nn) = t.strip_prefix("bytes_n:") {
        let n: usize = nn.parse().ok()?;
        let buf = std::vec![0u8; n];
        return Some(Bytes::from_slice(env, &buf).into_val(env));
    }
    Some(match t {
        "u32" => 0u32.into_val(env),
        "i32" => 0i32.into_val(env),
        "u64" => 0u64.into_val(env),
        "i64" => 0i64.into_val(env),
        "u128" => 1u128.into_val(env),
        "i128" => 1i128.into_val(env),
        "bool" => false.into_val(env),
        "symbol" => Symbol::new(env, "x").into_val(env),
        "string" => SString::from_str(env, "x").into_val(env),
        "bytes" => Bytes::new(env).into_val(env),
        _ => return None,
    })
}

fn build_args(env: &Env, types: &[String], attacker: Option<&Address>) -> Option<SVec<Val>> {
    let mut args = SVec::new(env);
    for t in types {
        args.push_back(synth(env, t, attacker)?);
    }
    Some(args)
}

/// Deploy the wasm, synthesizing constructor args from `ctor_types`. Returns
/// None if the args can't be synthesized or the constructor traps.
fn try_deploy(env: &Env, wasm: &[u8], ctor_types: &[String]) -> Option<Address> {
    let args = build_args(env, ctor_types, None)?;
    let empty = ctor_types.is_empty();
    let wasm = wasm.to_vec();
    catch_unwind(AssertUnwindSafe(move || {
        if empty {
            env.register(wasm.as_slice(), ())
        } else {
            env.register(wasm.as_slice(), args)
        }
    }))
    .ok()
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn split_spec(spec: &str) -> (String, Vec<String>) {
    let (name, csv) = spec.split_once(':').unwrap_or((spec, ""));
    (name.to_string(), csv_types(csv))
}

fn csv_types(csv: &str) -> Vec<String> {
    if csv.is_empty() {
        Vec::new()
    } else {
        csv.split(',').map(|s| s.to_string()).collect()
    }
}

/// One-time setup functions: on a fresh-deploy fork they run once (there is no
/// prior state), which looks like a missing-auth breach but is a fresh-deploy
/// artifact, not a live finding. Treated specially in `probe`.
fn is_init_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("init") || matches!(n.as_str(), "setup" | "constructor" | "__constructor" | "bootstrap" | "boot")
}

/// Probe one function in a fresh Env so probes never contaminate each other.
fn probe(wasm: &[u8], ctor: &[String], name: &str, types: &[String]) -> (String, i64, String) {
    let env = Env::default();
    env.mock_all_auths(); // deploy freely
    let cid = match try_deploy(&env, wasm, ctor) {
        Some(c) => c,
        None => return ("deploy-failed".into(), 0, "could not deploy (constructor args unsynthesizable or deploy trapped)".into()),
    };

    let args = match build_args(&env, types, None) {
        Some(a) => a,
        None => return ("skipped".into(), 0, "unsynthesizable arg".into()),
    };

    env.set_auths(&[]); // nobody is authorized
    let before = env.events().all().events().len() as i64;
    let res = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, name), args);
    let after = env.events().all().events().len() as i64;
    let delta = after - before;

    match res {
        Err(_) => ("held".into(), delta, "aborted under empty auth".into()),
        Ok(_) if delta > 0 => {
            if is_init_name(name) {
                // A one-time initializer runs once on a fresh deploy — a
                // fresh-deploy artifact, not a live finding. Re-invoke under
                // empty auth: guarded (reverts) -> suppress; runs again -> a
                // real re-initialization bug (TA-03).
                let repeatable = match build_args(&env, types, None) {
                    Some(a) => env
                        .try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, name), a)
                        .is_ok(),
                    None => false,
                };
                if repeatable {
                    ("reinit".into(), delta, "callable more than once under empty auth — re-initialization (TA-03)".into())
                } else {
                    ("init-guarded".into(), delta, "one-time initializer, guarded on the second call — fresh-deploy artifact, not a live finding".into())
                }
            } else {
                (
                    "breach".into(),
                    delta,
                    "succeeded and emitted an event under empty auth — state change without a signature".into(),
                )
            }
        }
        Ok(_) => ("view".into(), delta, "succeeded, no event — read-only".into()),
    }
}

/// Execute a two-step privilege chain (TE-01 / SK-C01) in one fork.
fn probe_chain(
    wasm: &[u8],
    ctor: &[String],
    foothold: &str,
    f_types: &[String],
    target: &str,
    t_types: &[String],
) -> (String, String) {
    // 1. baseline: can the attacker call the target directly, with no foothold?
    {
        let env = Env::default();
        env.mock_all_auths();
        let cid = match try_deploy(&env, wasm, ctor) {
            Some(c) => c,
            None => return ("deploy-failed".into(), "could not deploy".into()),
        };
        let attacker = Address::generate(&env);
        let args = match build_args(&env, t_types, Some(&attacker)) {
            Some(a) => a,
            None => return ("skipped".into(), "unsynthesizable target arg".into()),
        };
        env.set_auths(&[]);
        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke { contract: &cid, fn_name: target, args: args.clone(), sub_invokes: &[] },
        }]);
        let r = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, target), args);
        if r.is_ok() {
            return (
                "direct".into(),
                "target is directly attacker-callable without a foothold (single-technique, not a chain)".into(),
            );
        }
    }

    // 2+3. foothold under empty auth, then target under the attacker's auth.
    let env = Env::default();
    env.mock_all_auths();
    let cid = match try_deploy(&env, wasm, ctor) {
        Some(c) => c,
        None => return ("deploy-failed".into(), "could not deploy".into()),
    };
    let attacker = Address::generate(&env);

    let f_args = match build_args(&env, f_types, Some(&attacker)) {
        Some(a) => a,
        None => return ("skipped".into(), "unsynthesizable foothold arg".into()),
    };
    env.set_auths(&[]);
    let fr = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, foothold), f_args);
    if fr.is_err() {
        return ("no-foothold".into(), "foothold aborts under empty auth (setter is gated)".into());
    }

    let t_args = match build_args(&env, t_types, Some(&attacker)) {
        Some(a) => a,
        None => return ("skipped".into(), "unsynthesizable target arg".into()),
    };
    let before = env.events().all().events().len() as i64;
    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke { contract: &cid, fn_name: target, args: t_args.clone(), sub_invokes: &[] },
    }]);
    let tr = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, target), t_args);
    let after = env.events().all().events().len() as i64;

    match tr {
        Ok(_) if after - before > 0 => (
            "chain".into(),
            format!(
                "foothold {}() under empty auth seized control, unlocking gated {}() for the attacker — composition, PoC is the executed sequence",
                foothold, target
            ),
        ),
        _ => ("held-after-foothold".into(), "foothold established but target still not reachable by the attacker".into()),
    }
}

/// Execute an unprotected-upgrade hijack (TP-01) in one fork.
fn probe_upgrade(
    target_wasm: &[u8],
    ctor: &[String],
    attacker_wasm: &[u8],
    upgrade_fn: &str,
    u_types: &[String],
) -> (String, String) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = match try_deploy(&env, target_wasm, ctor) {
        Some(c) => c,
        None => return ("deploy-failed".into(), "could not deploy".into()),
    };
    let attacker_hash = env.deployer().upload_contract_wasm(attacker_wasm);

    let mut args = SVec::new(&env);
    for t in u_types {
        let v = if t == "bytes_n:32" {
            attacker_hash.clone().into_val(&env)
        } else {
            match synth(&env, t, None) {
                Some(v) => v,
                None => return ("skipped".into(), "unsynthesizable upgrade arg".into()),
            }
        };
        args.push_back(v);
    }

    env.set_auths(&[]);
    let r = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, upgrade_fn), args);
    if r.is_err() {
        return ("held".into(), "upgrade aborts under empty auth (gated)".into());
    }

    let pwned = matches!(
        env.try_invoke_contract::<u32, soroban_sdk::Error>(&cid, &Symbol::new(&env, "pwned"), SVec::new(&env)),
        Ok(Ok(1337))
    );
    if pwned {
        (
            "hijack".into(),
            format!(
                "{}() swapped the contract code under empty auth — the attacker payload now executes (pwned=1337): OBJ-SEIZE, arbitrary control",
                upgrade_fn
            ),
        )
    } else {
        ("held-after".into(), "upgrade ran but the code was not swapped to the attacker payload".into())
    }
}

/// Deploy a smart-account wasm for the check_auth prover. Smart accounts
/// commonly take their initial signer in the constructor. We handle the shapes
/// that matter: no ctor, a single 32-byte ed25519 pubkey, a single 65-byte
/// secp256r1 (passkey) pubkey, or a single admin Address. Unknown shapes fall
/// back to the generic synth path.
fn checkauth_deploy(env: &Env, wasm: &[u8], ctor_csv: &str) -> Option<Address> {
    let wasm_owned = wasm.to_vec();
    let types = csv_types(ctor_csv);
    if types.is_empty() {
        let w = wasm_owned.clone();
        return catch_unwind(AssertUnwindSafe(move || env.register(w.as_slice(), ()))).ok();
    }
    if types.len() == 1 {
        let t = types[0].as_str();
        let w = wasm_owned.clone();
        let res = catch_unwind(AssertUnwindSafe(move || match t {
            "bytes_n:32" => {
                let pk = BytesN::from_array(env, &[0u8; 32]);
                env.register(w.as_slice(), (pk,))
            }
            "bytes_n:65" => {
                let pk = BytesN::from_array(env, &[0u8; 65]);
                env.register(w.as_slice(), (pk,))
            }
            "address" => {
                let a = Address::generate(env);
                env.register(w.as_slice(), (a,))
            }
            _ => panic!("unsupported ctor type"),
        }));
        if let Ok(cid) = res {
            return Some(cid);
        }
    }
    // Fallback: generic synth (may or may not satisfy the constructor).
    try_deploy(env, wasm, &types)
}

/// The check_auth prover. Deploys a `__check_auth`-exporting wasm and drives its
/// authorization logic directly via `try_invoke_contract_check_auth` — with NO
/// `mock_all_auths`, so the real `__check_auth` runs. Each hypothesis is a
/// signature that ANY correct account must reject (unauthenticated, forged, or
/// type-confused). A hypothesis that returns Ok(()) is an authorization bypass:
/// the account approved a request that carried no valid signature. Because a
/// correct account rejects every hypothesis, a clean run has zero false
/// positives by construction (proven by the good_account fixture).
fn probe_checkauth(wasm: &[u8], ctor_csv: &str) -> (String, Vec<(String, String, bool, String)>) {
    let env = Env::default();
    let cid = match checkauth_deploy(&env, wasm, ctor_csv) {
        Some(c) => c,
        None => {
            return (
                "deploy-failed".into(),
                std::vec![(
                    "-".into(),
                    "-".into(),
                    false,
                    "could not deploy (constructor shape unsupported or trapped)".into(),
                )],
            );
        }
    };

    // A fixed, non-zero signature payload (the message the account must have
    // authorized). Its exact value is irrelevant to the bypass test: every
    // hypothesis is a signature no honest signer produced for it.
    let mut pbuf = [0u8; 32];
    for (i, b) in pbuf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    let payload: BytesN<32> = BytesN::from_array(&env, &pbuf);

    // The authorization the account is asked to grant: a `transfer` on itself.
    let realistic_ctx: SVec<Context> = {
        let mut v = SVec::new(&env);
        v.push_back(Context::Contract(ContractContext {
            contract: cid.clone(),
            fn_name: symbol_short!("transfer"),
            args: SVec::new(&env),
        }));
        v
    };
    let empty_ctx: SVec<Context> = SVec::new(&env);

    // Signature hypotheses: each is something no honest signer over `payload`
    // would ever produce. A correct account rejects all of them.
    let hypotheses: Vec<(&str, Val)> = std::vec![
        ("void", ().into_val(&env)),
        ("empty-bytes", Bytes::new(&env).into_val(&env)),
        ("zero-64", BytesN::from_array(&env, &[0u8; 64]).into_val(&env)),
        ("garbage-64", BytesN::from_array(&env, &[0xABu8; 64]).into_val(&env)),
        ("int-0", 0_i32.into_val(&env)),
    ];

    let mut records: Vec<(String, String, bool, String)> = Vec::new();
    let mut any_bypass = false;

    for (ctx_name, ctx) in [("transfer-ctx", &realistic_ctx), ("empty-ctx", &empty_ctx)] {
        for (h_name, sig) in &hypotheses {
            let sig = *sig;
            let res = catch_unwind(AssertUnwindSafe(|| {
                env.try_invoke_contract_check_auth::<soroban_sdk::InvokeError>(
                    &cid, &payload, sig, ctx,
                )
            }));
            let (bypass, detail) = match res {
                Ok(Ok(())) => (
                    true,
                    "__check_auth returned Ok for an unauthenticated/forged signature — BYPASS".to_string(),
                ),
                Ok(Err(_)) => (false, "rejected (auth failed) — correct".to_string()),
                Err(_) => (false, "trapped (auth failed) — correct".to_string()),
            };
            if bypass {
                any_bypass = true;
            }
            records.push((h_name.to_string(), ctx_name.to_string(), bypass, detail));
        }
    }

    let verdict = if any_bypass { "auth-bypass".to_string() } else { "held".to_string() };
    (verdict, records)
}

/// The signature-binding (cross-payload replay) prover. This is the passkey
/// class: the target verifies a REAL signature — so `--checkauth`'s forgery
/// battery finds nothing — but may fail to bind that signature to the payload it
/// is actually authorizing. We hold the key here (it is our own fixture / any
/// account whose signer we control for the test), so we can do what `--checkauth`
/// cannot: produce ONE genuinely valid signature and then check two things a
/// forgery battery never can — (1) the positive path (a valid signature IS
/// accepted, closing that honest-limit) and (2) whether that same valid pair is
/// accepted for a DIFFERENT payload, which is the bypass.
///
/// Signature ABI probed: a 96-byte `msg[0..32] || sig[32..96]` blob (the
/// `unbound_account`/`bound_account` shape). A `held` verdict here means the
/// account bound the signature to the payload; `replay-bypass` means a valid
/// signature for payload A authorized payload B.
fn probe_replay(wasm: &[u8], ctor_csv: &str) -> (String, Vec<(String, bool, String)>) {
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic keypair (no RNG — reproducible across runs).
    let seed: [u8; 32] = [7u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();

    let env = Env::default();

    // Deploy with OUR pubkey as the signer. Only the single-`BytesN<32>`
    // constructor shape is meaningful for this prover; anything else is skipped.
    let types = csv_types(ctor_csv);
    let cid = {
        let w = wasm.to_vec();
        let pk = BytesN::from_array(&env, &pk_bytes);
        let env2 = env.clone();
        let res = catch_unwind(AssertUnwindSafe(move || {
            if types.len() == 1 && types[0] == "bytes_n:32" {
                env2.register(w.as_slice(), (pk,))
            } else {
                panic!("replay prover requires a single bytes_n:32 (ed25519 signer) constructor");
            }
        }));
        match res {
            Ok(c) => c,
            Err(_) => {
                return (
                    "deploy-failed".into(),
                    std::vec![(
                        "-".into(),
                        false,
                        "could not deploy with our signer (needs a single bytes_n:32 constructor)".into(),
                    )],
                );
            }
        }
    };

    let payload_a: [u8; 32] = [0x11; 32];
    let mut payload_b = [0x22u8; 32];
    payload_b[0] = 0x23; // distinct from A

    // A genuinely valid pair over payload A.
    let sig_a: [u8; 64] = sk.sign(&payload_a).to_bytes();
    let mut blob = [0u8; 96];
    blob[0..32].copy_from_slice(&payload_a);
    blob[32..96].copy_from_slice(&sig_a);

    let ctx: SVec<Context> = {
        let mut v = SVec::new(&env);
        v.push_back(Context::Contract(ContractContext {
            contract: cid.clone(),
            fn_name: symbol_short!("transfer"),
            args: SVec::new(&env),
        }));
        v
    };

    let call = |payload_bytes: &[u8; 32], sig_val: Val| -> Result<(), ()> {
        let p: BytesN<32> = BytesN::from_array(&env, payload_bytes);
        let r = catch_unwind(AssertUnwindSafe(|| {
            env.try_invoke_contract_check_auth::<soroban_sdk::InvokeError>(
                &cid, &p, sig_val, &ctx,
            )
        }));
        match r {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    };

    let blob_val = BytesN::from_array(&env, &blob).into_val(&env);
    let mut records: Vec<(String, bool, String)> = Vec::new();

    // (1) Positive path: the valid pair over A must be accepted for payload A.
    let positive_ok = call(&payload_a, blob_val).is_ok();
    records.push((
        "positive-path".into(),
        false,
        if positive_ok {
            "valid signature accepted for its own payload — baseline established".into()
        } else {
            "valid signature REJECTED for its own payload — ABI/signer mismatch, replay test inconclusive".into()
        },
    ));

    // Control: a valid-length but wrong signature over A must be rejected (proves
    // the account really verifies, so a later Ok is meaningful and not a stub).
    let mut forged = [0u8; 96];
    forged[0..32].copy_from_slice(&payload_a);
    forged[32..96].copy_from_slice(&[0xABu8; 64]);
    let forged_val = BytesN::from_array(&env, &forged).into_val(&env);
    let forgery_rejected = call(&payload_a, forged_val).is_err();
    records.push((
        "forgery-control".into(),
        false,
        if forgery_rejected {
            "forged signature over A rejected — account really verifies".into()
        } else {
            "forged signature over A ACCEPTED — account does not verify (see --checkauth)".into()
        },
    ));

    // (2) The bypass: the SAME valid pair, submitted for a different payload B.
    let blob_val2 = BytesN::from_array(&env, &blob).into_val(&env);
    let replay_ok = call(&payload_b, blob_val2).is_ok();
    records.push((
        "cross-payload-replay".into(),
        replay_ok,
        if replay_ok {
            "valid signature for payload A authorized DIFFERENT payload B — signature not bound to payload — BYPASS".into()
        } else {
            "valid pair for A rejected for B — signature bound to payload — correct".into()
        },
    ));

    let verdict = if !positive_ok {
        "inconclusive"
    } else if replay_ok {
        "replay-bypass"
    } else {
        "held"
    };
    (verdict.to_string(), records)
}

/// Real-target auth prover. Unlike `--replay` (which only understands the
/// synthetic `unbound_account` 96-byte blob ABI), this deploys the ACTUAL
/// passkey-kit smart-wallet wasm using its Ed25519 signer branch — a signer
/// whose key we hold — and drives the genuine `__check_auth` with a real
/// ed25519 signature wrapped in the target's own `Signatures(Map<SignerKey,
/// Signature>)` type. No mock. Three probes on the live authorization logic:
///   (1) positive: a genuine signature over payload A is accepted for A;
///   (2) forgery-control: a garbage 64-byte "signature" over A is rejected
///       (proves the account really verifies — a later Ok is meaningful);
///   (3) cross-payload replay: the genuine A-signature is presented for a
///       DIFFERENT payload B — accepted = binding bug, rejected = held.
/// Verdict `held` here is a real result against the real wasm, not a fixture.
fn probe_realauth(wasm: &[u8]) -> (String, Vec<(String, bool, String)>) {
    use ed25519_dalek::{Signer as _, SigningKey};
    use passkey::{Signature, Signatures, Signer, SignerExpiration, SignerKey, SignerLimits, SignerStorage};
    use soroban_sdk::Map;

    let env = Env::default();

    // A signer we control.
    let seed: [u8; 32] = [7u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let pk: BytesN<32> = BytesN::from_array(&env, &pk_bytes);

    // Deploy the REAL wasm with our Ed25519 signer, no limits, no expiration.
    let signer = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(None),
        SignerLimits(None),
        SignerStorage::Persistent,
    );
    let w = wasm.to_vec();
    let env2 = env.clone();
    let deploy = catch_unwind(AssertUnwindSafe(move || env2.register(w.as_slice(), (signer,))));
    let cid = match deploy {
        Ok(c) => c,
        Err(_) => {
            return (
                "deploy-failed".into(),
                std::vec![("-".into(), false, "could not deploy real wasm with Ed25519 signer".into())],
            );
        }
    };

    let ctx: SVec<Context> = {
        let mut v = SVec::new(&env);
        v.push_back(Context::Contract(ContractContext {
            contract: cid.clone(),
            fn_name: symbol_short!("transfer"),
            args: SVec::new(&env),
        }));
        v
    };

    // Build a `Signatures` map carrying one Ed25519 signature for our key.
    let make_sigs = |sig64: [u8; 64]| -> Val {
        let mut m: Map<SignerKey, Signature> = Map::new(&env);
        m.set(
            SignerKey::Ed25519(pk.clone()),
            Signature::Ed25519(BytesN::from_array(&env, &sig64)),
        );
        Signatures(m).into_val(&env)
    };

    let call = |payload_bytes: &[u8; 32], sig_val: Val| -> Result<(), ()> {
        let p: BytesN<32> = BytesN::from_array(&env, payload_bytes);
        let r = catch_unwind(AssertUnwindSafe(|| {
            env.try_invoke_contract_check_auth::<soroban_sdk::InvokeError>(&cid, &p, sig_val, &ctx)
        }));
        match r {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    };

    let payload_a: [u8; 32] = [0x11; 32];
    let mut payload_b = [0x22u8; 32];
    payload_b[0] = 0x23;

    let sig_a: [u8; 64] = sk.sign(&payload_a).to_bytes();

    let mut records: Vec<(String, bool, String)> = Vec::new();

    // (1) positive path
    let positive_ok = call(&payload_a, make_sigs(sig_a)).is_ok();
    records.push((
        "positive-path".into(),
        false,
        if positive_ok {
            "genuine ed25519 signature accepted for its own payload — real __check_auth reached and baseline established".into()
        } else {
            "genuine signature REJECTED for its own payload — deploy/ABI mismatch, test inconclusive".into()
        },
    ));

    // (2) forgery control
    let forgery_rejected = call(&payload_a, make_sigs([0xABu8; 64])).is_err();
    records.push((
        "forgery-control".into(),
        false,
        if forgery_rejected {
            "forged signature over A rejected — real account verifies cryptographically".into()
        } else {
            "forged signature over A ACCEPTED — account does not verify".into()
        },
    ));

    // (3) cross-payload replay
    let replay_ok = call(&payload_b, make_sigs(sig_a)).is_ok();
    records.push((
        "cross-payload-replay".into(),
        replay_ok,
        if replay_ok {
            "genuine signature for payload A authorized DIFFERENT payload B — signature not bound — BYPASS".into()
        } else {
            "genuine A-signature rejected for B — signature bound to payload — held".into()
        },
    ));

    let verdict = if !positive_ok {
        "inconclusive"
    } else if replay_ok {
        "replay-bypass"
    } else {
        "held"
    };
    (verdict.to_string(), records)
}

/// Real-target auth prover for the SECP256R1 / WebAuthn (passkey) signer branch.
/// This is the branch that actually matters: `--realauth` (ed25519) proves the
/// machinery lands, but a correct `ed25519_verify(pk, payload, sig)` binds the
/// signature to the payload by construction, so its cross-payload probe is
/// nearly vacuous. The real binding bug (swig-wallet #143) lives here — a wallet
/// that verifies the ECDSA assertion but never checks the signed
/// `clientDataJSON.challenge` equals the payload it is authorizing.
///
/// We hold a p256 key, deploy the target via its `Signer::Secp256r1` branch, and
/// forge a genuine WebAuthn assertion (authenticatorData + clientDataJSON +
/// ECDSA-secp256r1 signature over `sha256(ad || sha256(cdj))`). Three probes:
///   (1) positive: a genuine assertion whose challenge encodes payload A is
///       accepted for A — establishes the real `__check_auth` was reached;
///   (2) forgery-control: the same assertion with a garbage signature is
///       rejected — proves the account cryptographically verifies;
///   (3) cross-payload replay: the genuine A-assertion (challenge still encodes
///       A) is presented to authorize a DIFFERENT payload B. A wallet that binds
///       the challenge rejects it; one that does not authorizes B — BYPASS.
fn probe_realauth_p256(wasm: &[u8]) -> (String, Vec<(String, bool, String)>) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as P256Sig, SigningKey};
    use passkey::{
        Secp256r1Signature, Signature, Signatures, Signer, SignerExpiration, SignerKey,
        SignerLimits, SignerStorage,
    };
    use sha2::{Digest, Sha256};
    use soroban_sdk::Map;

    let env = Env::default();

    // A p256 signer we control (fixed nonzero scalar < curve order).
    let scalar = [0x11u8; 32];
    let sk = SigningKey::from_slice(&scalar).expect("valid p256 scalar");
    let vk = sk.verifying_key();
    let ep = vk.to_encoded_point(false); // uncompressed 0x04 || X || Y
    let pk65: BytesN<65> = BytesN::from_array(&env, ep.as_bytes().try_into().expect("65-byte key"));

    let key_id = Bytes::from_slice(&env, b"kid1");
    let signer = Signer::Secp256r1(
        key_id.clone(),
        pk65.clone(),
        SignerExpiration(None),
        SignerLimits(None),
        SignerStorage::Persistent,
    );
    let w = wasm.to_vec();
    let env2 = env.clone();
    let deploy = catch_unwind(AssertUnwindSafe(move || env2.register(w.as_slice(), (signer,))));
    let cid = match deploy {
        Ok(c) => c,
        Err(_) => {
            return (
                "deploy-failed".into(),
                std::vec![("-".into(), false, "could not deploy real wasm with Secp256r1 signer".into())],
            );
        }
    };

    let ctx: SVec<Context> = {
        let mut v = SVec::new(&env);
        v.push_back(Context::Contract(ContractContext {
            contract: cid.clone(),
            fn_name: symbol_short!("transfer"),
            args: SVec::new(&env),
        }));
        v
    };

    // authenticatorData: 32-byte rpIdHash || flags(UP|UV=0x05) || 4-byte counter.
    let mut ad = [0u8; 37];
    ad[32] = 0x05;
    ad[36] = 0x01;
    let ad_bytes = Bytes::from_array(&env, &ad);

    // Build a genuine WebAuthn assertion whose challenge encodes `payload`.
    let make_assertion = |payload: &[u8; 32]| -> (Bytes, [u8; 64]) {
        let chal = URL_SAFE_NO_PAD.encode(payload);
        let cdj = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://x\",\"crossOrigin\":false}}",
            chal
        );
        let cdj_bytes = Bytes::from_slice(&env, cdj.as_bytes());
        // digest = sha256(authenticatorData || sha256(clientDataJSON))
        let cdj_hash = Sha256::digest(cdj.as_bytes());
        let mut pre = ad.to_vec();
        pre.extend_from_slice(&cdj_hash);
        let digest = Sha256::digest(&pre);
        let sig: P256Sig = sk.sign_prehash(&digest).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig); // low-S, required by host
        let sig_arr: [u8; 64] = sig.to_bytes().into();
        (cdj_bytes, sig_arr)
    };

    // Wrap an assertion in the target's own Signatures(Map<SignerKey,Signature>).
    let make_sigs = |cdj: &Bytes, sig64: [u8; 64]| -> Val {
        let mut m: Map<SignerKey, Signature> = Map::new(&env);
        m.set(
            SignerKey::Secp256r1(key_id.clone()),
            Signature::Secp256r1(Secp256r1Signature {
                authenticator_data: ad_bytes.clone(),
                client_data_json: cdj.clone(),
                signature: BytesN::from_array(&env, &sig64),
            }),
        );
        Signatures(m).into_val(&env)
    };

    let call = |payload: &[u8; 32], sig_val: Val| -> Result<(), ()> {
        let p: BytesN<32> = BytesN::from_array(&env, payload);
        let r = catch_unwind(AssertUnwindSafe(|| {
            env.try_invoke_contract_check_auth::<soroban_sdk::InvokeError>(&cid, &p, sig_val, &ctx)
        }));
        match r {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    };

    let payload_a: [u8; 32] = [0x11; 32];
    let mut payload_b = [0x22u8; 32];
    payload_b[0] = 0x23;

    let (cdj_a, sig_a) = make_assertion(&payload_a);

    let mut records: Vec<(String, bool, String)> = Vec::new();

    // (1) positive path
    let positive_ok = call(&payload_a, make_sigs(&cdj_a, sig_a)).is_ok();
    records.push((
        "positive-path".into(),
        false,
        if positive_ok {
            "genuine secp256r1 WebAuthn assertion accepted for its own payload — real __check_auth reached, baseline established".into()
        } else {
            "genuine assertion REJECTED for its own payload — deploy/ABI/digest mismatch, test inconclusive".into()
        },
    ));

    // (2) forgery control
    let forgery_rejected = call(&payload_a, make_sigs(&cdj_a, [0xABu8; 64])).is_err();
    records.push((
        "forgery-control".into(),
        false,
        if forgery_rejected {
            "garbage signature rejected — real account verifies the ECDSA assertion".into()
        } else {
            "garbage signature ACCEPTED — account does not verify (see --checkauth)".into()
        },
    ));

    // (3) cross-payload replay: A's genuine assertion presented for payload B.
    let replay_ok = call(&payload_b, make_sigs(&cdj_a, sig_a)).is_ok();
    records.push((
        "cross-payload-replay".into(),
        replay_ok,
        if replay_ok {
            "assertion whose challenge encodes payload A authorized DIFFERENT payload B — challenge not bound — BYPASS".into()
        } else {
            "A-assertion rejected for B — challenge bound to payload — held".into()
        },
    ));

    let verdict = if !positive_ok {
        "inconclusive"
    } else if replay_ok {
        "replay-bypass"
    } else {
        "held"
    };
    (verdict.to_string(), records)
}

/// Unrestricted-`transfer_from` prover: the third-party allowance-drain class
/// (Scout's `unrestricted-transfer-from`, but as an EXECUTED value loss, not a
/// static pattern). sorohunter's economic detectors watch the contract's and the
/// attacker's balances; this class moves a VICTIM's approved balance, which none
/// of them watch — the exact gap. Here the prover sets up the victim state and
/// proves it: mint a victim, have the victim grant the contract a standing
/// allowance (a legitimate one-time approve), then call the target fn under EMPTY
/// auth (no victim signature). If the victim's real token balance drops, the
/// contract spent someone else's allowance on an unauthenticated call — an
/// executed `transfer_from` bypass. A contract that guards with `from.require_auth()`
/// reverts under empty auth and is `held`.
///
/// v1 convention: the target has a single-`Address` (token) constructor and a fn
/// `<name>(from: Address, amount: i128)`. Other shapes are roadmap.
fn probe_allowance(wasm: &[u8], fn_name: &str) -> (String, Vec<(String, bool, String)>) {
    use soroban_sdk::token::{StellarAssetClient, TokenClient};

    let env = Env::default();
    env.mock_all_auths(); // setup phase: mint + approve run with authorization

    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();

    // Deploy the target with its (token) constructor.
    let w = wasm.to_vec();
    let token_for_deploy = token.clone();
    let env2 = env.clone();
    let target = match catch_unwind(AssertUnwindSafe(move || {
        env2.register(w.as_slice(), (token_for_deploy,))
    })) {
        Ok(c) => c,
        Err(_) => {
            return (
                "deploy-failed".into(),
                std::vec![("-".into(), false, "could not deploy target with a single-Address (token) constructor".into())],
            );
        }
    };

    let victim = Address::generate(&env);
    let amount: i128 = 1000;
    StellarAssetClient::new(&env, &token).mint(&victim, &amount);
    // The victim legitimately approves the contract as a spender (one-time).
    let exp = env.ledger().sequence() + 10_000;
    TokenClient::new(&env, &token).approve(&victim, &target, &amount, &exp);

    let before = TokenClient::new(&env, &token).balance(&victim);

    // PROBE: invoke the fn under EMPTY auth — the victim signs nothing now.
    env.set_auths(&[]);
    let mut call_args: SVec<Val> = SVec::new(&env);
    call_args.push_back(victim.clone().into_val(&env)); // from = victim
    call_args.push_back(amount.into_val(&env)); // amount = full allowance
    let name = Symbol::new(&env, fn_name);
    let tgt = target.clone();
    let env3 = env.clone();
    let reverted = catch_unwind(AssertUnwindSafe(move || {
        env3.invoke_contract::<Val>(&tgt, &name, call_args);
    }))
    .is_err();

    let after = TokenClient::new(&env, &token).balance(&victim);
    let drained = after < before;

    let mut records: Vec<(String, bool, String)> = Vec::new();
    records.push((
        "victim-approved".into(),
        false,
        format!(
            "victim granted the contract a standing allowance of {} and holds {} before the probe",
            amount, before
        ),
    ));
    records.push((
        "empty-auth-pull".into(),
        drained,
        if drained {
            format!(
                "a call to `{}` under EMPTY auth moved {} of the victim's tokens (balance {}->{}) with NO victim signature — unauthorized third-party transfer_from",
                fn_name,
                before - after,
                before,
                after
            )
        } else if reverted {
            format!("`{}` reverted under empty auth (the victim's require_auth is unsatisfied) — held", fn_name)
        } else {
            format!("`{}` ran under empty auth but the victim's balance is unchanged ({}) — no third-party drain", fn_name, after)
        },
    ));

    let verdict = if drained { "allowance-drain" } else { "held" };
    (verdict.to_string(), records)
}

/// P2/P3: economic multi-call fuzzer. Sets up a real token, a funded target, and
/// an attacker; fuzzes SEQUENCES of the target's economic functions with the
/// attacker as the (legitimately authorized) actor; and reports any sequence that
/// leaves the attacker with MORE tokens than they started with — net profit
/// drained from the protocol. This finds economic bugs that (a) auth-scan misses
/// (every call is authorized) and (b) single-shot misses (the drain needs a
/// specific multi-call sequence). The invariant is composition-level solvency,
/// exactly what per-contract formal verification does not model.
///
/// v1 convention: economic fns are `<name>(from: Address, amount: i128)`; the
/// target has a single-Address (token) constructor. Amount is fixed so the fn
/// SEQUENCE is the only variable (the bug is the sequence, not the value).
struct ERng(u64);
impl ERng {
    fn next(&mut self, n: usize) -> usize {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x;
        if n == 0 { 0 } else { (x % n as u64) as usize }
    }
}

fn econ_replay(target_wasm: &[u8], fns: &[String], seq: &[usize], amount: i128) -> Option<(i128, usize)> {
    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    let r = catch_unwind(AssertUnwindSafe(|| {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let token = sac.address();
        let w = target_wasm.to_vec();
        let tkc = token.clone();
        let target = env.register(w.as_slice(), (tkc,));
        let attacker = Address::generate(&env);
        let start: i128 = 1_000;
        let reserve: i128 = 1_000_000;
        StellarAssetClient::new(&env, &token).mint(&attacker, &start);
        StellarAssetClient::new(&env, &token).mint(&target, &reserve);
        let exp = env.ledger().sequence() + 100_000;
        TokenClient::new(&env, &token).approve(&attacker, &target, &(start * 100), &exp);
        let bal = |e: &Env, t: &Address, a: &Address| -> i128 { TokenClient::new(e, t).balance(a) };
        let start_bal = bal(&env, &token, &attacker);
        let mut best: i128 = 0;
        let mut best_step = 0usize;
        for (step, &fi) in seq.iter().enumerate() {
            let mut args: SVec<Val> = SVec::new(&env);
            args.push_back(attacker.clone().into_val(&env));
            args.push_back(amount.into_val(&env));
            let _ = catch_unwind(AssertUnwindSafe(|| {
                env.invoke_contract::<Val>(&target, &Symbol::new(&env, &fns[fi]), args);
            }));
            let profit = bal(&env, &token, &attacker) - start_bal;
            if profit > best { best = profit; best_step = step + 1; }
        }
        (best, best_step)
    }));
    r.ok()
}

fn probe_econ(target_wasm: &[u8], fns: &[String]) -> (String, Vec<(String, bool, String)>) {
    let amount: i128 = 100;
    let max_seq = 5usize;
    let rounds = 400u32;
    let mut corpus: Vec<Vec<usize>> = vec![Vec::new()];
    let mut rng = ERng(0x2545f4914f6cdd1d);
    let mut hit: Option<(Vec<usize>, i128)> = None;
    for _ in 0..rounds {
        let base = corpus[rng.next(corpus.len())].clone();
        let mut seq = base;
        if seq.len() < max_seq { seq.push(rng.next(fns.len())); }
        else if !seq.is_empty() { let l = seq.len() - 1; seq[l] = rng.next(fns.len()); }
        if let Some((profit, _step)) = econ_replay(target_wasm, fns, &seq, amount) {
            if profit > 0 { hit = Some((seq.clone(), profit)); break; }
            // crude coverage: keep any sequence that ran (grows the corpus)
            corpus.push(seq);
            if corpus.len() > 200 { corpus.remove(1); }
        }
    }
    let mut records: Vec<(String, bool, String)> = Vec::new();
    if let Some((seq, profit)) = hit {
        // shrink
        let mut cur = seq;
        let mut i = 0;
        while i < cur.len() {
            let mut trial = cur.clone(); trial.remove(i);
            match econ_replay(target_wasm, fns, &trial, amount) {
                Some((p, _)) if p > 0 => cur = trial,
                _ => i += 1,
            }
        }
        let path = cur.iter().map(|&i| fns[i].clone()).collect::<Vec<_>>().join(" -> ");
        records.push(("net-profit".into(), true, format!(
            "attacker ended +{} tokens over start via the {}-call sequence [{}] (amount {} each) — value drained from the protocol; every call authorized, no single call is a finding",
            profit, cur.len(), path, amount)));
        ("econ-drain".to_string(), records)
    } else {
        records.push(("net-profit".into(), false, "no sequence left the attacker in profit — solvency held under fuzzing".into()));
        ("held".to_string(), records)
    }
}

/// EMPIRICAL PROBE (not a shipped detector): does Soroban's auth model permit a
/// confused-deputy? victim.forward(attacker) -> attacker.poke() -> victim.set_flag()
/// where set_flag is gated by the victim's OWN (current-contract) auth. If the flag
/// is set, a contract's authority propagates through a re-entrant sub-call it did
/// not directly make (TD-02 is real). If it reverts, Soroban blocks it (a TD-02
/// detector would be theater). Returns whether the attack succeeded.
fn probe_deputy(victim_wasm: &[u8], attacker_wasm: &[u8]) -> (String, Vec<(String, bool, String)>) {
    let env = Env::default();
    let vw = victim_wasm.to_vec();
    let ev = env.clone();
    let victim = ev.register(vw.as_slice(), ());
    let aw = attacker_wasm.to_vec();
    let vic = victim.clone();
    let ea = env.clone();
    let attacker = ea.register(aw.as_slice(), (vic,));

    let call_forward = |mock: bool| -> bool {
        let e = Env::default();
        let v = e.register(victim_wasm.to_vec().as_slice(), ());
        let a = e.register(attacker_wasm.to_vec().as_slice(), (v.clone(),));
        if mock {
            e.mock_all_auths();
        } else {
            e.set_auths(&[]);
        }
        let mut fargs: SVec<Val> = SVec::new(&e);
        fargs.push_back(a.into_val(&e));
        let _ = catch_unwind(AssertUnwindSafe(|| {
            e.invoke_contract::<Val>(&v, &Symbol::new(&e, "forward"), fargs);
        }));
        e.mock_all_auths();
        e.invoke_contract::<bool>(&v, &Symbol::new(&e, "flag"), SVec::new(&e))
    };
    let _ = (&victim, &attacker); // deployed above only to validate the wasm loads

    let with_auth = call_forward(true); // control: does the mechanism work at all?
    let empty_auth = call_forward(false); // attack: attacker has no victim authority

    let mut records: Vec<(String, bool, String)> = Vec::new();
    records.push((
        "mechanism-control".into(),
        false,
        format!("under mock_all_auths the reentrant chain set the flag = {} (proves the call path works when authorized)", with_auth),
    ));
    records.push((
        "confused-deputy-attack".into(),
        empty_auth,
        if empty_auth {
            "REAL: with NO victim authorization the reentrant set_flag still succeeded — the victim's authority propagated. TD-02 is exploitable; ship the detector.".into()
        } else {
            "BLOCKED: with no victim authorization the reentrant set_flag reverted. The victim's contract authority does NOT propagate to a re-entrant sub-call it did not directly authorize. Soroban's per-subtree auth prevents the EVM/Solana-style confused-deputy — a TD-02 detector would be theater.".into()
        },
    ));
    let verdict = if empty_auth { "deputy-exploitable" } else { "deputy-blocked" };
    (verdict.to_string(), records)
}

/// Auth-arg scope-mismatch prover (TA-04). A payment fn that authorizes the payer
/// with `require_auth_for_args` scoped too narrowly (omitting the recipient /
/// amount) lets one authorization be replayed to any recipient. The prover mocks
/// an authorization for the payer scoped to ONLY the payer address, then calls
/// `pay(payer, attacker, amount)`. If the attacker's balance moves, the narrow
/// scope authorized a redirected payment — an executed scope-mismatch bypass. A
/// contract that binds the full args (`require_auth`) reverts under that mock.
///
/// v1 convention: `pay(from: Address, to: Address, amount: i128)` +
/// `mint(to, amount)` + `balance(id) -> i128`.
fn probe_scope(wasm: &[u8]) -> (String, Vec<(String, bool, String)>) {
    let env = Env::default();
    env.mock_all_auths();

    let w = wasm.to_vec();
    let env_a = env.clone();
    let cid = match catch_unwind(AssertUnwindSafe(move || env_a.register(w.as_slice(), ()))) {
        Ok(c) => c,
        Err(_) => return ("deploy-failed".into(), std::vec![("-".into(), false, "deploy failed (expects no-arg constructor)".into())]),
    };

    let victim = Address::generate(&env);
    let attacker = Address::generate(&env);
    let amount: i128 = 500;

    // seed the victim's balance (setup, freely authorized)
    let mut margs: SVec<Val> = SVec::new(&env);
    margs.push_back(victim.clone().into_val(&env));
    margs.push_back(1000i128.into_val(&env));
    if catch_unwind(AssertUnwindSafe(|| { env.invoke_contract::<Val>(&cid, &Symbol::new(&env, "mint"), margs); })).is_err() {
        return ("inconclusive".into(), std::vec![("mint".into(), false, "no mint(Address,i128) — cannot set up the scope test".into())]);
    }

    // Authorization the payer produces, scoped to ONLY [victim] — the exact
    // (buggy) scope a TA-04 contract asks for. It does NOT name the recipient.
    let mut scope: SVec<Val> = SVec::new(&env);
    scope.push_back(victim.clone().into_val(&env));
    env.mock_auths(&[MockAuth {
        address: &victim,
        invoke: &MockAuthInvoke { contract: &cid, fn_name: "pay", args: scope.clone(), sub_invokes: &[] },
    }]);

    // Attacker redirects the payment to themselves under that narrow auth.
    let mut pargs: SVec<Val> = SVec::new(&env);
    pargs.push_back(victim.clone().into_val(&env));
    pargs.push_back(attacker.clone().into_val(&env));
    pargs.push_back(amount.into_val(&env));
    let paid = catch_unwind(AssertUnwindSafe(|| { env.invoke_contract::<Val>(&cid, &Symbol::new(&env, "pay"), pargs); })).is_ok();

    // Confirm value actually moved to the attacker (not just that the call ran).
    env.mock_all_auths();
    let mut bargs: SVec<Val> = SVec::new(&env);
    bargs.push_back(attacker.clone().into_val(&env));
    let atk_bal: i128 = env.invoke_contract(&cid, &Symbol::new(&env, "balance"), bargs);
    let moved = paid && atk_bal >= amount;

    let mut records: Vec<(String, bool, String)> = Vec::new();
    records.push((
        "narrow-auth".into(),
        false,
        "payer authorized scoped to [payer] only (recipient/amount omitted from the auth scope)".into(),
    ));
    records.push((
        "redirect-under-scope".into(),
        moved,
        if moved {
            format!("pay(payer, attacker, {}) executed under the [payer]-only auth — {} moved to an unnamed recipient; the authorization did not bind (to, amount)", amount, atk_bal)
        } else {
            "the redirected payment reverted — the authorization binds the full (from, to, amount), held".into()
        },
    ));
    let verdict = if moved { "scope-mismatch" } else { "held" };
    (verdict.to_string(), records)
}

/// Fee-on-transfer accounting prover (Coinspect Tricorn TRI-005 class). A vault
/// that credits the `amount` argument instead of its measured balance delta
/// over-credits against a deflationary token, going insolvent. Static linters
/// (Scout/OZ) do not catch this — it is a dynamic accounting invariant. The
/// prover deploys a real fee-on-transfer token and the target vault, deposits
/// through it, and compares the vault's internal credit to the tokens it actually
/// holds. credit > real balance = over-credit = the bug.
///
/// v1 convention: target has a single-Address (token) constructor and a
/// `deposit(from: Address, amount: i128)` + `credit(id: Address) -> i128`.
fn probe_feetoken(vault_wasm: &[u8], fee_token_wasm: &[u8]) -> (String, Vec<(String, bool, String)>) {
    let env = Env::default();
    env.mock_all_auths();

    // fee-on-transfer token, 10% skim.
    let ftw = fee_token_wasm.to_vec();
    let env_a = env.clone();
    let token = match catch_unwind(AssertUnwindSafe(move || env_a.register(ftw.as_slice(), (1000u32,)))) {
        Ok(c) => c,
        Err(_) => return ("deploy-failed".into(), std::vec![("-".into(), false, "fee_token deploy failed".into())]),
    };
    let vw = vault_wasm.to_vec();
    let token_c = token.clone();
    let env_b = env.clone();
    let vault = match catch_unwind(AssertUnwindSafe(move || env_b.register(vw.as_slice(), (token_c,)))) {
        Ok(c) => c,
        Err(_) => return ("deploy-failed".into(), std::vec![("-".into(), false, "vault deploy failed (needs single-Address token constructor)".into())]),
    };

    let attacker = Address::generate(&env);
    let amount: i128 = 1000;
    // mint the attacker fee-token balance
    let mut margs: SVec<Val> = SVec::new(&env);
    margs.push_back(attacker.clone().into_val(&env));
    margs.push_back(amount.into_val(&env));
    let _ = catch_unwind(AssertUnwindSafe(|| {
        env.invoke_contract::<Val>(&token, &Symbol::new(&env, "mint"), margs);
    }));

    // deposit through the vault
    let mut dargs: SVec<Val> = SVec::new(&env);
    dargs.push_back(attacker.clone().into_val(&env));
    dargs.push_back(amount.into_val(&env));
    let deposited = catch_unwind(AssertUnwindSafe(|| {
        env.invoke_contract::<Val>(&vault, &Symbol::new(&env, "deposit"), dargs);
    }))
    .is_ok();
    if !deposited {
        return ("inconclusive".into(), std::vec![("deposit".into(), false, "deposit reverted — ABI mismatch or guarded path".into())]);
    }

    // internal credit vs real tokens held
    let mut cargs: SVec<Val> = SVec::new(&env);
    cargs.push_back(attacker.clone().into_val(&env));
    let credit: i128 = env.invoke_contract(&vault, &Symbol::new(&env, "credit"), cargs);
    let mut bargs: SVec<Val> = SVec::new(&env);
    bargs.push_back(vault.clone().into_val(&env));
    let held: i128 = env.invoke_contract(&token, &Symbol::new(&env, "balance"), bargs);

    let over = credit - held;
    let mut records: Vec<(String, bool, String)> = Vec::new();
    records.push((
        "deposit".into(),
        false,
        format!("attacker deposited {} of a 10% fee-on-transfer token; the vault actually received {}", amount, held),
    ));
    records.push((
        "over-credit".into(),
        over > 0,
        if over > 0 {
            format!("vault credited {} but holds only {} — over-credited by {}; internal accounting exceeds real balance, the vault is insolvent (fee-on-transfer accounting bug)", credit, held, over)
        } else {
            format!("vault credited {} == tokens received {} — accounting matches real receipt, held", credit, held)
        },
    ));
    let verdict = if over > 0 { "fee-overcredit" } else { "held" };
    (verdict.to_string(), records)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(|s| s.as_str()) == Some("--econ") {
        // --econ <wasm> <out_json> <fn1,fn2,...>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let fns: Vec<String> = args.get(3).map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_else(|| std::vec!["deposit".into(), "withdraw".into()]);
        let (verdict, records) = probe_econ(&wasm, &fns);
        let recs: Vec<String> = records.iter().map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d))).collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(out_path, format!("{{\"mode\":\"econ\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}", verdict, bypasses, recs.join(","))).expect("write out");
        println!("[harness --econ] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--deputy") {
        let vw = std::fs::read(&args[1]).expect("read victim wasm");
        let aw = std::fs::read(&args[2]).expect("read attacker wasm");
        let (verdict, records) = probe_deputy(&vw, &aw);
        for (h, b, d) in &records {
            println!("[--deputy] {} bypass={} :: {}", h, b, d);
        }
        println!("[--deputy] verdict={}", verdict);
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--scope") {
        // --scope <wasm> <out_json>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let (verdict, records) = probe_scope(&wasm);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d)))
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"scope\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --scope] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--feetoken") {
        // --feetoken <vault_wasm> <out_json> <fee_token_wasm>
        let vault = std::fs::read(&args[1]).expect("read vault wasm");
        let out_path = &args[2];
        let ft = std::fs::read(&args[3]).expect("read fee_token wasm");
        let (verdict, records) = probe_feetoken(&vault, &ft);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d)))
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"feetoken\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --feetoken] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--allowance") {
        // --allowance <wasm> <out_json> <fn:types>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let spec = args.get(3).map(|s| s.as_str()).unwrap_or("pull");
        let (fn_name, _types) = split_spec(spec);
        let (verdict, records) = probe_allowance(&wasm, &fn_name);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d)))
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"allowance\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --allowance] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--realauth-p256") {
        // --realauth-p256 <wasm> <out_json>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let (verdict, records) = probe_realauth_p256(&wasm);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d)))
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"realauth-p256\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --realauth-p256] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--realauth") {
        // --realauth <wasm> <out_json>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let (verdict, records) = probe_realauth(&wasm);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| format!("{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}", esc(h), b, esc(d)))
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"realauth\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --realauth] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--replay") {
        // --replay <wasm> <out_json> <ctor_csv>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let ctor_csv = args.get(3).map(|s| s.as_str()).unwrap_or("");
        let (verdict, records) = probe_replay(&wasm, ctor_csv);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, b, d)| {
                format!(
                    "{{\"probe\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}",
                    esc(h), b, esc(d)
                )
            })
            .collect();
        let bypasses = records.iter().filter(|(_, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"replay\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict, bypasses, recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --replay] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--checkauth") {
        // --checkauth <wasm> <out_json> <ctor_csv>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let ctor_csv = args.get(3).map(|s| s.as_str()).unwrap_or("");
        let (verdict, records) = probe_checkauth(&wasm, ctor_csv);
        let recs: Vec<String> = records
            .iter()
            .map(|(h, c, b, d)| {
                format!(
                    "{{\"hypothesis\":\"{}\",\"context\":\"{}\",\"bypass\":{},\"detail\":\"{}\"}}",
                    esc(h), esc(c), b, esc(d)
                )
            })
            .collect();
        let bypasses = records.iter().filter(|(_, _, b, _)| *b).count();
        std::fs::write(
            out_path,
            format!(
                "{{\"mode\":\"checkauth\",\"verdict\":\"{}\",\"bypasses\":{},\"probes\":[{}]}}",
                verdict,
                bypasses,
                recs.join(",")
            ),
        )
        .expect("write out");
        println!("[harness --checkauth] verdict={} bypasses={}/{}", verdict, bypasses, records.len());
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--upgrade") {
        // --upgrade <target> <attacker> <out> <ctor_csv> <upgrade_fn:types>
        let target = std::fs::read(&args[1]).expect("read target wasm");
        let attacker = std::fs::read(&args[2]).expect("read attacker wasm");
        let out_path = &args[3];
        let ctor = csv_types(&args[4]);
        let (uname, utypes) = split_spec(&args[5]);
        let (verdict, detail) = probe_upgrade(&target, &ctor, &attacker, &uname, &utypes);
        std::fs::write(out_path, format!("{{\"verdict\":\"{}\",\"detail\":\"{}\"}}", verdict, esc(&detail))).expect("write out");
        println!("[harness --upgrade] {} : {}", args[5], verdict);
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("--chain") {
        // --chain <wasm> <out> <ctor_csv> <foothold:types> <target:types>
        let wasm = std::fs::read(&args[1]).expect("read wasm");
        let out_path = &args[2];
        let ctor = csv_types(&args[3]);
        let (fname, ftypes) = split_spec(&args[4]);
        let (tname, ttypes) = split_spec(&args[5]);
        let (verdict, detail) = probe_chain(&wasm, &ctor, &fname, &ftypes, &tname, &ttypes);
        std::fs::write(out_path, format!("{{\"verdict\":\"{}\",\"detail\":\"{}\"}}", verdict, esc(&detail))).expect("write out");
        println!("[harness --chain] {} -> {} : {}", args[4], args[5], verdict);
        return;
    }

    // single-fn mode: <wasm> <out> <ctor_csv> <fn:types>...
    let wasm = std::fs::read(&args[0]).expect("read wasm");
    let out_path = &args[1];
    let ctor = csv_types(&args[2]);

    let mut records: Vec<String> = Vec::new();
    for spec in &args[3..] {
        let (name, types) = split_spec(spec);
        let types_csv = spec.split_once(':').map(|(_, c)| c).unwrap_or("");
        let (verdict, delta, detail) = probe(&wasm, &ctor, &name, &types);
        records.push(format!(
            "{{\"fn\":\"{}\",\"arg_types\":\"{}\",\"verdict\":\"{}\",\"events_delta\":{},\"detail\":\"{}\"}}",
            esc(&name), esc(types_csv), verdict, delta, esc(&detail)
        ));
    }
    std::fs::write(out_path, format!("[{}]", records.join(","))).expect("write out");
    println!("[harness] {} probes -> {}", records.len(), out_path);
}
