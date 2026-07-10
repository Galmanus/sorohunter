//! The fork-sim engine, ported from `../harness` into an in-process library.
//!
//! The Python version spawned a harness process per probe (and per chain/upgrade
//! candidate). Here `probe_contract` runs the whole contract — single-fn probes,
//! composition chains, upgrade hijacks — in one process, in fresh local `Env`s.
//! This is the throughput the autonomous continuous scanner needs.
//!
//! Every probe executes only in a local `Env` against public WASM; nothing ever
//! touches a live network.

use std::panic::{catch_unwind, AssertUnwindSafe};

use soroban_sdk::{
    testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke},
    Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

use crate::abi::FnPlan;

#[derive(Debug, Clone)]
pub struct Verdict {
    pub fn_name: String,
    pub arg_types: String,
    pub verdict: String,
    pub events_delta: i64,
    pub detail: String,
}

/// Verdicts that count as a real finding (mirrors report.FINDING_VERDICTS).
pub const FINDING_VERDICTS: &[&str] = &["breach", "chain", "hijack", "reinit"];

fn synth(env: &Env, t: &str, attacker: Option<&Address>) -> Option<Val> {
    if t == "address" {
        return Some(match attacker {
            Some(a) => a.clone().into_val(env),
            None => Address::generate(env).into_val(env),
        });
    }
    if let Some(nn) = t.strip_prefix("bytes_n:") {
        let n: usize = nn.parse().ok()?;
        return Some(Bytes::from_slice(env, &std::vec![0u8; n]).into_val(env));
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

/// One-time setup functions; a fresh-deploy fork runs them once, which is an
/// artifact, not a live finding (handled in `probe`).
fn is_init_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("init") || matches!(n.as_str(), "setup" | "constructor" | "__constructor" | "bootstrap" | "boot")
}

/// Deploy the wasm, synthesizing constructor args; None if unsynthesizable or the
/// constructor traps.
fn try_deploy(env: &Env, wasm: &[u8], ctor: &[String]) -> Option<Address> {
    let args = build_args(env, ctor, None)?;
    let empty = ctor.is_empty();
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

fn probe(wasm: &[u8], ctor: &[String], name: &str, types: &[String]) -> (String, i64, String) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = match try_deploy(&env, wasm, ctor) {
        Some(c) => c,
        None => return ("deploy-failed".into(), 0, "could not deploy (constructor args unsynthesizable or deploy trapped)".into()),
    };
    let args = match build_args(&env, types, None) {
        Some(a) => a,
        None => return ("skipped".into(), 0, "unsynthesizable arg".into()),
    };
    env.set_auths(&[]);
    let before = env.events().all().events().len() as i64;
    let res = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, name), args);
    let after = env.events().all().events().len() as i64;
    let delta = after - before;
    match res {
        Err(_) => ("held".into(), delta, "aborted under empty auth".into()),
        Ok(_) if delta > 0 => {
            if is_init_name(name) {
                let repeatable = match build_args(&env, types, None) {
                    Some(a) => env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, name), a).is_ok(),
                    None => false,
                };
                if repeatable {
                    ("reinit".into(), delta, "callable more than once under empty auth — re-initialization (TA-03)".into())
                } else {
                    ("init-guarded".into(), delta, "one-time initializer, guarded on the second call — fresh-deploy artifact, not a live finding".into())
                }
            } else {
                ("breach".into(), delta, "succeeded and emitted an event under empty auth — state change without a signature".into())
            }
        }
        Ok(_) => ("view".into(), delta, "succeeded, no event — read-only".into()),
    }
}

fn probe_chain(wasm: &[u8], ctor: &[String], foothold: &str, f_types: &[String], target: &str, t_types: &[String]) -> (String, String) {
    {
        let env = Env::default();
        env.mock_all_auths();
        let cid = match try_deploy(&env, wasm, ctor) { Some(c) => c, None => return ("deploy-failed".into(), "could not deploy".into()) };
        let attacker = Address::generate(&env);
        let args = match build_args(&env, t_types, Some(&attacker)) { Some(a) => a, None => return ("skipped".into(), "unsynthesizable target arg".into()) };
        env.set_auths(&[]);
        env.mock_auths(&[MockAuth { address: &attacker, invoke: &MockAuthInvoke { contract: &cid, fn_name: target, args: args.clone(), sub_invokes: &[] } }]);
        if env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, target), args).is_ok() {
            return ("direct".into(), "target is directly attacker-callable without a foothold (single-technique, not a chain)".into());
        }
    }
    let env = Env::default();
    env.mock_all_auths();
    let cid = match try_deploy(&env, wasm, ctor) { Some(c) => c, None => return ("deploy-failed".into(), "could not deploy".into()) };
    let attacker = Address::generate(&env);
    let f_args = match build_args(&env, f_types, Some(&attacker)) { Some(a) => a, None => return ("skipped".into(), "unsynthesizable foothold arg".into()) };
    env.set_auths(&[]);
    if env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, foothold), f_args).is_err() {
        return ("no-foothold".into(), "foothold aborts under empty auth (setter is gated)".into());
    }
    let t_args = match build_args(&env, t_types, Some(&attacker)) { Some(a) => a, None => return ("skipped".into(), "unsynthesizable target arg".into()) };
    let before = env.events().all().events().len() as i64;
    env.mock_auths(&[MockAuth { address: &attacker, invoke: &MockAuthInvoke { contract: &cid, fn_name: target, args: t_args.clone(), sub_invokes: &[] } }]);
    let tr = env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, target), t_args);
    let after = env.events().all().events().len() as i64;
    match tr {
        Ok(_) if after - before > 0 => ("chain".into(), format!("foothold {}() under empty auth seized control, unlocking gated {}() for the attacker — composition, PoC is the executed sequence", foothold, target)),
        _ => ("held-after-foothold".into(), "foothold established but target still not reachable by the attacker".into()),
    }
}

fn probe_upgrade(wasm: &[u8], ctor: &[String], attacker_wasm: &[u8], upgrade_fn: &str, u_types: &[String]) -> (String, String) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = match try_deploy(&env, wasm, ctor) { Some(c) => c, None => return ("deploy-failed".into(), "could not deploy".into()) };
    let attacker_hash = env.deployer().upload_contract_wasm(attacker_wasm);
    let mut args = SVec::new(&env);
    for t in u_types {
        let v = if t == "bytes_n:32" { attacker_hash.clone().into_val(&env) } else {
            match synth(&env, t, None) { Some(v) => v, None => return ("skipped".into(), "unsynthesizable upgrade arg".into()) }
        };
        args.push_back(v);
    }
    env.set_auths(&[]);
    if env.try_invoke_contract::<Val, soroban_sdk::Error>(&cid, &Symbol::new(&env, upgrade_fn), args).is_err() {
        return ("held".into(), "upgrade aborts under empty auth (gated)".into());
    }
    let pwned = matches!(
        env.try_invoke_contract::<u32, soroban_sdk::Error>(&cid, &Symbol::new(&env, "pwned"), SVec::new(&env)),
        Ok(Ok(1337))
    );
    if pwned {
        ("hijack".into(), format!("{}() swapped the contract code under empty auth — the attacker payload now executes (pwned=1337): OBJ-SEIZE, arbitrary control", upgrade_fn))
    } else {
        ("held-after".into(), "upgrade ran but the code was not swapped to the attacker payload".into())
    }
}

/// Run the full engine over a contract in-process: single-fn probes, then
/// composition chains (address-setter foothold × held gate, confirmed by
/// execution), then upgrade hijacks (bytes_n:32 candidates). One process, any
/// contract — no subprocess per probe.
pub fn probe_contract(wasm: &[u8], attacker_wasm: &[u8], plan: &[FnPlan]) -> Vec<Verdict> {
    let ctor: Vec<String> = plan
        .iter()
        .find(|p| p.name == "__constructor" && p.synthesizable)
        .map(|p| p.inputs.clone())
        .unwrap_or_default();
    let plan: Vec<&FnPlan> = plan.iter().filter(|p| p.name != "__constructor").collect();

    let mut out: Vec<Verdict> = Vec::new();
    for p in &plan {
        if p.synthesizable {
            let (v, d, det) = probe(wasm, &ctor, &p.name, &p.inputs);
            out.push(Verdict { fn_name: p.name.clone(), arg_types: p.inputs.join(","), verdict: v, events_delta: d, detail: det });
        } else {
            out.push(Verdict { fn_name: p.name.clone(), arg_types: p.inputs.join(","), verdict: "skipped".into(), events_delta: 0, detail: p.skip_reason.clone().unwrap_or_default() });
        }
    }

    let held: Vec<(String, Vec<String>)> = plan
        .iter()
        .filter(|p| out.iter().any(|v| v.fn_name == p.name && v.verdict == "held"))
        .map(|p| (p.name.clone(), p.inputs.clone()))
        .collect();
    for fh in plan.iter().filter(|p| p.synthesizable && p.inputs.iter().any(|t| t == "address")) {
        for (tname, ttypes) in &held {
            if fh.name == *tname {
                continue;
            }
            let (v, det) = probe_chain(wasm, &ctor, &fh.name, &fh.inputs, tname, ttypes);
            if v == "chain" {
                out.push(Verdict { fn_name: format!("{}->{}", fh.name, tname), arg_types: String::new(), verdict: "chain".into(), events_delta: 0, detail: det });
            }
        }
    }

    for p in plan.iter().filter(|p| p.synthesizable && p.inputs.iter().any(|t| t == "bytes_n:32")) {
        let (v, det) = probe_upgrade(wasm, &ctor, attacker_wasm, &p.name, &p.inputs);
        if v == "hijack" {
            out.push(Verdict { fn_name: p.name.clone(), arg_types: p.inputs.join(","), verdict: "hijack".into(), events_delta: 0, detail: det });
        }
    }

    out
}
