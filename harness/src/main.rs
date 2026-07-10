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
    testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke},
    Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

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
        Ok(_) if delta > 0 => (
            "breach".into(),
            delta,
            "succeeded and emitted an event under empty auth — state change without a signature".into(),
        ),
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

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
