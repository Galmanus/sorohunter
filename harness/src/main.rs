//! sorohunter fork-sim harness — generic auth prober + composition prober.
//!
//! Single-fn mode:  <wasm> <out_json> "<fn>:<t1>,<t2>,..." [more fns...]
//!   deploy the WASM into a local Env and, for each function, synthesize args
//!   from the ABI types, invoke under EMPTY auth, classify via an event-diff:
//!     aborts under empty auth     -> held   (enforces auth)
//!     succeeds and emits an event -> BREACH (state change without a signature)
//!     succeeds and emits no event -> view   (read-only; not a finding)
//!
//! Chain mode:      --chain <wasm> <out_json> "<foothold>:<types>" "<target>:<types>"
//!   executes a two-step privilege chain (TE-01 / SK-C01) in ONE fork:
//!     1. baseline: target under the attacker's auth, no foothold -> must abort;
//!        if it succeeds, the target is directly attacker-callable ("direct",
//!        single-technique, not a chain).
//!     2. foothold: invoke the setter under EMPTY auth, its address arg set to
//!        the attacker -> if it aborts, "no-foothold".
//!     3. target: invoke under the attacker's auth only -> if it now succeeds
//!        and emits an event, the chain is CONFIRMED ("chain").
//!
//! Nothing here ever touches a live network: every invocation is in-process
//! against a local ledger.

use soroban_sdk::{
    testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke},
    Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

/// Synthesize a `Val` for an ABI type. If `attacker` is set, `address` args
/// resolve to it (so a foothold's new-admin arg and the target's auth subject
/// are the same principal); otherwise a fresh address is generated.
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

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn split_spec(spec: &str) -> (String, Vec<String>) {
    let (name, csv) = spec.split_once(':').unwrap_or((spec, ""));
    let types = if csv.is_empty() {
        Vec::new()
    } else {
        csv.split(',').map(|s| s.to_string()).collect()
    };
    (name.to_string(), types)
}

/// Probe one function in a fresh Env so probes never contaminate each other.
fn probe(wasm: &[u8], name: &str, types: &[String]) -> (String, i64, String) {
    let env = Env::default();
    env.mock_all_auths(); // deploy freely
    let cid = env.register(wasm, ());

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
    foothold: &str,
    f_types: &[String],
    target: &str,
    t_types: &[String],
) -> (String, String) {
    // 1. baseline: can the attacker call the target directly, with no foothold?
    {
        let env = Env::default();
        env.mock_all_auths();
        let cid = env.register(wasm, ());
        let attacker = Address::generate(&env);
        let args = match build_args(&env, t_types, Some(&attacker)) {
            Some(a) => a,
            None => return ("skipped".into(), "unsynthesizable target arg".into()),
        };
        env.set_auths(&[]);
        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &cid,
                fn_name: target,
                args: args.clone(),
                sub_invokes: &[],
            },
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
    let cid = env.register(wasm, ());
    let attacker = Address::generate(&env);

    let f_args = match build_args(&env, f_types, Some(&attacker)) {
        Some(a) => a,
        None => return ("skipped".into(), "unsynthesizable foothold arg".into()),
    };
    env.set_auths(&[]); // foothold must land with NO signature
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
        invoke: &MockAuthInvoke {
            contract: &cid,
            fn_name: target,
            args: t_args.clone(),
            sub_invokes: &[],
        },
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
        _ => (
            "held-after-foothold".into(),
            "foothold established but target still not reachable by the attacker".into(),
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(|s| s.as_str()) == Some("--chain") {
        let wasm_path = &args[1];
        let out_path = &args[2];
        let (fname, ftypes) = split_spec(&args[3]);
        let (tname, ttypes) = split_spec(&args[4]);
        let wasm = std::fs::read(wasm_path).expect("read wasm");
        let (verdict, detail) = probe_chain(&wasm, &fname, &ftypes, &tname, &ttypes);
        std::fs::write(
            out_path,
            format!("{{\"verdict\":\"{}\",\"detail\":\"{}\"}}", verdict, esc(&detail)),
        )
        .expect("write out");
        println!("[harness --chain] {} -> {} : {}", args[3], args[4], verdict);
        return;
    }

    // single-fn mode
    let wasm_path = &args[0];
    let out_path = &args[1];
    let wasm = std::fs::read(wasm_path).expect("read wasm");

    let mut records: Vec<String> = Vec::new();
    for spec in &args[2..] {
        let (name, types) = split_spec(spec);
        let types_csv = spec.split_once(':').map(|(_, c)| c).unwrap_or("");
        let (verdict, delta, detail) = probe(&wasm, &name, &types);
        records.push(format!(
            "{{\"fn\":\"{}\",\"arg_types\":\"{}\",\"verdict\":\"{}\",\"events_delta\":{},\"detail\":\"{}\"}}",
            esc(&name), esc(types_csv), verdict, delta, esc(&detail)
        ));
    }
    std::fs::write(out_path, format!("[{}]", records.join(","))).expect("write out");
    println!("[harness] {} probes -> {}", records.len(), out_path);
}
