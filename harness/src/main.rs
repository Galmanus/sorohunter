//! sorohunter fork-sim harness — the generic auth prober.
//!
//! Given a contract WASM and a probe plan (function name + ABI arg types), it
//! deploys the WASM into a local Env and, for each function, synthesizes args
//! from the types, invokes under EMPTY auth, and classifies via an event-diff:
//!
//!   aborts under empty auth        -> held  (the function enforces auth)
//!   succeeds and emits an event    -> BREACH (state change without a signature)
//!   succeeds and emits no event    -> view   (read-only; not a finding)
//!
//! Nothing here ever touches a live network: every invocation is in-process
//! against a local ledger. Verdicts are written as JSON.
//!
//! argv: <wasm_path> <out_json> "<fn>:<t1>,<t2>,..." [more fns...]

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

fn synth(env: &Env, t: &str) -> Option<Val> {
    if t == "address" {
        return Some(Address::generate(env).into_val(env));
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

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Probe one function in a fresh Env so probes never contaminate each other.
fn probe(wasm: &[u8], name: &str, types: &[String]) -> (String, i64, String) {
    let env = Env::default();
    env.mock_all_auths(); // deploy freely
    let cid = env.register(wasm, ());

    let mut args = SVec::new(&env);
    for t in types {
        match synth(&env, t) {
            Some(v) => args.push_back(v),
            None => return ("skipped".into(), 0, format!("unsynthesizable arg: {}", t)),
        }
    }

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

fn main() {
    let mut a = std::env::args().skip(1);
    let wasm_path = a.next().expect("wasm path");
    let out_path = a.next().expect("out json path");
    let wasm = std::fs::read(&wasm_path).expect("read wasm");

    let mut records: Vec<String> = Vec::new();
    for spec in a {
        let (name, types_csv) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
        let types: Vec<String> = if types_csv.is_empty() {
            Vec::new()
        } else {
            types_csv.split(',').map(|s| s.to_string()).collect()
        };
        let (verdict, delta, detail) = probe(&wasm, name, &types);
        records.push(format!(
            "{{\"fn\":\"{}\",\"arg_types\":\"{}\",\"verdict\":\"{}\",\"events_delta\":{},\"detail\":\"{}\"}}",
            esc(name), esc(&types_csv), verdict, delta, esc(&detail)
        ));
    }
    std::fs::write(&out_path, format!("[{}]", records.join(","))).expect("write out");
    println!("[harness] {} probes -> {}", records.len(), out_path);
}
