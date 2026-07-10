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
use std::rc::Rc;

use soroban_ledger_snapshot::LedgerSnapshot;
use soroban_sdk::{
    testutils::{
        Address as _, Events as _, LedgerInfo, MockAuth, MockAuthInvoke, SnapshotSource,
        SnapshotSourceInput,
    },
    Address, Bytes, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec,
};

use crate::abi::FnPlan;
use crate::fork::RpcSnapshotSource;

#[derive(Debug, Clone)]
pub struct Verdict {
    pub fn_name: String,
    pub arg_types: String,
    pub verdict: String,
    pub events_delta: i64,
    pub detail: String,
}

/// Verdicts that count as a real finding (mirrors report.FINDING_VERDICTS).
pub const FINDING_VERDICTS: &[&str] = &["breach", "chain", "hijack", "reinit", "drain", "greed", "redirect"];

/// The protocol version this SDK's host runs at — stamp a state-fork snapshot
/// with it so the host accepts it (mainnet's live protocol may be newer).
pub fn host_protocol_version() -> u32 {
    Env::default().ledger().protocol_version()
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

/// Probe a contract against its REAL forked on-chain state (a minimal
/// LedgerSnapshot: instance storage + code). The contract already exists at its
/// real address with real admin/config, so a breach here is CONFIRMED — not a
/// fresh-deploy candidate — and one-time initializers revert naturally (no
/// heuristic). Single-fn for v1; chains/upgrades stay in fresh-deploy mode.
pub fn probe_forked(snapshot: &LedgerSnapshot, contract_id: &str, plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| p.name != "__constructor") {
        if !p.synthesizable {
            out.push(Verdict {
                fn_name: p.name.clone(),
                arg_types: p.inputs.join(","),
                verdict: "skipped".into(),
                events_delta: 0,
                detail: p.skip_reason.clone().unwrap_or_default(),
            });
            continue;
        }
        let (v, d, det) = probe_one_forked(snapshot, contract_id, &p.name, &p.inputs);
        out.push(Verdict {
            fn_name: p.name.clone(),
            arg_types: p.inputs.join(","),
            verdict: v,
            events_delta: d,
            detail: det,
        });
    }
    out
}

fn probe_one_forked(snapshot: &LedgerSnapshot, contract_id: &str, name: &str, types: &[String]) -> (String, i64, String) {
    let env = Env::from_ledger_snapshot(snapshot.clone());
    let addr = Address::from_string(&SString::from_str(&env, contract_id));
    let args = match build_args(&env, types, None) {
        Some(a) => a,
        None => return ("skipped".into(), 0, "unsynthesizable arg".into()),
    };
    env.set_auths(&[]);
    let before = env.events().all().events().len() as i64;
    let res = env.try_invoke_contract::<Val, soroban_sdk::Error>(&addr, &Symbol::new(&env, name), args);
    let after = env.events().all().events().len() as i64;
    let delta = after - before;
    match res {
        Err(_) => ("held".into(), delta, "aborted under empty auth (real forked state)".into()),
        Ok(_) if delta > 0 => (
            "breach".into(),
            delta,
            "CONFIRMED against real forked state: state change + event under empty auth — missing auth".into(),
        ),
        Ok(_) => ("view".into(), delta, "succeeded, no event — read-only".into()),
    }
}

/// Probe against the contract's REAL full on-chain state, pulled lazily via RPC
/// (balances, reserves, config — not just instance storage). This is the mode
/// for economic bugs: the fork sees real liquidity. A breach here is CONFIRMED.
pub fn probe_forked_lazy(source: Rc<RpcSnapshotSource>, ledger_info: &LedgerInfo, contract_id: &str, plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| p.name != "__constructor") {
        if !p.synthesizable {
            out.push(Verdict {
                fn_name: p.name.clone(),
                arg_types: p.inputs.join(","),
                verdict: "skipped".into(),
                events_delta: 0,
                detail: p.skip_reason.clone().unwrap_or_default(),
            });
            continue;
        }
        let (v, d, det) = probe_one_forked_lazy(source.clone(), ledger_info, contract_id, &p.name, &p.inputs);
        out.push(Verdict {
            fn_name: p.name.clone(),
            arg_types: p.inputs.join(","),
            verdict: v,
            events_delta: d,
            detail: det,
        });
    }
    out
}

fn probe_one_forked_lazy(source: Rc<RpcSnapshotSource>, li: &LedgerInfo, contract_id: &str, name: &str, types: &[String]) -> (String, i64, String) {
    let src: Rc<dyn SnapshotSource> = source;
    let env = Env::from_ledger_snapshot(SnapshotSourceInput {
        source: src,
        ledger_info: Some(li.clone()),
        snapshot: None,
    });
    let addr = Address::from_string(&SString::from_str(&env, contract_id));
    let args = match build_args(&env, types, None) {
        Some(a) => a,
        None => return ("skipped".into(), 0, "unsynthesizable arg".into()),
    };
    env.set_auths(&[]);
    let before = env.events().all().events().len() as i64;
    let res = env.try_invoke_contract::<Val, soroban_sdk::Error>(&addr, &Symbol::new(&env, name), args);
    let after = env.events().all().events().len() as i64;
    let delta = after - before;
    match res {
        Err(_) => ("held".into(), delta, "aborted under empty auth (real forked state)".into()),
        Ok(_) if delta > 0 => (
            "breach".into(),
            delta,
            "CONFIRMED against real forked state: state change + event under empty auth — missing auth".into(),
        ),
        Ok(_) => ("view".into(), delta, "succeeded, no event — read-only".into()),
    }
}

/// Build a fork Env from the lazy RPC source + ledger info.
pub fn forked_env(source: Rc<RpcSnapshotSource>, ledger_info: &LedgerInfo) -> Env {
    let src: Rc<dyn SnapshotSource> = source;
    Env::from_ledger_snapshot(SnapshotSourceInput {
        source: src,
        ledger_info: Some(ledger_info.clone()),
        snapshot: None,
    })
}

/// Read `token.balance(holder)` in the given env. None if it is not a token or
/// has no `balance` function.
pub fn token_balance(env: &Env, token: &str, holder: &str) -> Option<i128> {
    let taddr = Address::from_string(&SString::from_str(env, token));
    let haddr = Address::from_string(&SString::from_str(env, holder));
    let mut args = SVec::new(env);
    args.push_back(haddr.into_val(env));
    match env.try_invoke_contract::<i128, soroban_sdk::Error>(&taddr, &Symbol::new(env, "balance"), args) {
        Ok(Ok(v)) => Some(v),
        _ => None,
    }
}

/// Economic drain detector: for each mutating fn, probe it under EMPTY auth
/// against real forked reserves and check if the contract's real token balance
/// DROPPED. A drop under empty auth = unauthenticated value extraction from real
/// liquidity — a CONFIRMED economic drain. Fns that require auth revert, so their
/// reserves are unchanged and they are not flagged.
pub fn probe_drain(source: Rc<RpcSnapshotSource>, li: &LedgerInfo, contract: &str, tokens: &[String], plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| p.synthesizable && !p.inputs.is_empty() && p.name != "__constructor") {
        let env = forked_env(source.clone(), li);
        let attacker = Address::generate(&env);
        let caddr = Address::from_string(&SString::from_str(&env, contract));
        let before: Vec<Option<i128>> = tokens.iter().map(|t| token_balance(&env, t, contract)).collect();
        let args = match build_args(&env, &p.inputs, Some(&attacker)) {
            Some(a) => a,
            None => continue,
        };
        env.set_auths(&[]);
        let _ = env.try_invoke_contract::<Val, soroban_sdk::Error>(&caddr, &Symbol::new(&env, &p.name), args);
        for (i, t) in tokens.iter().enumerate() {
            let after = token_balance(&env, t, contract);
            if let (Some(b), Some(a)) = (before[i], after) {
                if a < b {
                    out.push(Verdict {
                        fn_name: p.name.clone(),
                        arg_types: p.inputs.join(","),
                        verdict: "drain".into(),
                        events_delta: 0,
                        detail: format!(
                            "OBJ-DRAIN: {}() under empty auth reduced the contract's real {} balance by {} — unauthenticated value extraction, CONFIRMED against forked state",
                            p.name, t, b - a
                        ),
                    });
                }
            }
        }
    }
    out
}

/// The std-string (C-address) form of a soroban `Address`, for `token_balance`.
fn addr_to_str(a: &Address) -> Option<std::string::String> {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    std::string::String::from_utf8(buf).ok()
}

/// Attacker-authorized net-gain check for one fn, in an already-forked `env`.
///
/// The empty-auth drain detector misses the *authorized* economic bug: a fn that
/// calls `caller.require_auth()` (so it aborts under empty auth) but then pays the
/// caller value they never earned — unchecked `claim`/`withdraw`, broken
/// accounting, a payout that forgets to verify a deposit/position. Here the
/// attacker authorizes everything (`mock_all_auths`); starting from a fresh zero
/// position, if invoking the fn leaves the attacker holding MORE of any token,
/// the contract paid unearned value to whoever signs — a confirmed economic
/// exploit. Returns the finding or `None`.
fn greed_check_in_env(env: &Env, contract: &str, tokens: &[String], p: &FnPlan) -> Option<Verdict> {
    let attacker = Address::generate(env);
    let attacker_str = addr_to_str(&attacker)?;
    let before: Vec<Option<i128>> =
        tokens.iter().map(|t| token_balance(env, t, &attacker_str)).collect();
    let caddr = Address::from_string(&SString::from_str(env, contract));
    let args = build_args(env, &p.inputs, Some(&attacker))?;
    env.mock_all_auths();
    let _ = env.try_invoke_contract::<Val, soroban_sdk::Error>(&caddr, &Symbol::new(env, &p.name), args);
    for (i, t) in tokens.iter().enumerate() {
        let after = token_balance(env, t, &attacker_str);
        if let (Some(b), Some(a)) = (before[i], after) {
            if a > b {
                return Some(Verdict {
                    fn_name: p.name.clone(),
                    arg_types: p.inputs.join(","),
                    verdict: "greed".into(),
                    events_delta: 0,
                    detail: format!(
                        "OBJ-GREED: {}() under attacker auth paid the caller {} of {} from a zero position — authorized-but-unearned value extraction (broken accounting / unchecked payout), CONFIRMED against forked state",
                        p.name, a - b, t
                    ),
                });
            }
        }
    }
    None
}

/// Economic greed detector: the attacker-authorized counterpart to `probe_drain`.
/// For each mutating fn, in a fresh forked env, let the attacker authorize the
/// call and flag any fn that leaves the attacker richer (see `greed_check_in_env`).
pub fn probe_greed(source: Rc<RpcSnapshotSource>, li: &LedgerInfo, contract: &str, tokens: &[String], plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| p.synthesizable && !p.inputs.is_empty() && p.name != "__constructor") {
        let env = forked_env(source.clone(), li);
        if let Some(v) = greed_check_in_env(&env, contract, tokens, p) {
            out.push(v);
        }
    }
    out
}

/// Read the contract's admin/owner address via a standard getter. Tries the
/// common Soroban names and returns the first that answers with an `Address`.
/// `None` if the contract exposes no readable admin — then there is nothing to
/// compare and the hijack check abstains.
fn read_admin(env: &Env, contract: &str) -> Option<std::string::String> {
    let caddr = Address::from_string(&SString::from_str(env, contract));
    for getter in ["admin", "get_admin", "owner", "get_owner"] {
        let args = SVec::new(env);
        if let Ok(Ok(a)) =
            env.try_invoke_contract::<Address, soroban_sdk::Error>(&caddr, &Symbol::new(env, getter), args)
        {
            return addr_to_str(&a);
        }
    }
    None
}

/// Admin-capture (privilege escalation) check for one fn, in an already-forked
/// `env`. The attacker-auth trick that saves `greed` (state-gating survives
/// `mock_all_auths`) does NOT apply here: an admin gate is an *auth* check, and
/// mocking all auths would let a correctly-gated `set_admin` through — a false
/// positive. So this runs under EMPTY auth like `probe_drain`: a correct setter
/// calls `current_admin.require_auth()` and reverts, leaving the admin unchanged;
/// an unprotected setter reassigns the admin to the attacker-supplied address and
/// is flagged. Unlike the event-delta `breach` probe, this reads the admin getter
/// and confirms *who* holds control, so it also catches silent setters that emit
/// no event (which `breach` misses). Returns the finding or `None`.
fn hijack_check_in_env(env: &Env, contract: &str, p: &FnPlan) -> Option<Verdict> {
    let attacker = Address::generate(env);
    let attacker_str = addr_to_str(&attacker)?;
    let admin_before = read_admin(env, contract)?;
    if admin_before == attacker_str {
        return None;
    }
    let caddr = Address::from_string(&SString::from_str(env, contract));
    let args = build_args(env, &p.inputs, Some(&attacker))?;
    env.set_auths(&[]);
    let _ = env.try_invoke_contract::<Val, soroban_sdk::Error>(&caddr, &Symbol::new(env, &p.name), args);
    let admin_after = read_admin(env, contract)?;
    if admin_after != admin_before && admin_after == attacker_str {
        return Some(Verdict {
            fn_name: p.name.clone(),
            arg_types: p.inputs.join(","),
            verdict: "hijack".into(),
            events_delta: 0,
            detail: format!(
                "OBJ-HIJACK: {}() under EMPTY auth reassigned the contract admin/owner to the attacker-supplied address — unprotected privilege setter (missing current-admin require_auth), CONFIRMED against forked state",
                p.name
            ),
        });
    }
    None
}

/// Admin-capture detector: the role-capture sibling of `probe_drain`/`probe_greed`.
/// For each mutating fn that takes an address, in a fresh forked env, inject the
/// attacker's address under empty auth and flag any fn that leaves the attacker
/// holding the contract's admin/owner role (see `hijack_check_in_env`).
pub fn probe_hijack(source: Rc<RpcSnapshotSource>, li: &LedgerInfo, contract: &str, plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan
        .iter()
        .filter(|p| p.synthesizable && p.inputs.iter().any(|t| t == "address") && p.name != "__constructor")
    {
        let env = forked_env(source.clone(), li);
        if let Some(v) = hijack_check_in_env(&env, contract, p) {
            out.push(v);
        }
    }
    out
}

/// Build args placing a distinct authorizer at `auth_idx` and the attacker
/// `recipient` at every other address slot; non-address args get their default
/// synth. This is what decouples the *authorizer* from the *beneficiary* — the
/// property `greed` (which injects one attacker into every slot) cannot express.
fn synth_decoupled(
    env: &Env,
    types: &[String],
    auth_idx: usize,
    authorizer: &Address,
    recipient: &Address,
) -> Option<SVec<Val>> {
    let mut args = SVec::new(env);
    for (i, t) in types.iter().enumerate() {
        let v = if t == "address" {
            if i == auth_idx {
                authorizer.clone().into_val(env)
            } else {
                recipient.clone().into_val(env)
            }
        } else {
            synth(env, t, None)?
        };
        args.push_back(v);
    }
    Some(args)
}

/// Injected-recipient / caller-supplied-address-trust check (TA-05) for one fn,
/// in an already-forked `env`. The agent-payment class: a legitimately authorized
/// caller can redirect the contract's value to an attacker-supplied address the
/// contract never bound auth to (Bankr/Grok ~$150-180K, MCP router drain $500K —
/// the agent *was* authorized; the recipient was injected).
///
/// For each address arg tried as the sole authorizer (auth forged scoped to that
/// address only — never the recipient), the attacker takes every other address
/// slot as beneficiary. If a reserve token leaves the contract and lands on the
/// non-authorizing attacker, the recipient was unbound. This is decoupled from
/// `greed`: a contract that forbids self-pay (`recipient != caller`) silences
/// greed's single-attacker injection but is fully exposed here.
fn redirect_check_in_env(env: &Env, contract: &str, tokens: &[String], p: &FnPlan) -> Option<Verdict> {
    let addr_idxs: Vec<usize> = p
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, t)| *t == "address")
        .map(|(i, _)| i)
        .collect();
    if addr_idxs.len() < 2 {
        return None;
    }
    let caddr = Address::from_string(&SString::from_str(env, contract));
    for &auth_idx in &addr_idxs {
        let authorizer = Address::generate(env);
        let recipient = Address::generate(env);
        let recipient_str = match addr_to_str(&recipient) {
            Some(s) => s,
            None => continue,
        };
        let args = match synth_decoupled(env, &p.inputs, auth_idx, &authorizer, &recipient) {
            Some(a) => a,
            None => continue,
        };
        let before_c: Vec<Option<i128>> = tokens.iter().map(|t| token_balance(env, t, contract)).collect();
        let before_r: Vec<Option<i128>> = tokens.iter().map(|t| token_balance(env, t, &recipient_str)).collect();
        env.set_auths(&[]);
        env.mock_auths(&[MockAuth {
            address: &authorizer,
            invoke: &MockAuthInvoke {
                contract: &caddr,
                fn_name: &p.name,
                args: args.clone(),
                sub_invokes: &[],
            },
        }]);
        let _ = env.try_invoke_contract::<Val, soroban_sdk::Error>(&caddr, &Symbol::new(env, &p.name), args);
        for (i, t) in tokens.iter().enumerate() {
            let after_c = token_balance(env, t, contract);
            let after_r = token_balance(env, t, &recipient_str);
            if let (Some(bc), Some(ac), Some(br), Some(ar)) = (before_c[i], after_c, before_r[i], after_r) {
                if ac < bc && ar > br {
                    return Some(Verdict {
                        fn_name: p.name.clone(),
                        arg_types: p.inputs.join(","),
                        verdict: "redirect".into(),
                        events_delta: 0,
                        detail: format!(
                            "OBJ-REDIRECT: {}() let an authorized caller send {} of {} to an attacker-supplied recipient that never signed — caller-supplied-address trust (injected-recipient / agent-payment class, TA-05), CONFIRMED against forked state",
                            p.name, ar - br, t
                        ),
                    });
                }
            }
        }
    }
    None
}

/// Injected-recipient detector (TA-05): the auth-scoping sibling of the economic
/// probes. For each mutating fn with two or more address args, in a fresh forked
/// env, flag any fn that pays the contract's reserves to an attacker-supplied
/// address that never authorized (see `redirect_check_in_env`).
pub fn probe_redirect(source: Rc<RpcSnapshotSource>, li: &LedgerInfo, contract: &str, tokens: &[String], plan: &[FnPlan]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for p in plan.iter().filter(|p| {
        p.synthesizable
            && p.name != "__constructor"
            && p.inputs.iter().filter(|t| *t == "address").count() >= 2
    }) {
        let env = forked_env(source.clone(), li);
        if let Some(v) = redirect_check_in_env(&env, contract, tokens, p) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

    #[contracttype]
    enum RKey {
        Token,
    }

    // VULN: `pay` authorizes the operator and forbids self-pay, then sends reserves
    // to an arbitrary `recipient` it never binds auth to. The self-pay guard is
    // exactly what makes greed's single-attacker injection revert (silent) while the
    // decoupled authorizer/recipient injection here drains it — TA-05, not greed.
    #[contract]
    struct RedirectVault;
    #[contractimpl]
    impl RedirectVault {
        pub fn __constructor(e: Env, token: Address) {
            e.storage().instance().set(&RKey::Token, &token);
        }
        pub fn pay(e: Env, operator: Address, recipient: Address, amount: i128) {
            operator.require_auth();
            if operator == recipient {
                panic!("no self-pay");
            }
            let t: Address = e.storage().instance().get(&RKey::Token).unwrap();
            token::Client::new(&e, &t).transfer(&e.current_contract_address(), &recipient, &amount);
        }
    }

    // CORRECT: `pay` binds the recipient too — it must consent. An attacker
    // recipient that never signs makes require_auth revert, so nothing moves.
    #[contract]
    struct BoundRouter;
    #[contractimpl]
    impl BoundRouter {
        pub fn __constructor(e: Env, token: Address) {
            e.storage().instance().set(&RKey::Token, &token);
        }
        pub fn pay(e: Env, operator: Address, recipient: Address, amount: i128) {
            operator.require_auth();
            recipient.require_auth();
            let t: Address = e.storage().instance().get(&RKey::Token).unwrap();
            token::Client::new(&e, &t).transfer(&e.current_contract_address(), &recipient, &amount);
        }
    }

    fn make_token(env: &Env) -> Address {
        let issuer = Address::generate(env);
        env.register_stellar_asset_contract_v2(issuer).address()
    }

    fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
        token::StellarAssetClient::new(env, token).mint(to, &amount);
    }

    fn plan(name: &str) -> FnPlan {
        FnPlan {
            name: name.into(),
            inputs: std::vec!["address".into(), "address".into(), "i128".into()],
            synthesizable: true,
            skip_reason: None,
        }
    }

    #[test]
    fn redirect_flags_unbound_recipient() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = make_token(&env);
        let vault = env.register(RedirectVault, (token_addr.clone(),));
        mint(&env, &token_addr, &vault, 1_000);
        let contract = addr_to_str(&vault).unwrap();
        let tokens = std::vec![addr_to_str(&token_addr).unwrap()];
        let v = redirect_check_in_env(&env, &contract, &tokens, &plan("pay"));
        assert!(v.is_some(), "redirect detector must flag an unbound-recipient payout");
        assert_eq!(v.unwrap().verdict, "redirect");
    }

    #[test]
    fn redirect_silent_on_bound_recipient() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = make_token(&env);
        let vault = env.register(BoundRouter, (token_addr.clone(),));
        mint(&env, &token_addr, &vault, 1_000);
        let contract = addr_to_str(&vault).unwrap();
        let tokens = std::vec![addr_to_str(&token_addr).unwrap()];
        let v = redirect_check_in_env(&env, &contract, &tokens, &plan("pay"));
        assert!(v.is_none(), "redirect detector must NOT flag a recipient-bound router");
    }

    // Guard the greed/redirect boundary: the same self-pay-guarded vault that
    // redirect flags must leave greed SILENT (its single-attacker injection hits
    // the `operator == recipient` panic), proving the two detectors are orthogonal.
    #[test]
    fn greed_silent_where_redirect_fires() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = make_token(&env);
        let vault = env.register(RedirectVault, (token_addr.clone(),));
        mint(&env, &token_addr, &vault, 1_000);
        let contract = addr_to_str(&vault).unwrap();
        let tokens = std::vec![addr_to_str(&token_addr).unwrap()];
        let g = greed_check_in_env(&env, &contract, &tokens, &plan("pay"));
        assert!(g.is_none(), "greed must be silent on the self-pay-guarded vault (redirect's domain)");
    }
}

#[cfg(test)]
mod hijack_tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

    #[contracttype]
    enum AKey {
        Admin,
    }

    // VULN: `set_admin` overwrites the admin with no current-admin auth check —
    // the unprotected privilege-setter class (TA-02). Anyone can seize control.
    #[contract]
    struct VulnAdmin;
    #[contractimpl]
    impl VulnAdmin {
        pub fn __constructor(e: Env, admin: Address) {
            e.storage().instance().set(&AKey::Admin, &admin);
        }
        pub fn admin(e: Env) -> Address {
            e.storage().instance().get(&AKey::Admin).unwrap()
        }
        pub fn set_admin(e: Env, new_admin: Address) {
            e.storage().instance().set(&AKey::Admin, &new_admin);
        }
    }

    // CORRECT: `set_admin` requires the CURRENT admin's auth before rotating; under
    // empty auth it reverts and the admin is unchanged.
    #[contract]
    struct SafeAdmin;
    #[contractimpl]
    impl SafeAdmin {
        pub fn __constructor(e: Env, admin: Address) {
            e.storage().instance().set(&AKey::Admin, &admin);
        }
        pub fn admin(e: Env) -> Address {
            e.storage().instance().get(&AKey::Admin).unwrap()
        }
        pub fn set_admin(e: Env, new_admin: Address) {
            let cur: Address = e.storage().instance().get(&AKey::Admin).unwrap();
            cur.require_auth();
            e.storage().instance().set(&AKey::Admin, &new_admin);
        }
    }

    fn plan(name: &str) -> FnPlan {
        FnPlan {
            name: name.into(),
            inputs: std::vec!["address".into()],
            synthesizable: true,
            skip_reason: None,
        }
    }

    // The bracket: a stub returning None fails recall, a stub returning Some fails
    // precision — only a detector that discriminates unprotected-vs-gated passes both.
    #[test]
    fn hijack_flags_unprotected_set_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let orig_admin = Address::generate(&env);
        let vault = env.register(VulnAdmin, (orig_admin,));
        let contract = addr_to_str(&vault).unwrap();
        let v = hijack_check_in_env(&env, &contract, &plan("set_admin"));
        assert!(v.is_some(), "hijack detector must flag an unprotected set_admin");
        assert_eq!(v.unwrap().verdict, "hijack");
    }

    #[test]
    fn hijack_silent_on_gated_set_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let orig_admin = Address::generate(&env);
        let vault = env.register(SafeAdmin, (orig_admin,));
        let contract = addr_to_str(&vault).unwrap();
        let v = hijack_check_in_env(&env, &contract, &plan("set_admin"));
        assert!(v.is_none(), "hijack detector must NOT flag a current-admin-gated set_admin");
    }
}

#[cfg(test)]
mod greed_tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

    #[contracttype]
    enum GKey {
        Token,
    }

    // VULN: `claim` pays any authorizing caller from reserves with no eligibility
    // check — the authorized-but-broken-accounting class.
    #[contract]
    struct GreedVault;
    #[contractimpl]
    impl GreedVault {
        pub fn __constructor(e: Env, token: Address) {
            e.storage().instance().set(&GKey::Token, &token);
        }
        pub fn claim(e: Env, caller: Address, amount: i128) {
            caller.require_auth();
            let t: Address = e.storage().instance().get(&GKey::Token).unwrap();
            token::Client::new(&e, &t).transfer(&e.current_contract_address(), &caller, &amount);
        }
    }

    // CORRECT: `withdraw` is gated on the caller's recorded deposit; a fresh
    // attacker has none, so it reverts and pays nothing.
    #[contract]
    struct SafeVault;
    #[contractimpl]
    impl SafeVault {
        pub fn __constructor(e: Env, token: Address) {
            e.storage().instance().set(&GKey::Token, &token);
        }
        pub fn withdraw(e: Env, caller: Address, amount: i128) {
            caller.require_auth();
            let bal: i128 = e.storage().persistent().get(&caller).unwrap_or(0);
            if amount > bal {
                panic!("insufficient deposit");
            }
            let t: Address = e.storage().instance().get(&GKey::Token).unwrap();
            token::Client::new(&e, &t).transfer(&e.current_contract_address(), &caller, &amount);
        }
    }

    fn make_token(env: &Env) -> Address {
        let issuer = Address::generate(env);
        env.register_stellar_asset_contract_v2(issuer).address()
    }

    fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
        token::StellarAssetClient::new(env, token).mint(to, &amount);
    }

    fn plan(name: &str) -> FnPlan {
        FnPlan {
            name: name.into(),
            inputs: std::vec!["address".into(), "i128".into()],
            synthesizable: true,
            skip_reason: None,
        }
    }

    // The pair brackets the behavior: a stub returning None fails the recall
    // test, a stub returning Some fails the precision test — only a detector that
    // actually discriminates payout-from-zero passes both.
    #[test]
    fn greed_flags_unchecked_payout() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = make_token(&env);
        let vault = env.register(GreedVault, (token_addr.clone(),));
        mint(&env, &token_addr, &vault, 1_000);

        let contract = addr_to_str(&vault).unwrap();
        let tokens = std::vec![addr_to_str(&token_addr).unwrap()];
        let v = greed_check_in_env(&env, &contract, &tokens, &plan("claim"));
        assert!(v.is_some(), "greed detector must flag unchecked claim payout");
        assert_eq!(v.unwrap().verdict, "greed");
    }

    #[test]
    fn greed_silent_on_correct_vault() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = make_token(&env);
        let vault = env.register(SafeVault, (token_addr.clone(),));
        mint(&env, &token_addr, &vault, 1_000);

        let contract = addr_to_str(&vault).unwrap();
        let tokens = std::vec![addr_to_str(&token_addr).unwrap()];
        let v = greed_check_in_env(&env, &contract, &tokens, &plan("withdraw"));
        assert!(v.is_none(), "greed detector must NOT flag a correctly-gated withdraw");
    }
}
