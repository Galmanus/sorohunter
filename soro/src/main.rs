//! sorohunter — single-binary Rust consolidation.
//!
//! Replaces the Python orchestration (abi/cli/report) with one static binary so
//! the autonomous continuous scanner runs in-process (no subprocess-per-probe)
//! and with no Python runtime. The fork-sim engine is ported from `../harness`.
//!
//!   sorohunter bench                 run the engine over bench/ vs ground truth
//!   sorohunter probe <wasm...>       run the engine on local contract wasm file(s)
//!
//! `scan <id>` (native RPC acquisition) is the next increment.

#![allow(dead_code)]

mod abi;
mod cve;
mod econ;
mod engine;
mod fork;
mod report;
mod rpc;

use std::collections::BTreeMap;

use serde_json::Value;

/// The attacker payload for the upgrade detector, embedded so the binary is
/// self-contained.
const ATTACKER: &[u8] = include_bytes!("../assets/attacker_pwn.wasm");

fn probe_wasm_file(path: &str) -> Vec<engine::Verdict> {
    let wasm = std::fs::read(path).unwrap_or_default();
    // native: parse the ABI straight from the WASM custom section, no CLI.
    let plan = abi::plan_from_wasm(&wasm);
    engine::probe_contract(&wasm, ATTACKER, &plan)
}

fn cmd_bench() -> i32 {
    let raw = match std::fs::read_to_string("bench/ground_truth.json") {
        Ok(r) => r,
        Err(_) => {
            eprintln!("run from the repo root (needs bench/ground_truth.json)");
            return 1;
        }
    };
    let gt_val: Value = serde_json::from_str(&raw).expect("parse ground_truth.json");
    let mut gt: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in gt_val.as_object().unwrap() {
        let expected = v.as_array().unwrap().iter().filter_map(|x| x.as_str().map(String::from)).collect();
        gt.insert(k.clone(), expected);
    }

    let mut results = Vec::new();
    for contract in gt.keys() {
        let wasm = format!("bench/target/wasm32v1-none/release/{}.wasm", contract);
        if !std::path::Path::new(&wasm).exists() {
            eprintln!("missing {} — run `stellar contract build` in bench/ first", wasm);
            return 1;
        }
        results.push((contract.clone(), probe_wasm_file(&wasm)));
    }

    let ev = report::evaluate(&results, &gt);
    println!(
        "precision {:.0}% · recall {:.0}% (tp {}, fp {}, fn {})",
        ev.precision * 100.0,
        ev.recall * 100.0,
        ev.tp,
        ev.fp,
        ev.fn_
    );
    for pc in &ev.per {
        let flag = if pc.flagged.is_empty() { "clean".to_string() } else { pc.flagged.join(", ") };
        println!("  {:<18} findings: {}", pc.contract, flag);
    }
    if ev.fp == 0 && ev.fn_ == 0 {
        0
    } else {
        1
    }
}

fn cmd_probe(wasms: &[String]) -> i32 {
    let mut rows: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut total = 0usize;
    for w in wasms {
        if !std::path::Path::new(w).exists() {
            eprintln!("skip (no file): {}", w);
            continue;
        }
        let verdicts = probe_wasm_file(w);
        if verdicts.is_empty() {
            eprintln!("skip (no spec): {}", w);
            continue;
        }
        let label = std::path::Path::new(w).file_stem().unwrap().to_string_lossy().into_owned();
        let f = report::findings(&verdicts);
        total += f.len();
        rows.push((label, verdicts.len(), f));
    }
    println!("\n=== summary ===");
    for (label, n, f) in &rows {
        let flag = if f.is_empty() { "clean".to_string() } else { f.join(", ") };
        println!("  {:<30} {:>2} probes  ->  {}", label, n, flag);
    }
    println!("\n{} contracts probed, {} finding(s)", rows.len(), total);
    0
}

/// Acquire a public contract read-only (fetch WASM + spec via the stellar CLI)
/// and probe a local fork. Never touches the deployed contract.
/// Network passphrase hash (sha256) — mainnet / testnet, hardcoded constants.
fn network_id(network: &str) -> [u8; 32] {
    match network {
        "mainnet" | "public" => [
            0x7a, 0xc3, 0x39, 0x97, 0x54, 0x4e, 0x31, 0x75, 0xd2, 0x66, 0xbd, 0x02, 0x24, 0x39,
            0xb2, 0x2c, 0xdb, 0x16, 0x50, 0x8c, 0x01, 0x16, 0x3f, 0x26, 0xe5, 0xcb, 0x2a, 0x3e,
            0x10, 0x45, 0xa9, 0x79,
        ],
        _ => [
            0xce, 0xe0, 0x30, 0x2d, 0x59, 0x84, 0x4d, 0x32, 0xbd, 0xca, 0x91, 0x5c, 0x82, 0x03,
            0xdd, 0x44, 0xb3, 0x3f, 0xbb, 0x7e, 0xdc, 0x19, 0x05, 0x1e, 0xa3, 0x7a, 0xbe, 0xdf,
            0x28, 0xec, 0xd4, 0x72,
        ],
    }
}

fn cmd_scan(id: &str, network: &str, fork: bool) -> i32 {
    let url = rpc::rpc_url(network);
    let verdicts = if fork {
        eprintln!("acquiring {} ({}) — STATE-FORK via RPC (real full on-chain state, lazy) ...", id, network);
        let (seq, _proto) = match rpc::latest_ledger(url) {
            Some(x) => x,
            None => {
                eprintln!("getLatestLedger failed");
                return 1;
            }
        };
        // fetch the wasm once for the ABI; the lazy source pulls code + real
        // state (balances, reserves, config) on demand during each probe.
        let wasm = match rpc::fetch_wasm(url, id) {
            Some(w) => w,
            None => {
                eprintln!("could not fetch wasm via RPC");
                return 1;
            }
        };
        let plan = abi::plan_from_wasm(&wasm);
        let li = soroban_sdk::testutils::LedgerInfo {
            // stamp with the host's own protocol (mainnet's live one may be newer).
            protocol_version: engine::host_protocol_version(),
            sequence_number: seq,
            timestamp: 0,
            network_id: network_id(network),
            base_reserve: 0,
            min_persistent_entry_ttl: 1,
            min_temp_entry_ttl: 1,
            max_entry_ttl: 6_312_000,
        };
        let source = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
        let mut v = engine::probe_forked_lazy(source, &li, id, &plan);
        // Role-capture pass: the event-delta breach probe flags "something changed"
        // and misses silent admin setters entirely. probe_hijack reads the admin
        // getter and confirms an attacker seizing control — a sharper, higher-severity
        // finding on the same forked state.
        let source_h = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
        v.extend(engine::probe_hijack(source_h, &li, id, &plan));
        // Temporal pass: the clock is an attacker. Flag one-shot guards that live
        // in temporary storage and evaporate past their TTL, reopening a replay.
        let source_r = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
        v.extend(engine::probe_replay(source_r, &li, id, &plan));
        v
    } else {
        eprintln!("acquiring {} ({}) — read-only via RPC ...", id, network);
        let wasm = match rpc::fetch_wasm(url, id) {
            Some(w) => w,
            None => {
                eprintln!("could not fetch wasm via RPC (bad id, not found, or RPC error)");
                return 1;
            }
        };
        let plan = abi::plan_from_wasm(&wasm);
        if plan.is_empty() {
            eprintln!("no contract spec found in fetched wasm");
            return 1;
        }
        engine::probe_contract(&wasm, ATTACKER, &plan)
    };

    println!("\n{}: {} probes{}", id, verdicts.len(), if fork { " (state-fork)" } else { "" });
    for v in &verdicts {
        println!("  [{:<7}] {}({})  {}", report::mark(&v.verdict), v.fn_name, v.arg_types, v.detail);
    }
    if !report::findings(&verdicts).is_empty() {
        if fork {
            println!("\nNOTE: probed against real forked state — findings are CONFIRMED, not fresh-deploy candidates. Disclose responsibly; the fork is local, the live contract was never touched.");
        } else {
            println!("\nNOTE: fresh-deploy probing. A finding here is a CANDIDATE — re-run with --fork (real state) before any disclosure. Never touch the live contract.");
        }
    }
    0
}

/// Supply-chain scan: read the contract's soroban-sdk version from its WASM meta
/// and cross-reference the confirmed CVE table. The check no logic scanner runs.
fn cmd_cve(id: &str, network: &str) -> i32 {
    let url = rpc::rpc_url(network);
    let wasm = match rpc::fetch_wasm(url, id) {
        Some(w) => w,
        None => {
            eprintln!("could not fetch wasm via RPC (SAC, archived instance, or bad id)");
            return 1;
        }
    };
    let sdkver = match cve::sdk_version_from_wasm(&wasm) {
        Some(v) => v,
        None => {
            println!("{}: no rssdkver in contractmetav0 (SAC or meta stripped) — cannot fingerprint", id);
            return 0;
        }
    };
    let hits = cve::exposure(&sdkver);
    println!("{}", id);
    println!("  soroban-sdk: {}", sdkver);
    if hits.is_empty() {
        println!("  CVE exposure: none — SDK version is at or past every patched line.");
        return 0;
    }
    println!("  CVE exposure ({} advisory/ies, by version — NECESSARY not sufficient):", hits.len());
    for c in &hits {
        println!("    [{}] {}", c.sev, c.id);
        println!("        {}", c.what);
        println!("        exploitable only if: {}", c.needs);
    }
    println!("\nNOTE: version-vulnerable flags EXPOSURE. Confirm the code pattern above (or run a\ndynamic probe) before disclosure. WASM read only — the live contract was never touched.");
    0
}

/// Spike: identify a contract's tokens and read its REAL holdings in the fork —
/// the value-measurement primitive the economic drain detector is built on.
fn cmd_econ(id: &str, network: &str) -> i32 {
    let url = rpc::rpc_url(network);
    let seq = match rpc::latest_ledger(url) {
        Some((s, _)) => s,
        None => {
            eprintln!("getLatestLedger failed");
            return 1;
        }
    };
    let entries = match rpc::fetch_snapshot_entries(url, id) {
        Some(e) => e,
        None => {
            eprintln!("could not fetch instance via RPC");
            return 1;
        }
    };
    let wasm = match rpc::fetch_wasm(url, id) {
        Some(w) => w,
        None => {
            eprintln!("could not fetch wasm via RPC");
            return 1;
        }
    };
    let plan = abi::plan_from_wasm(&wasm);
    let li = soroban_sdk::testutils::LedgerInfo {
        protocol_version: engine::host_protocol_version(),
        sequence_number: seq,
        timestamp: 0,
        network_id: network_id(network),
        base_reserve: 0,
        min_persistent_entry_ttl: 1,
        min_temp_entry_ttl: 1,
        max_entry_ttl: 6_312_000,
    };
    let source = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
    let env = engine::forked_env(source, &li);
    let tokens = econ::candidate_tokens(&env, id, entries[0].1 .0.as_ref(), &plan);
    eprintln!("candidate tokens (instance + getters): {:?}", tokens);
    println!("\n{} — token holdings (real forked state):", id);
    for t in &tokens {
        match engine::token_balance(&env, t, id) {
            Some(b) => println!("  holds {:>22} of {}", b, t),
            None => println!("  {}  (not a token / no balance())", t),
        }
    }

    let n_mut = plan.iter().filter(|p| p.synthesizable && !p.inputs.is_empty()).count();
    let source2 = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
    let drains = engine::probe_drain(source2, &li, id, &tokens, &plan);
    println!("\n=== economic drain probe ({} mutating fns, empty auth, real reserves) ===", n_mut);
    if drains.is_empty() {
        println!("  no drain — no mutating fn reduced the contract's real reserves under empty auth.");
    } else {
        for d in &drains {
            println!("  [DRAIN]  {}({})  {}", d.fn_name, d.arg_types, d.detail);
        }
    }

    // The authorized counterpart: the attacker signs, and we flag any fn that
    // pays the attacker unearned value (broken accounting / unchecked payout) —
    // the class the empty-auth drain probe reverts on and misses.
    let source3 = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
    let greed = engine::probe_greed(source3, &li, id, &tokens, &plan);
    println!("\n=== economic greed probe ({} mutating fns, attacker auth, real reserves) ===", n_mut);
    if greed.is_empty() {
        println!("  no greed — no mutating fn paid an authorizing attacker unearned value from a zero position.");
    } else {
        for g in &greed {
            println!("  [GREED]  {}({})  {}", g.fn_name, g.arg_types, g.detail);
        }
    }

    // Caller-supplied-address trust: an authorized caller redirects reserves to an
    // attacker-supplied recipient that never signed — the agent-payment injected-
    // recipient class greed misses when the contract forbids self-pay.
    let n_multi = plan
        .iter()
        .filter(|p| p.synthesizable && p.inputs.iter().filter(|t| *t == "address").count() >= 2)
        .count();
    let source4 = std::rc::Rc::new(fork::RpcSnapshotSource::new(url));
    let redirect = engine::probe_redirect(source4, &li, id, &tokens, &plan);
    println!("\n=== injected-recipient probe ({} multi-address fns, authorizer != recipient, real reserves) ===", n_multi);
    if redirect.is_empty() {
        println!("  no redirect — no fn paid the contract's reserves to an unbound attacker-supplied recipient.");
    } else {
        for r in &redirect {
            println!("  [REDIRECT]  {}({})  {}", r.fn_name, r.arg_types, r.detail);
        }
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("bench") => cmd_bench(),
        Some("econ") if args.len() > 1 => {
            let id = args[1].clone();
            let mut network = "mainnet".to_string();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--network" && i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            cmd_econ(&id, &network)
        }
        Some("cve") if args.len() > 1 => {
            let id = args[1].clone();
            let mut network = "mainnet".to_string();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--network" && i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            cmd_cve(&id, &network)
        }
        Some("probe") if args.len() > 1 => cmd_probe(&args[1..]),
        Some("scan") if args.len() > 1 => {
            let id = args[1].clone();
            let mut network = "testnet".to_string();
            let mut fork = false;
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--network" && i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else if args[i] == "--fork" {
                    fork = true;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            cmd_scan(&id, &network, fork)
        }
        _ => {
            eprintln!("usage: sorohunter <bench | probe <wasm...> | scan <id> [--network <net>] [--fork] | econ <id> | cve <id> [--network <net>]>");
            2
        }
    };
    std::process::exit(code);
}
