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
mod engine;
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
fn cmd_scan(id: &str, network: &str) -> i32 {
    eprintln!("acquiring {} ({}) — read-only via RPC ...", id, network);
    // native: fetch the WASM over Soroban RPC (getLedgerEntries), no stellar CLI.
    let wasm = match rpc::fetch_wasm(rpc::rpc_url(network), id) {
        Some(w) => w,
        None => {
            eprintln!("could not fetch wasm via RPC (bad id, not found, or RPC error)");
            return 1;
        }
    };
    // native: ABI straight from the fetched WASM's custom section.
    let plan = abi::plan_from_wasm(&wasm);
    if plan.is_empty() {
        eprintln!("no contract spec found in fetched wasm");
        return 1;
    }
    let verdicts = engine::probe_contract(&wasm, ATTACKER, &plan);

    println!("\n{}: {} probes", id, verdicts.len());
    for v in &verdicts {
        println!("  [{:<7}] {}({})  {}", report::mark(&v.verdict), v.fn_name, v.arg_types, v.detail);
    }
    if !report::findings(&verdicts).is_empty() {
        println!(
            "\nNOTE: fresh-deploy probing. A finding here is a CANDIDATE — confirm against \
             a state-fork before any disclosure. Never touch the live contract."
        );
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("bench") => cmd_bench(),
        Some("probe") if args.len() > 1 => cmd_probe(&args[1..]),
        Some("scan") if args.len() > 1 => {
            let id = args[1].clone();
            let mut network = "testnet".to_string();
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--network" && i + 1 < args.len() {
                    network = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            cmd_scan(&id, &network)
        }
        _ => {
            eprintln!("usage: sorohunter <bench | probe <wasm...> | scan <id> [--network <net>]>");
            2
        }
    };
    std::process::exit(code);
}
