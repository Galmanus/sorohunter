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

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::Value;

/// The attacker payload for the upgrade detector, embedded so the binary is
/// self-contained.
const ATTACKER: &[u8] = include_bytes!("../assets/attacker_pwn.wasm");

/// Read a contract's spec via the stellar CLI (stage-1 acquisition; a native
/// spec-from-wasm parse is the next increment).
fn abi_entries(extra: &[&str]) -> Vec<Value> {
    let out = Command::new("stellar")
        .args(["contract", "info", "interface"])
        .args(extra)
        .args(["--output", "json"])
        .output();
    let stdout = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return Vec::new(),
    };
    // the CLI prints a status line before the JSON array
    match stdout.find('[') {
        Some(i) => serde_json::from_str::<Value>(&stdout[i..])
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

fn probe_wasm_file(path: &str) -> Vec<engine::Verdict> {
    let entries = abi_entries(&["--wasm", path]);
    let plan = abi::parse_spec(&entries);
    let wasm = std::fs::read(path).unwrap_or_default();
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("bench") => cmd_bench(),
        Some("probe") if args.len() > 1 => cmd_probe(&args[1..]),
        _ => {
            eprintln!("usage: sorohunter <bench | probe <wasm...>>");
            2
        }
    };
    std::process::exit(code);
}
