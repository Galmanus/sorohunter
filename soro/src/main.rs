//! sorohunter — single-binary Rust consolidation (WIP).
//!
//! Replaces the Python orchestration (abi/cli/report) with one static binary so
//! the autonomous continuous scanner runs in-process (no subprocess-per-probe)
//! and with no Python runtime. Ported incrementally from the Python + the
//! `../harness` fork-sim engine. Currently: the ABI module (`abi.rs`), tested.
//! Next: the engine (probe/chain/upgrade), report, and the CLI (bench/probe/scan).

#![allow(dead_code)]

mod abi;

fn main() {
    eprintln!("sorohunter (rust consolidation, WIP): abi module ported + tested. engine/report/cli next.");
}
