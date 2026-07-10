#![no_std]
//! The attacker payload for the TP-01 detector. If a contract's code can be
//! swapped for this under empty auth, the upgrade hijack is confirmed by calling
//! `pwned()` on the victim's address and getting the marker 1337 back. Not a
//! benchmark target (not in ground_truth) — just the proof-of-control payload.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct AttackerPwn;

#[contractimpl]
impl AttackerPwn {
    pub fn pwned(env: Env) -> u32 {
        let _ = &env;
        1337
    }
}
