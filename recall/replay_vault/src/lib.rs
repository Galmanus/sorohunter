#![no_std]
//! Recall target for the "replay" detector — the archival-replay (temporal) attack.
//!
//! `claim` guards against a second claim with a "claimed" flag, but stores it in
//! TEMPORARY storage. When the temporary entry's TTL lapses the flag evaporates,
//! and the same caller can claim again. The attacker breaks nothing — they wait
//! for the clock. A correct contract would store the guard in PERSISTENT storage.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum DataKey {
    Claimed(Address),
}

#[contract]
pub struct ReplayVault;

#[contractimpl]
impl ReplayVault {
    pub fn claim(e: Env, caller: Address) {
        caller.require_auth();
        // VULN: one-shot guard in TEMPORARY storage — evaporates past its TTL.
        if e.storage().temporary().has(&DataKey::Claimed(caller.clone())) {
            panic!("already claimed");
        }
        e.storage().temporary().set(&DataKey::Claimed(caller), &true);
    }
}
