#![no_std]
//! Benchmark decoy for TP-01: the same upgrade entry point, properly gated.
//! `upgrade` requires the admin's auth; with admin unset it aborts under empty
//! auth, so the code swap never lands. The TP-01 false-positive control.

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
}

#[contract]
pub struct SafeUpgradeVault;

#[contractimpl]
impl SafeUpgradeVault {
    /// Gated upgrade: only the admin can swap code. Aborts under empty auth.
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm);
    }

    pub fn ping(env: Env) -> u32 {
        let _ = &env;
        1
    }
}
