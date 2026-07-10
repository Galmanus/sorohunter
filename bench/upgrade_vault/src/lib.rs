#![no_std]
//! Benchmark target for the PERSISTENCE detector (TP-01 unprotected upgrade).
//!
//! `upgrade` swaps the contract's own code with NO `require_auth`, so anyone can
//! replace the logic with theirs and take total control. It is invisible to the
//! single-fn probe: called with a zero hash under empty auth, the swap errors
//! (no such wasm) and the probe classes it `held`. Only the TP-01 detector —
//! which uploads a real attacker wasm and passes its hash — confirms the hijack
//! by swapping the code and calling the attacker's marker. No constructor.

use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct UpgradeVault;

#[contractimpl]
impl UpgradeVault {
    /// PLANTED VULN (TP-01): no `require_auth` on a code swap.
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm);
    }

    pub fn ping(env: Env) -> u32 {
        let _ = &env;
        1
    }
}
