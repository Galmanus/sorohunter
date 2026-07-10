#![no_std]
//! Benchmark decoy for the COMPOSITION detector: the SAME shape as chain_vault,
//! but the admin setter is properly gated. `set_admin` requires the CURRENT
//! admin's auth, so under empty auth (admin unset) it aborts — the foothold
//! fails, so the chain [set_admin -> withdraw] never establishes. This is the
//! composition false-positive control: the detector must NOT flag it.

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Pot,
}

#[contractevent(topics = ["withdraw"])]
pub struct Withdraw {
    pub amount: i128,
}

#[contract]
pub struct SafeChainVault;

#[contractimpl]
impl SafeChainVault {
    /// Gated setter: only the current admin can rotate admin. Under empty auth
    /// (admin unset) this aborts, so no foothold is available.
    pub fn set_admin(env: Env, new_admin: Address) {
        let cur: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        cur.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    pub fn withdraw(env: Env, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let pot: i128 = env.storage().instance().get(&DataKey::Pot).unwrap_or(1_000_000);
        env.storage().instance().set(&DataKey::Pot, &(pot - amount));
        Withdraw { amount }.publish(&env);
    }

    pub fn pot(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Pot).unwrap_or(1_000_000)
    }
}
