#![no_std]
//! Benchmark target for the COMPOSITION detector (TE-01 / SK-C01).
//!
//! Neither function is a single-probe finding — the vault looks CLEAN to TA-01:
//!   - `set_admin` mutates state under empty auth but emits NO event, so the
//!     event-diff single-fn probe classes it as a read-only `view` (a false
//!     negative for the foothold — exactly why composition is needed).
//!   - `withdraw` is admin-gated (`admin.require_auth()`), so under empty auth,
//!     with admin unset, it aborts (`held`).
//!
//! The CHAIN [set_admin(attacker) -> withdraw] drains it: seize admin with no
//! signature (TA-02 foothold), then drain the pot through the legit gate
//! (TE-01), realizing OBJ-DRAIN. No constructor, so the generic harness deploys
//! it with ().

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
pub struct ChainVault;

#[contractimpl]
impl ChainVault {
    /// FOOTHOLD (TA-02): sets admin with NO `require_auth`, emits NO event.
    /// Invisible to the event-diff single-fn probe (classed `view`).
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    /// Admin-gated drain (TE-01 target). Aborts if admin unset (baseline) or the
    /// caller is not the stored admin.
    pub fn withdraw(env: Env, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let pot: i128 = env.storage().instance().get(&DataKey::Pot).unwrap_or(1_000_000);
        env.storage().instance().set(&DataKey::Pot, &(pot - amount));
        Withdraw { amount }.publish(&env);
    }

    /// Read-only view: the pot balance. Control — must not be flagged.
    pub fn pot(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Pot).unwrap_or(1_000_000)
    }
}
