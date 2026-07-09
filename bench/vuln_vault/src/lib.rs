#![no_std]
//! Benchmark target: a vault with a PLANTED missing-auth bug.
//!
//! `deposit` is correctly authorized. `withdraw` is the vuln: it mutates state
//! and emits an event with NO `require_auth`, so anyone can drain anyone.
//! `balance` is a read-only view (no auth, no event) — the control that must
//! NOT be flagged. No constructor, so the generic harness deploys it with ().

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Bal(Address),
}

#[contractevent(topics = ["withdraw"])]
pub struct Withdraw {
    pub to: Address,
    pub amount: i128,
}

#[contract]
pub struct VulnVault;

#[contractimpl]
impl VulnVault {
    pub fn deposit(env: Env, who: Address, amount: i128) {
        who.require_auth();
        let k = DataKey::Bal(who);
        let b: i128 = env.storage().persistent().get(&k).unwrap_or(0);
        env.storage().persistent().set(&k, &(b + amount));
    }

    /// PLANTED VULN: no `require_auth`. A state change + event with no signature.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let k = DataKey::Bal(to.clone());
        let b: i128 = env.storage().persistent().get(&k).unwrap_or(0);
        env.storage().persistent().set(&k, &(b - amount));
        Withdraw { to, amount }.publish(&env);
    }

    /// Read-only view: no auth, no event, no state change. Must not be a finding.
    pub fn balance(env: Env, who: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Bal(who)).unwrap_or(0)
    }
}
