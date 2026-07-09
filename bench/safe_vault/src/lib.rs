#![no_std]
//! Benchmark decoy: the same vault, correctly authorized. `withdraw` calls
//! `require_auth` before touching state, so under empty auth it aborts. Nothing
//! here should be flagged — it is the false-positive control.

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
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    pub fn deposit(env: Env, who: Address, amount: i128) {
        who.require_auth();
        let k = DataKey::Bal(who);
        let b: i128 = env.storage().persistent().get(&k).unwrap_or(0);
        env.storage().persistent().set(&k, &(b + amount));
    }

    /// Correctly authorized: only `to` can move `to`'s funds.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        to.require_auth();
        let k = DataKey::Bal(to.clone());
        let b: i128 = env.storage().persistent().get(&k).unwrap_or(0);
        env.storage().persistent().set(&k, &(b - amount));
        Withdraw { to, amount }.publish(&env);
    }

    pub fn balance(env: Env, who: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Bal(who)).unwrap_or(0)
    }
}
