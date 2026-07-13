#![no_std]
//! Fixture: the CORRECT counterpart to `scoped_vuln`, and the false-positive
//! control for the TA-04 prover. Identical `pay`, but it authorizes `from` with
//! `require_auth()` — which binds the FULL invocation args `(from, to, amount)`.
//! So an authorization for paying one recipient a given amount cannot be replayed
//! to pay a different recipient. Under the prover's `[from]`-scoped mock the full
//! auth is unsatisfied, so the redirected call reverts and the prover is `held`.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum Key {
    Bal(Address),
}

#[contract]
pub struct ScopedSafe;

#[contractimpl]
impl ScopedSafe {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let b: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(b + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage().persistent().get(&Key::Bal(id)).unwrap_or(0)
    }

    pub fn pay(env: Env, from: Address, to: Address, amount: i128) {
        // THE FIX: bind the authorization to the full invocation (from, to, amount).
        from.require_auth();

        let fb: i128 = env.storage().persistent().get(&Key::Bal(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(from), &(fb - amount));
        let tb: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(tb + amount));
    }
}
