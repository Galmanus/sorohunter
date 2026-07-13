#![no_std]
//! Fixture: the AUTH-ARG SCOPE MISMATCH bug (TA-04). `pay(from, to, amount)`
//! authorizes `from` with `require_auth_for_args` scoped to ONLY `[from]` — the
//! recipient and amount are left OUT of the authorized scope. So a single
//! authorization the payer produces (binding only their identity) is valid for
//! ANY recipient and ANY amount: an attacker redirects the payment to themselves.
//! Its safe twin `scoped_safe` differs by one call: `from.require_auth()`, which
//! binds the full invocation args.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, IntoVal, Val, Vec};

#[contracttype]
enum Key {
    Bal(Address),
}

#[contract]
pub struct ScopedVuln;

#[contractimpl]
impl ScopedVuln {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let b: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(b + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage().persistent().get(&Key::Bal(id)).unwrap_or(0)
    }

    pub fn pay(env: Env, from: Address, to: Address, amount: i128) {
        // THE BUG: scope the authorization to only `from`, omitting `to`/`amount`.
        let mut scope: Vec<Val> = Vec::new(&env);
        scope.push_back(from.clone().into_val(&env));
        from.require_auth_for_args(scope);

        let fb: i128 = env.storage().persistent().get(&Key::Bal(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(from), &(fb - amount));
        let tb: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(tb + amount));
    }
}
