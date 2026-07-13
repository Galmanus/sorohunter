#![no_std]
//! Fixture: the CORRECT counterpart to `unauth_pull`, and the false-positive
//! control for the `harness --allowance` prover. Identical `transfer_from` on a
//! victim's standing allowance, but it FIRST asserts `from.require_auth()` — so
//! the victim's tokens move only on the victim's own authorization. Under the
//! prover's empty-auth probe the victim never signs, so this reverts and the
//! prover must report `held`. If it ever drains, the prover is broken.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, Symbol};

const TOKEN: Symbol = symbol_short!("token");

#[contract]
pub struct AuthPull;

#[contractimpl]
impl AuthPull {
    pub fn __constructor(env: Env, token: Address) {
        env.storage().instance().set(&TOKEN, &token);
    }

    pub fn pull(env: Env, from: Address, amount: i128) {
        // THE FIX: the account whose funds move must authorize this call.
        from.require_auth();
        let token: Address = env.storage().instance().get(&TOKEN).unwrap();
        let client = token::TokenClient::new(&env, &token);
        let me = env.current_contract_address();
        client.transfer_from(&me, &from, &me, &amount);
    }
}
