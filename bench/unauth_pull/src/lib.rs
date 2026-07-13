#![no_std]
//! Fixture: the UNRESTRICTED-`transfer_from` bug (Scout's `unrestricted-transfer-from`
//! class, but as an EXECUTED value loss). The contract holds an allowance from a
//! victim who once approved it, and exposes `pull(from, amount)` that calls
//! `token.transfer_from(self, from, self, amount)` — WITHOUT `from.require_auth()`.
//!
//! Consequence: anyone can call `pull` and make the contract spend the victim's
//! standing allowance at an attacker-chosen time, moving the victim's real tokens
//! with no signature from the victim. The token itself is satisfied: the spender
//! is this contract, which authorizes its own sub-invocation implicitly. The
//! missing check is the contract-level `from.require_auth()`.
//!
//! Its safe twin `auth_pull` adds exactly that one line. The prover
//! (`harness --allowance`) must drain the victim here and be held on the twin.

use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, Symbol};

const TOKEN: Symbol = symbol_short!("token");

#[contract]
pub struct UnauthPull;

#[contractimpl]
impl UnauthPull {
    pub fn __constructor(env: Env, token: Address) {
        env.storage().instance().set(&TOKEN, &token);
    }

    pub fn pull(env: Env, from: Address, amount: i128) {
        let token: Address = env.storage().instance().get(&TOKEN).unwrap();
        let client = token::TokenClient::new(&env, &token);
        let me = env.current_contract_address();
        // THE BUG: no `from.require_auth()`. The victim's approved balance is
        // pulled on anyone's call.
        client.transfer_from(&me, &from, &me, &amount);
    }
}
