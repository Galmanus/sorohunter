#![no_std]
//! Fixture: the CORRECT counterpart to `fee_vault_vuln`, and the false-positive
//! control. Identical deposit path, but it credits the **measured balance delta**
//! (balance_after - balance_before) instead of the `amount` argument — so a
//! deflationary token credits exactly what arrived, and internal accounting can
//! never exceed the real token balance. The prover must be `held` here.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum Key {
    Token,
    Credit(Address),
}

#[contract]
pub struct FeeVaultSafe;

#[contractimpl]
impl FeeVaultSafe {
    pub fn __constructor(env: Env, token: Address) {
        env.storage().instance().set(&Key::Token, &token);
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        let token: Address = env.storage().instance().get(&Key::Token).unwrap();
        let me = env.current_contract_address();
        let client = token::TokenClient::new(&env, &token);
        let before = client.balance(&me);
        client.transfer_from(&me, &from, &me, &amount);
        let after = client.balance(&me);
        // THE FIX: credit what actually arrived.
        let received = after - before;
        let c: i128 = env.storage().persistent().get(&Key::Credit(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Credit(from), &(c + received));
    }

    pub fn credit(env: Env, id: Address) -> i128 {
        env.storage().persistent().get(&Key::Credit(id)).unwrap_or(0)
    }
}
