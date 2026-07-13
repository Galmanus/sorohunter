#![no_std]
//! Fixture: the FEE-ON-TRANSFER ACCOUNTING BUG (Coinspect Tricorn TRI-005 class).
//! `deposit` pulls `amount` via the token and credits the depositor `amount` in
//! its own ledger — trusting the argument instead of measuring what actually
//! arrived. Against a deflationary token the vault receives less than `amount`
//! but credits the full `amount`, so its internal accounting exceeds its real
//! token balance: it is now insolvent, and a depositor can withdraw more than
//! the vault truly holds.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum Key {
    Token,
    Credit(Address),
}

#[contract]
pub struct FeeVaultVuln;

#[contractimpl]
impl FeeVaultVuln {
    pub fn __constructor(env: Env, token: Address) {
        env.storage().instance().set(&Key::Token, &token);
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        let token: Address = env.storage().instance().get(&Key::Token).unwrap();
        let me = env.current_contract_address();
        token::TokenClient::new(&env, &token).transfer_from(&me, &from, &me, &amount);
        // THE BUG: credit the argument, not the amount actually received.
        let c: i128 = env.storage().persistent().get(&Key::Credit(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Credit(from), &(c + amount));
    }

    pub fn credit(env: Env, id: Address) -> i128 {
        env.storage().persistent().get(&Key::Credit(id)).unwrap_or(0)
    }
}
