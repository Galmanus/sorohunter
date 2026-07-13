#![no_std]
//! Fixture: a deflationary / fee-on-transfer token. `transfer_from` debits the
//! full `amount` from `from` but credits `to` only `amount - fee` — the fee is
//! skimmed. A contract that assumes it received the full `amount` (rather than
//! measuring its real balance delta) will over-credit. This is the token side of
//! the accounting bug found in a real Soroban bridge audit (Coinspect Tricorn
//! TRI-005). Minimal SEP-41-ish surface: mint / balance / transfer_from.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum Key {
    Bal(Address),
    Fee,
}

#[contract]
pub struct FeeToken;

#[contractimpl]
impl FeeToken {
    /// fee_bps: skim in basis points (e.g. 1000 = 10%).
    pub fn __constructor(env: Env, fee_bps: u32) {
        env.storage().instance().set(&Key::Fee, &fee_bps);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let b: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(b + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage().persistent().get(&Key::Bal(id)).unwrap_or(0)
    }

    pub fn approve(_env: Env, _from: Address, _spender: Address, _amount: i128, _exp: u32) {}

    pub fn transfer_from(env: Env, _spender: Address, from: Address, to: Address, amount: i128) {
        let fee_bps: u32 = env.storage().instance().get(&Key::Fee).unwrap_or(0);
        let delivered = amount - amount * (fee_bps as i128) / 10_000;
        let fb: i128 = env.storage().persistent().get(&Key::Bal(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(from), &(fb - amount));
        let tb: i128 = env.storage().persistent().get(&Key::Bal(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&Key::Bal(to), &(tb + delivered));
    }
}
