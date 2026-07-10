#![no_std]
//! Recall target for the "roundtrip" (value-conservation) detector. `unstake` pays
//! back 101% of the stake — a legitimate stake->unstake round-trip mints 1% free
//! value out of the vault's real reserves. Broken math, no attack pattern.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum Key { Token, Staked(Address) }

#[contract]
pub struct StakeVault;

#[contractimpl]
impl StakeVault {
    pub fn __constructor(e: Env, token: Address) { e.storage().instance().set(&Key::Token, &token); }
    pub fn stake(e: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let t: Address = e.storage().instance().get(&Key::Token).unwrap();
        token::Client::new(&e, &t).transfer(&caller, &e.current_contract_address(), &amount);
        let s: i128 = e.storage().persistent().get(&Key::Staked(caller.clone())).unwrap_or(0);
        e.storage().persistent().set(&Key::Staked(caller), &(s + amount));
    }
    pub fn unstake(e: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let s: i128 = e.storage().persistent().get(&Key::Staked(caller.clone())).unwrap_or(0);
        if amount > s { panic!("over-unstake"); }
        e.storage().persistent().set(&Key::Staked(caller.clone()), &(s - amount));
        let t: Address = e.storage().instance().get(&Key::Token).unwrap();
        token::Client::new(&e, &t).transfer(&e.current_contract_address(), &caller, &(amount * 101 / 100));
    }
}
