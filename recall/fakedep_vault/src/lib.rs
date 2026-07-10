#![no_std]
//! Recall target for the "counterfeit" detector — token-balance-lie / fake-deposit.
//!
//! `deposit` "receives" a caller-supplied token and pays the user the same amount
//! from its REAL reserve, with no allowlist. An attacker passes a counterfeit token
//! whose transfer moves nothing; the vault pays out real reserve for a phantom
//! deposit. "Everything that communicates is attack surface": the token contract's
//! behavior is trusted.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum Key { Reserve }

#[contract]
pub struct FakeDepositVault;

#[contractimpl]
impl FakeDepositVault {
    pub fn __constructor(e: Env, reserve: Address) {
        e.storage().instance().set(&Key::Reserve, &reserve);
    }
    pub fn deposit(e: Env, user: Address, dep_token: Address, amount: i128) {
        user.require_auth();
        // VULN: no allowlist on dep_token — a counterfeit's transfer is a no-op.
        token::Client::new(&e, &dep_token).transfer(&user, &e.current_contract_address(), &amount);
        let reserve: Address = e.storage().instance().get(&Key::Reserve).unwrap();
        token::Client::new(&e, &reserve).transfer(&e.current_contract_address(), &user, &amount);
    }
}
