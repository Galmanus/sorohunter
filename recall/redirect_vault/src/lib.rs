#![no_std]
//! Recall target for the "redirect" detector (TA-05, caller-supplied-address
//! trust / injected-recipient — the agent-payment class).
//!
//! `pay` authenticates the `operator` and even forbids self-pay, but sends the
//! vault's reserves to an arbitrary `recipient` it never binds auth to. The
//! self-pay guard is exactly what makes the `greed` detector (which injects one
//! attacker into every address slot) revert and stay silent — while a decoupled
//! authorizer/recipient injection drains it. `token()` is the getter the detector
//! uses to find the reserve token.
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
enum DataKey {
    Token,
}

#[contract]
pub struct RedirectVault;

#[contractimpl]
impl RedirectVault {
    pub fn __constructor(e: Env, token: Address) {
        e.storage().instance().set(&DataKey::Token, &token);
    }

    pub fn token(e: Env) -> Address {
        e.storage().instance().get(&DataKey::Token).unwrap()
    }

    // VULN: operator is authenticated and self-pay is blocked, but `recipient` is
    // never bound — an authorized caller redirects reserves to any address.
    pub fn pay(e: Env, operator: Address, recipient: Address, amount: i128) {
        operator.require_auth();
        if operator == recipient {
            panic!("no self-pay");
        }
        let token: Address = e.storage().instance().get(&DataKey::Token).unwrap();
        token::Client::new(&e, &token).transfer(&e.current_contract_address(), &recipient, &amount);
    }
}
