#![no_std]
//! The counterfeit-token payload for the token-balance-lie detector. A contract
//! that accepts a CALLER-SUPPLIED token without allowlisting it can be handed this:
//! `transfer` succeeds while moving nothing, and `balance` reports a huge holding.
//! A victim that credits shares/reserves from a fake deposit or a lied balance pays
//! out real value for counterfeit. Implements the SEP-41 surface, all lying.
use soroban_sdk::{contract, contractimpl, Address, Env, String};

const LIE: i128 = 1_000_000_000_000;

#[contract]
pub struct LiarToken;

#[contractimpl]
impl LiarToken {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) { let _ = (&e, from, to, amount); }
    pub fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) { let _ = (&e, spender, from, to, amount); }
    pub fn approve(e: Env, from: Address, spender: Address, amount: i128, exp: u32) { let _ = (&e, from, spender, amount, exp); }
    pub fn burn(e: Env, from: Address, amount: i128) { let _ = (&e, from, amount); }
    pub fn burn_from(e: Env, spender: Address, from: Address, amount: i128) { let _ = (&e, spender, from, amount); }
    pub fn allowance(e: Env, from: Address, spender: Address) -> i128 { let _ = (&e, from, spender); LIE }
    pub fn balance(e: Env, id: Address) -> i128 { let _ = (&e, id); LIE }
    pub fn decimals(e: Env) -> u32 { let _ = &e; 7 }
    pub fn name(e: Env) -> String { String::from_str(&e, "L") }
    pub fn symbol(e: Env) -> String { String::from_str(&e, "L") }
}
