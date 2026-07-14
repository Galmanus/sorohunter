#![no_std]
//! Fixture: a SEQUENCE-DEPENDENT breach. `fire` mutates state and emits an event
//! under empty auth — but ONLY after `arm` has been called. Probed alone, `fire`
//! reverts (not armed) and looks safe (held). Only a stateful fuzzer that finds
//! the sequence arm() -> fire() triggers the breach. This is what single-shot
//! probing structurally cannot find.
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
const ARMED: Symbol = symbol_short!("armed");
const LOOT: Symbol = symbol_short!("loot");
#[contract]
pub struct SeqVuln;
#[contractimpl]
impl SeqVuln {
    pub fn arm(env: Env) {
        env.storage().instance().set(&ARMED, &true);
    }
    pub fn fire(env: Env) {
        let armed: bool = env.storage().instance().get(&ARMED).unwrap_or(false);
        if !armed {
            panic!("not armed");
        }
        env.storage().instance().set(&LOOT, &true);
        env.events().publish((symbol_short!("fired"),), true); // state change, no signature
    }
}
