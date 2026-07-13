#![no_std]
//! Fixture: the CORRECT counterpart to `unbound_account`, and the positive
//! control for the `--replay` prover. Same signature ABI (a 96-byte
//! `msg || sig` blob), same ed25519 verification, but it FIRST asserts that the
//! message carried in the signature equals the host's `signature_payload`. That
//! one line is the whole difference: it binds the signature to the bytes being
//! authorized, so a valid pair for payload A cannot authorize payload B.
//!
//! Why it is a distinct control from `good_account`: `good_account` takes a raw
//! `BytesN<64>` and would reject this fixture's 96-byte blob on a type mismatch,
//! which a skeptic could dismiss as "it only rejects because it can't parse."
//! `bound_account` parses the exact same blob `unbound_account` accepts and
//! still refuses the cross-payload replay — proving the prover reads the binding
//! bug specifically, not a parse failure.

use soroban_sdk::{
    auth::Context, contract, contracterror, contractimpl, symbol_short, Bytes, BytesN, Env,
    TryIntoVal, Val, Vec,
};

const PK: soroban_sdk::Symbol = symbol_short!("pk");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    BadSig = 1,
    Unbound = 2,
}

#[contract]
pub struct BoundAccount;

#[contractimpl]
impl BoundAccount {
    pub fn __constructor(env: Env, pubkey: BytesN<32>) {
        env.storage().instance().set(&PK, &pubkey);
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let blob: BytesN<96> = signature.try_into_val(&env).map_err(|_| Error::BadSig)?;
        let raw = blob.to_array();
        let msg_bytes: [u8; 32] = raw[0..32].try_into().unwrap();
        // THE FIX: bind the signed message to the payload being authorized.
        if msg_bytes != signature_payload.to_array() {
            return Err(Error::Unbound);
        }
        let msg = Bytes::from_array(&env, &msg_bytes);
        let sig_bytes: [u8; 64] = raw[32..96].try_into().unwrap();
        let sig = BytesN::<64>::from_array(&env, &sig_bytes);
        let pubkey: BytesN<32> = env.storage().instance().get(&PK).ok_or(Error::BadSig)?;
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        Ok(())
    }
}
