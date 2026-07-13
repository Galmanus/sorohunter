#![no_std]
//! Fixture: the PASSKEY-CLASS bug. `__check_auth` verifies a real ed25519
//! signature and rejects any forgery, so the blob battery (`--checkauth`) finds
//! NOTHING on it. Its bug is subtler and is the one that matters for passkey
//! wallets: it verifies the signature over a message CARRIED INSIDE the
//! signature blob, and never checks that that message equals the host's
//! `signature_payload` (the actual thing being authorized).
//!
//! Disanalogy with `blind_account`/`void_guard`: those ignore the signature.
//! This one verifies it correctly, but against the wrong bytes. It is the
//! executable analogue of a passkey wallet that reconstructs `clientDataJSON`
//! from attacker-supplied fields and verifies the assertion against THAT instead
//! of binding it to the challenge the protocol demanded (cf. swig-wallet #143).
//!
//! Consequence: one legitimate `(msg, sig)` pair the user ever produced — which
//! is observable on-chain — can be replayed to authorize a DIFFERENT payload.
//!
//! Signature ABI (shared with `bound_account`): a 96-byte blob,
//! `msg[0..32] || sig[32..96]`.

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
}

#[contract]
pub struct UnboundAccount;

#[contractimpl]
impl UnboundAccount {
    pub fn __constructor(env: Env, pubkey: BytesN<32>) {
        env.storage().instance().set(&PK, &pubkey);
    }

    #[allow(non_snake_case)]
    pub fn __check_auth(
        env: Env,
        _signature_payload: BytesN<32>,
        signature: Val,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let blob: BytesN<96> = signature.try_into_val(&env).map_err(|_| Error::BadSig)?;
        let raw = blob.to_array();
        let msg_bytes: [u8; 32] = raw[0..32].try_into().unwrap();
        let sig_bytes: [u8; 64] = raw[32..96].try_into().unwrap();
        let msg = Bytes::from_array(&env, &msg_bytes);
        let sig = BytesN::<64>::from_array(&env, &sig_bytes);
        let pubkey: BytesN<32> = env.storage().instance().get(&PK).ok_or(Error::BadSig)?;
        // Verifies the signature over the message the SIGNATURE carries...
        env.crypto().ed25519_verify(&pubkey, &msg, &sig);
        // ...and never checks `msg == _signature_payload`. THE BUG.
        Ok(())
    }
}
