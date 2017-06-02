//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol.
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! shs = "0.1"
//! ```
#![warn(missing_docs)]

extern crate sodiumoxide;

use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;

mod crypto;
mod client;
mod server;

pub use client::*;
pub use server::*;

// TODO doc comment warning that this does not perform any encryption
// TODO warn that this conforms to the reference implementaiton, not to the spec
// (the reference implementation contains an error which is replicated here)
// TODO usage examples

/// The data resulting from a handshake: Keys and nonces suitable for encrypted
/// two-way communication with the peer via sodium boxes.
pub struct Outcome {
    /// A secret key for sealing boxes. The `decryption_key` of the peer's
    /// `Outcome` can be used to open these boxes.
    pub encryption_key: box_::SecretKey,
    /// A nonce for sealing boxes. The `decryption_nonce` of the peer's
    /// `Outcome` matches this one.
    pub encryption_nonce: box_::Nonce,
    /// A public key for opening boxes. It can decrypt boxes sealed with the
    /// `encryption_key` of the peer's `Outcome`.
    pub decryption_key: box_::PublicKey,
    /// A nonce for opening boxes. It matches the `encryption_nonce` of the
    /// peer's `Outcome`.
    pub decryption_nonce: box_::Nonce,
}
