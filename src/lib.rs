//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol.
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! shs = "0.1"
//! ```
#![warn(missing_docs)]

extern crate sodiumoxide;
extern crate libc;

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
