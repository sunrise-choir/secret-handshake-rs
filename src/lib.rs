//! Implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake)
//! protocol.
//!
//! This library uses libsodium internally. In application code, call
//! [`sodiumoxide::init()`](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)
//! before performing any handshakes.

#![deny(missing_docs)]
extern crate sodiumoxide;
extern crate libc;
extern crate futures;
#[macro_use]
extern crate tokio_io;
extern crate void;

pub mod crypto;
pub mod client;
pub mod server;

pub use crypto::Outcome;

#[cfg(test)]
extern crate partial_io;
#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
