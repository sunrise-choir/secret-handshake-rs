//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol version 1.
//! Unlike the reference implementation, this crate only performs the handshake, but no further encryption.

#![deny(missing_docs)]
extern crate sodiumoxide;
extern crate libc;

pub mod crypto;
mod client;
mod server;

pub use client::*;
pub use server::*;
pub use crypto::Outcome;

#[cfg(test)]
extern crate partial_io;
#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;

// TODO usage examples
