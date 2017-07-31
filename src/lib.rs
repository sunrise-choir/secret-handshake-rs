//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol version 1.
//! Also provides convenient functions to create [box-streams](https://docs.rs/box_stream) from the outcome of a handshake.

#![warn(missing_docs)]
extern crate sodiumoxide;
extern crate libc;
extern crate futures;
extern crate tokio_io;
extern crate box_stream;

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
