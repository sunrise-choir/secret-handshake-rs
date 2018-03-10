//! Implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake)
//! protocol version 1.
//!
//! This library uses libsodium internally. In application code, call
//! [`sodiumoxide::init()`](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)
//! before performing any handshakes.

#![deny(missing_docs)]
extern crate sodiumoxide;
extern crate libc;
extern crate futures_core;
extern crate futures_io;

pub mod crypto;
pub mod errors;
mod client;
mod server;

pub use client::*;
pub use server::*;
pub use crypto::{Outcome, NETWORK_IDENTIFIER_BYTES};

#[cfg(test)]
extern crate async_ringbuffer;
#[cfg(test)]
extern crate atm_io_utils;
#[cfg(test)]
extern crate futures;

#[cfg(test)]
mod test;
