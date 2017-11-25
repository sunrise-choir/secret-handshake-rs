#![feature(drop_types_in_const)] // only for tests

//! Implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake)
//! protocol version 1.
//!
//! This library uses libsodium internally. In application code, call
//! [`sodiumoxide::init()`](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)
//! before performing any handshakes.

#![deny(missing_docs)]
extern crate sodiumoxide;
extern crate libc;
extern crate futures;
extern crate tokio_io;
extern crate void;
#[macro_use]
extern crate atm_io_utils;

pub mod crypto;
mod client;
mod server;

pub use client::*;
pub use server::*;
pub use crypto::{Outcome, NETWORK_IDENTIFIER_BYTES};

#[cfg(test)]
extern crate partial_io;
#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[cfg(test)]
extern crate async_ringbuffer;
#[cfg(test)]
extern crate rand;
