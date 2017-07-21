//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol.

// #![deny(missing_docs)]
extern crate sodiumoxide;
extern crate libc;

mod crypto;
mod client;
mod server;

pub use client::*;
pub use server::*;

#[cfg(test)]
extern crate partial_io;
#[cfg(test)]
mod test;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;

// TODO return Outcomes instead of Unit

// TODO doc comment warning that this does not perform any encryption
// TODO warn that this conforms to the reference implementation, not to the spec
// (the reference implementation contains an error which is replicated here)
// TODO usage examples
