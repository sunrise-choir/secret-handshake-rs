#![feature(drop_types_in_const)]
// This file serves both as an example of using the `ClientHandshaker` struct, and as the client test executable for the [shs1 testsuite](https://github.com/AljoschaMeyer/shs1-testsuite).
extern crate secret_handshake;
extern crate futures;
extern crate tokio_io;
extern crate sodiumoxide;
extern crate atm_io_utils;

use std::env;
use std::io::Write;

use sodiumoxide::crypto::{box_, sign, secretbox};
use tokio_io::io::AllowStdIo;
use futures::Future;
use atm_io_utils::Duplex;
use secret_handshake::*;

static CLIENT_LONGTERM_PK: sign::PublicKey =
    sign::PublicKey([225, 162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245,
                     198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]);
static CLIENT_LONGTERM_SK: sign::SecretKey =
    sign::SecretKey([243, 168, 6, 50, 44, 78, 192, 183, 210, 241, 189, 36, 183, 154, 132, 119,
                     115, 84, 47, 151, 32, 32, 26, 237, 64, 180, 69, 20, 95, 133, 92, 176, 225,
                     162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245, 198,
                     79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]);
static CLIENT_EPHEMERAL_PK: box_::PublicKey =
    box_::PublicKey([79, 79, 77, 238, 254, 215, 129, 197, 235, 41, 185, 208, 47, 32, 146, 37,
                     255, 237, 208, 215, 182, 92, 201, 106, 85, 86, 157, 41, 53, 165, 177, 32]);
static CLIENT_EPHEMERAL_SK: box_::SecretKey =
    box_::SecretKey([80, 169, 55, 157, 134, 142, 219, 152, 125, 240, 174, 209, 225, 109, 46, 188,
                     97, 224, 193, 187, 198, 58, 226, 193, 24, 235, 213, 214, 49, 55, 213, 104]);

fn main() {
    // parse cli arguments
    let mut network_identifier = [0u8; NETWORK_IDENTIFIER_BYTES];
    let mut server_longterm_pk_bytes = [0u8; sign::PUBLICKEYBYTES];

    let args: Vec<_> = env::args().collect();
    let network_identifier_vec = from_hex(&args[1]);
    let server_longterm_pk_vec = from_hex(&args[2]);

    for i in 0..32 {
        network_identifier[i] = network_identifier_vec[i];
        server_longterm_pk_bytes[i] = server_longterm_pk_vec[i];
    }
    let server_longterm_pk = sign::PublicKey(server_longterm_pk_bytes);

    // Always initialize libsodium before using this crate.
    assert!(sodiumoxide::init(), 1);

    let mut stream = AllowStdIo::new(Duplex::new(std::io::stdin(), std::io::stdout()));

    // Set up the handshaker.
    let handshaker = ClientHandshaker::new(stream,
                                           &network_identifier,
                                           &CLIENT_LONGTERM_PK,
                                           &CLIENT_LONGTERM_SK,
                                           &CLIENT_EPHEMERAL_PK,
                                           &CLIENT_EPHEMERAL_SK,
                                           &server_longterm_pk);

    match handshaker.wait() {
        Ok((Ok(outcome), _)) => {
            let mut stdout = std::io::stdout();

            let secretbox::Key(encryption_key_bytes) = outcome.encryption_key();
            let secretbox::Nonce(encryption_nonce_bytes) = outcome.encryption_nonce();
            let secretbox::Key(decryption_key_bytes) = outcome.decryption_key();
            let secretbox::Nonce(decryption_nonce_bytes) = outcome.decryption_nonce();

            let _ = stdout.write_all(&encryption_key_bytes).unwrap();
            let _ = stdout.write_all(&encryption_nonce_bytes).unwrap();
            let _ = stdout.write_all(&decryption_key_bytes).unwrap();
            let _ = stdout.write_all(&decryption_nonce_bytes).unwrap();
        }
        Ok((Err(ClientHandshakeFailure::InvalidMsg2), _)) => {
            std::process::exit(2);
        }
        Ok((Err(ClientHandshakeFailure::InvalidMsg4), _)) => {
            std::process::exit(4);
        }
        Err(_) => panic!("stdin/stdout failed"),
    }
}

// From https://github.com/rust-lang/rust/blob/master/src/libserialize/hex.rs
fn from_hex(s: &str) -> Vec<u8> {
    // This may be an overestimate if there is any whitespace
    let mut b = Vec::with_capacity(s.len() / 2);
    let mut modulus = 0;
    let mut buf = 0;

    for (idx, byte) in s.bytes().enumerate() {
        buf <<= 4;

        match byte {
            b'A'...b'F' => buf |= byte - b'A' + 10,
            b'a'...b'f' => buf |= byte - b'a' + 10,
            b'0'...b'9' => buf |= byte - b'0',
            b' ' | b'\r' | b'\n' | b'\t' => {
                buf >>= 4;
                continue;
            }
            _ => {
                let _ = s[idx..].chars().next().unwrap();
                panic!("Invalid hex character");
            }
        }

        modulus += 1;
        if modulus == 2 {
            modulus = 0;
            b.push(buf);
        }
    }

    match modulus {
        0 => b.into_iter().collect(),
        _ => panic!("Invalid hex length"),
    }
}
