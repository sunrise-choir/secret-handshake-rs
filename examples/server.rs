#![feature(drop_types_in_const)]
// This file serves both as an example of using the `ServerHandshaker` struct, and as the server test executable for the [shs1 testsuite](https://github.com/AljoschaMeyer/shs1-testsuite).
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

static SERVER_EPHEMERAL_PK: box_::PublicKey =
    box_::PublicKey([166, 12, 63, 218, 235, 136, 61, 99, 232, 142, 165, 147, 88, 93, 79, 177, 23,
                     148, 129, 57, 179, 24, 192, 174, 90, 62, 40, 83, 51, 9, 97, 82]);
static SERVER_EPHEMERAL_SK: box_::SecretKey =
    box_::SecretKey([176, 248, 210, 185, 226, 76, 162, 153, 239, 144, 57, 206, 218, 97, 2, 215,
                     155, 5, 223, 189, 22, 28, 137, 85, 228, 233, 93, 79, 217, 203, 63, 125]);

fn main() {
    // parse cli arguments
    let mut network_identifier = [0u8; NETWORK_IDENTIFIER_BYTES];
    let mut server_longterm_sk_bytes = [0u8; sign::SECRETKEYBYTES];
    let mut server_longterm_pk_bytes = [0u8; sign::PUBLICKEYBYTES];

    let args: Vec<_> = env::args().collect();
    let network_identifier_vec = from_hex(&args[1]);
    let server_longterm_sk_vec = from_hex(&args[2]);
    let server_longterm_pk_vec = from_hex(&args[3]);

    for i in 0..32 {
        network_identifier[i] = network_identifier_vec[i];
        server_longterm_pk_bytes[i] = server_longterm_pk_vec[i];
    }
    for i in 0..sign::SECRETKEYBYTES {
        server_longterm_sk_bytes[i] = server_longterm_sk_vec[i];
    }
    let server_longterm_sk = sign::SecretKey(server_longterm_sk_bytes);
    let server_longterm_pk = sign::PublicKey(server_longterm_pk_bytes);

    // Always initialize libsodium before using this crate.
    assert!(sodiumoxide::init(), 1);

    let mut stream = AllowStdIo::new(Duplex::new(std::io::stdin(), std::io::stdout()));

    // Set up the handshaker.
    let handshaker = ServerHandshaker::new(stream,
                                           &network_identifier,
                                           &server_longterm_pk,
                                           &server_longterm_sk,
                                           &SERVER_EPHEMERAL_PK,
                                           &SERVER_EPHEMERAL_SK);

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
        Ok((Err(ServerHandshakeFailure::InvalidMsg1), _)) => {
            std::process::exit(1);
        }
        Ok((Err(ServerHandshakeFailure::InvalidMsg3), _)) => {
            std::process::exit(3);
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
