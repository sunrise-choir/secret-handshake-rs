use super::*;
use super::crypto::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::auth;
use std::io::prelude::*;
use std::io;
use futures::Future;
use futures::{Poll, Async};
use tokio_io::{AsyncRead, AsyncWrite};

use partial_io::{PartialOp, PartialRead, PartialWrite, PartialAsyncRead, PartialAsyncWrite,
                 PartialWithErrors};
use partial_io::quickcheck_types::{GenInterruptedWouldBlock, GenWouldBlock};

/// A duplex stream for testing: it records all writes to it, and reads return predefined data
#[derive(Debug)]
struct TestDuplex<'a> {
    writes: Vec<u8>,
    read_data: &'a [u8],
}

impl<'a> TestDuplex<'a> {
    fn new(read_data: &'a [u8]) -> TestDuplex {
        TestDuplex {
            writes: Vec::new(),
            read_data,
        }
    }
}

impl<'a> Write for TestDuplex<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.writes.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.writes.flush()
    }
}

impl<'a> AsyncWrite for TestDuplex<'a> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(Async::Ready(()))
    }
}

impl<'a> Read for TestDuplex<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.read_data.read(buf)
    }
}

impl<'a> AsyncRead for TestDuplex<'a> {}

static APP: [u8; auth::KEYBYTES] = [111, 97, 159, 86, 19, 13, 53, 115, 66, 209, 32, 84, 255, 140,
                                    143, 85, 157, 74, 32, 154, 156, 90, 29, 185, 141, 19, 184,
                                    255, 104, 107, 124, 198];

static CLIENT_PUB: [u8; sign::PUBLICKEYBYTES] = [225, 162, 73, 136, 73, 119, 94, 84, 208, 102,
                                                 233, 120, 23, 46, 225, 245, 198, 79, 176, 0, 151,
                                                 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35];
static CLIENT_SEC: [u8; sign::SECRETKEYBYTES] =
    [243, 168, 6, 50, 44, 78, 192, 183, 210, 241, 189, 36, 183, 154, 132, 119, 115, 84, 47, 151,
     32, 32, 26, 237, 64, 180, 69, 20, 95, 133, 92, 176, 225, 162, 73, 136, 73, 119, 94, 84, 208,
     102, 233, 120, 23, 46, 225, 245, 198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25,
     192, 30, 35];
static CLIENT_EPH_PUB: [u8; box_::PUBLICKEYBYTES] =
    [79, 79, 77, 238, 254, 215, 129, 197, 235, 41, 185, 208, 47, 32, 146, 37, 255, 237, 208, 215,
     182, 92, 201, 106, 85, 86, 157, 41, 53, 165, 177, 32];
static CLIENT_EPH_SEC: [u8; box_::SECRETKEYBYTES] =
    [80, 169, 55, 157, 134, 142, 219, 152, 125, 240, 174, 209, 225, 109, 46, 188, 97, 224, 193,
     187, 198, 58, 226, 193, 24, 235, 213, 214, 49, 55, 213, 104];

static SERVER_PUB: [u8; sign::PUBLICKEYBYTES] = [42, 190, 113, 153, 16, 248, 187, 195, 163, 201,
                                                 187, 204, 86, 238, 66, 151, 52, 115, 160, 4, 244,
                                                 1, 12, 76, 170, 129, 66, 12, 202, 54, 1, 70];
static SERVER_SEC: [u8; sign::SECRETKEYBYTES] =
    [118, 98, 17, 77, 86, 116, 58, 146, 99, 84, 198, 164, 35, 220, 73, 213, 246, 224, 242, 230,
     175, 116, 71, 218, 56, 37, 212, 66, 163, 14, 74, 209, 42, 190, 113, 153, 16, 248, 187, 195,
     163, 201, 187, 204, 86, 238, 66, 151, 52, 115, 160, 4, 244, 1, 12, 76, 170, 129, 66, 12, 202,
     54, 1, 70];
static SERVER_EPH_PUB: [u8; box_::PUBLICKEYBYTES] =
    [166, 12, 63, 218, 235, 136, 61, 99, 232, 142, 165, 147, 88, 93, 79, 177, 23, 148, 129, 57,
     179, 24, 192, 174, 90, 62, 40, 83, 51, 9, 97, 82];
static SERVER_EPH_SEC: [u8; box_::SECRETKEYBYTES] =
    [176, 248, 210, 185, 226, 76, 162, 153, 239, 144, 57, 206, 218, 97, 2, 215, 155, 5, 223, 189,
     22, 28, 137, 85, 228, 233, 93, 79, 217, 203, 63, 125];

static EXP_CLIENT_ENC_KEY: [u8; secretbox::KEYBYTES] =
    [162, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190, 179, 158, 14, 176, 105, 232,
     238, 97, 66, 133, 194, 250, 148, 199, 7, 34, 157, 174, 24];
static EXP_CLIENT_ENC_NONCE: [u8; secretbox::NONCEBYTES] = [44, 140, 79, 227, 23, 153, 202, 203,
                                                            81, 40, 114, 59, 56, 167, 63, 166,
                                                            201, 9, 50, 152, 0, 255, 226, 147];
static EXP_CLIENT_DEC_KEY: [u8; secretbox::KEYBYTES] =
    [125, 136, 153, 7, 109, 241, 239, 84, 228, 176, 141, 23, 58, 129, 90, 228, 188, 93, 191, 224,
     209, 67, 147, 187, 45, 204, 178, 17, 77, 225, 117, 98];
static EXP_CLIENT_DEC_NONCE: [u8; secretbox::NONCEBYTES] = [211, 6, 20, 155, 178, 209, 30, 107, 1,
                                                            3, 140, 242, 73, 101, 116, 234, 249,
                                                            127, 131, 227, 142, 66, 240, 195];
static EXP_SERVER_ENC_KEY: [u8; secretbox::KEYBYTES] =
    [125, 136, 153, 7, 109, 241, 239, 84, 228, 176, 141, 23, 58, 129, 90, 228, 188, 93, 191, 224,
     209, 67, 147, 187, 45, 204, 178, 17, 77, 225, 117, 98];
static EXP_SERVER_ENC_NONCE: [u8; secretbox::NONCEBYTES] = [211, 6, 20, 155, 178, 209, 30, 107, 1,
                                                            3, 140, 242, 73, 101, 116, 234, 249,
                                                            127, 131, 227, 142, 66, 240, 195];
static EXP_SERVER_DEC_KEY: [u8; secretbox::KEYBYTES] =
    [162, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190, 179, 158, 14, 176, 105, 232,
     238, 97, 66, 133, 194, 250, 148, 199, 7, 34, 157, 174, 24];
static EXP_SERVER_DEC_NONCE: [u8; secretbox::NONCEBYTES] = [44, 140, 79, 227, 23, 153, 202, 203,
                                                            81, 40, 114, 59, 56, 167, 63, 166,
                                                            201, 9, 50, 152, 0, 255, 226, 147];

#[test]
// A client aborts the handshake if it receives an invalid challenge from the server.
fn test_client_invalid_challenge() {
    let invalid_server_challenge = [1u8; SERVER_CHALLENGE_BYTES];
    let stream = TestDuplex::new(&invalid_server_challenge);
    let client = ClientHandshaker::new(stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);


    match client.shake_hands().unwrap_err() {
        ClientHandshakeError::InvalidChallenge(_) => assert!(true),
        _ => assert!(false),
    }
}

#[test]
// A client aborts the handshake if it receives an invalid ack from the server.
fn test_client_invalid_ack() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 // end invalid server ack
    ];
    let stream = TestDuplex::new(&data);
    let client = ClientHandshaker::new(stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    match client.shake_hands().unwrap_err() {
        ClientHandshakeError::InvalidAck(_) => assert!(true),
        _ => assert!(false),
    }
}

#[test]
// A client propagates io errors in the handshake
fn test_client_io_error() {
    let valid_server_challenge = [44u8, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167,
                                  63, 166, 201, 9, 50, 152, 0, 255, 226, 147, 22, 43, 84, 99, 107,
                                  198, 198, 219, 166, 12, 63, 218, 235, 136, 61, 99, 232, 142,
                                  165, 147, 88, 93, 79, 177, 23, 148, 129, 57, 179, 24, 192, 174,
                                  90, 62, 40, 83, 51, 9, 97, 82];
    let stream = TestDuplex::new(&valid_server_challenge);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Err(io::ErrorKind::NotFound)];
    let stream = PartialWrite::new(stream, vec![]);
    let stream = PartialRead::new(stream, read_ops);

    let client = ClientHandshaker::new(stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    match client.shake_hands().unwrap_err() {
        ClientHandshakeError::IoErr(e, _) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        _ => assert!(false),
    }
}

#[test]
// A handhake succeeds if the server replies correctly.
fn test_client_success_simple() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);

    let client = ClientHandshaker::new(stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    let (outcome, _) = client.shake_hands().unwrap();

    assert_eq!(outcome.encryption_key(), &EXP_CLIENT_ENC_KEY);
    assert_eq!(outcome.encryption_nonce(), &EXP_CLIENT_ENC_NONCE);
    assert_eq!(outcome.decryption_key(), &EXP_CLIENT_DEC_KEY);
    assert_eq!(outcome.decryption_nonce(), &EXP_CLIENT_DEC_NONCE);
}

fn run_client_handshake<S: Read + Write>(client: ClientHandshaker<S>) -> bool {
    match client.shake_hands() {
        Err(e) => {
            match e {
                ClientHandshakeError::IoErr(_, client) => {
                    return run_client_handshake(client);
                }
                _ => unreachable!(),
            }
        }
        Ok((outcome, _)) => {
            assert_eq!(outcome.encryption_key(), &EXP_CLIENT_ENC_KEY);
            assert_eq!(outcome.encryption_nonce(), &EXP_CLIENT_ENC_NONCE);
            assert_eq!(outcome.decryption_key(), &EXP_CLIENT_DEC_KEY);
            assert_eq!(outcome.decryption_nonce(), &EXP_CLIENT_DEC_NONCE);
            return true;
        }
    }
}

quickcheck! {
      fn test_client_success_randomized(write_ops: PartialWithErrors<GenInterruptedWouldBlock>, read_ops: PartialWithErrors<GenInterruptedWouldBlock>) -> bool {
          let data = [
            44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
            72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
          ];
          let stream = TestDuplex::new(&data);
          let stream = PartialWrite::new(stream, write_ops);
          let stream = PartialRead::new(stream, read_ops);

          let client = ClientHandshaker::new(stream,&APP,
                                                 &CLIENT_PUB,
                                                 &CLIENT_SEC,
                                                 &CLIENT_EPH_PUB,
                                                 &CLIENT_EPH_SEC,
                                                 &SERVER_PUB);

          return run_client_handshake(client);
      }

      fn test_client_success_randomized_async(write_ops: PartialWithErrors<GenWouldBlock>, read_ops: PartialWithErrors<GenWouldBlock>) -> bool {
          let data = [
            44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
            72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
          ];
          let stream = TestDuplex::new(&data);
          let stream = PartialAsyncWrite::new(stream, write_ops);
          let stream = PartialAsyncRead::new(stream, read_ops);

          let client = ClientHandshaker::new(stream,
                                                 &APP,
                                                 &CLIENT_PUB,
                                                 &CLIENT_SEC,
                                                 &CLIENT_EPH_PUB,
                                                 &CLIENT_EPH_SEC,
                                                 &SERVER_PUB);

          let mut flag = true;
          let outcome = client.wait().unwrap();

          if outcome.encryption_key() != &EXP_CLIENT_ENC_KEY {flag = false}
          if outcome.encryption_nonce() != &EXP_CLIENT_ENC_NONCE {flag = false}
          if outcome.decryption_key() != &EXP_CLIENT_DEC_KEY {flag = false}
          if outcome.decryption_nonce() != &EXP_CLIENT_DEC_NONCE {flag = false}

          return flag;
      }
  }

#[test]
// A server aborts the handshake if it receives an invalid challenge from the client.
fn test_server_invalid_challenge() {
    let invalid_client_challenge = [1u8; CLIENT_CHALLENGE_BYTES];
    let stream = TestDuplex::new(&invalid_client_challenge);
    let server = ServerHandshaker::new(stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    match server.shake_hands().unwrap_err() {
        ServerHandshakeError::InvalidChallenge(_) => assert!(true),
        _ => assert!(false),
    }
}

#[test]
// A server aborts the handshake if it receives an invalid auth from the server.
fn test_server_invalid_auth() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 // end invalid client auth
      ];
    let stream = TestDuplex::new(&data);
    let server = ServerHandshaker::new(stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    match server.shake_hands().unwrap_err() {
        ServerHandshakeError::InvalidAuth(_) => assert!(true),
        _ => assert!(false),
    }
}

#[test]
// A server propagates io errors in the handshake
fn test_server_io_error() {
    let valid_client_challenge = [211u8, 6, 20, 155, 178, 209, 30, 107, 1, 3, 140, 242, 73, 101,
                                  116, 234, 249, 127, 131, 227, 142, 66, 240, 195, 13, 50, 38, 96,
                                  7, 208, 124, 180, 79, 79, 77, 238, 254, 215, 129, 197, 235, 41,
                                  185, 208, 47, 32, 146, 37, 255, 237, 208, 215, 182, 92, 201,
                                  106, 85, 86, 157, 41, 53, 165, 177, 32];
    let stream = TestDuplex::new(&valid_client_challenge);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Err(io::ErrorKind::NotFound)];
    let stream = PartialWrite::new(stream, vec![]);
    let stream = PartialRead::new(stream, read_ops);
    let server = ServerHandshaker::new(stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    match server.shake_hands().unwrap_err() {
        ServerHandshakeError::IoErr(e, _) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        _ => assert!(false),
    }
}

#[test]
// A handhake succeeds if the client replies correctly.
fn test_server_success_simple() {
    let data = [
    211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
    80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
      ];
    let stream = TestDuplex::new(&data);
    let server = ServerHandshaker::new(stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    let (outcome, _) = server.shake_hands().unwrap();

    assert_eq!(outcome.encryption_key(), &EXP_SERVER_ENC_KEY);
    assert_eq!(outcome.encryption_nonce(), &EXP_SERVER_ENC_NONCE);
    assert_eq!(outcome.decryption_key(), &EXP_SERVER_DEC_KEY);
    assert_eq!(outcome.decryption_nonce(), &EXP_SERVER_DEC_NONCE);
}

fn run_server_handshake<S: Read + Write>(server: ServerHandshaker<S>) -> bool {
    match server.shake_hands() {
        Err(e) => {
            match e {
                ServerHandshakeError::IoErr(_, server) => {
                    return run_server_handshake(server);
                }
                _ => unreachable!(),
            }
        }
        Ok((outcome, _)) => {
            assert_eq!(outcome.encryption_key(), &EXP_SERVER_ENC_KEY);
            assert_eq!(outcome.encryption_nonce(), &EXP_SERVER_ENC_NONCE);
            assert_eq!(outcome.decryption_key(), &EXP_SERVER_DEC_KEY);
            assert_eq!(outcome.decryption_nonce(), &EXP_SERVER_DEC_NONCE);
            return true;
        }
    }
}

quickcheck! {
        fn test_server_success_randomized(write_ops: PartialWithErrors<GenInterruptedWouldBlock>, read_ops: PartialWithErrors<GenInterruptedWouldBlock>) -> bool {
          let data = [
                211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
                80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
            ];
            let stream = TestDuplex::new(&data);
            let stream = PartialWrite::new(stream, write_ops);
            let stream = PartialRead::new(stream, read_ops);

            let server = ServerHandshaker::new(stream,
                                               &APP,
                                               &SERVER_PUB,
                                               &SERVER_SEC,
                                               &SERVER_EPH_PUB,
                                               &SERVER_EPH_SEC);

            return run_server_handshake(server);
        }

        fn test_server_success_randomized_async(write_ops: PartialWithErrors<GenWouldBlock>, read_ops: PartialWithErrors<GenWouldBlock>) -> bool {
          let data = [
                211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
                80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
            ];
            let stream = TestDuplex::new(&data);
            let stream = PartialAsyncWrite::new(stream, write_ops);
            let stream = PartialAsyncRead::new(stream, read_ops);

            let server = ServerHandshaker::new(stream,
                                               &APP,
                                               &SERVER_PUB,
                                               &SERVER_SEC,
                                               &SERVER_EPH_PUB,
                                               &SERVER_EPH_SEC);

            let mut flag = true;
            let outcome = server.wait().unwrap();

            if outcome.encryption_key() != &EXP_SERVER_ENC_KEY {flag = false}
            if outcome.encryption_nonce() != &EXP_SERVER_ENC_NONCE {flag = false}
            if outcome.decryption_key() != &EXP_SERVER_DEC_KEY {flag = false}
            if outcome.decryption_nonce() != &EXP_SERVER_DEC_NONCE {flag = false}

            return flag;
        }
    }
