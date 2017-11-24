use super::*;
use sodiumoxide::crypto::{box_, secretbox, sign, auth};
use sodiumoxide::randombytes::randombytes_into;
use std::io::prelude::*;
use std::io;
use futures::{Poll, Async, Future};
use futures::future::{ok, err, FutureResult};
use void::Void;
use tokio_io::{AsyncRead, AsyncWrite};

use partial_io::{PartialOp, PartialAsyncRead, PartialAsyncWrite, PartialWithErrors};
use partial_io::quickcheck_types::GenInterruptedWouldBlock;
use quickcheck::{QuickCheck, StdGen, Gen, Arbitrary};
use async_ringbuffer::*;
use rand::Rng;

/// Implements both Read and Write by delegating to a Read and a Write (of which
/// it takes ownership).
pub struct Duplex<R, W> {
    r: R,
    w: W,
}

impl<R, W> Duplex<R, W> {
    /// Takes ownership of a Read and a Write and creates a new Duplex.
    pub fn new(r: R, w: W) -> Duplex<R, W> {
        Duplex { r, w }
    }
}

impl<R, W: Write> Write for Duplex<R, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.w.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.w.flush()
    }
}

impl<R, W: AsyncWrite> AsyncWrite for Duplex<R, W> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.w.shutdown()
    }
}

impl<R: Read, W> Read for Duplex<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.r.read(buf)
    }
}

impl<R: AsyncRead, W> AsyncRead for Duplex<R, W> {}

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

static CLIENT_PUB: sign::PublicKey =
    sign::PublicKey([225, 162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245,
                     198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]);
static CLIENT_SEC: sign::SecretKey =
    sign::SecretKey([243, 168, 6, 50, 44, 78, 192, 183, 210, 241, 189, 36, 183, 154, 132, 119,
                     115, 84, 47, 151, 32, 32, 26, 237, 64, 180, 69, 20, 95, 133, 92, 176, 225,
                     162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245, 198,
                     79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]);
static CLIENT_EPH_PUB: box_::PublicKey =
    box_::PublicKey([79, 79, 77, 238, 254, 215, 129, 197, 235, 41, 185, 208, 47, 32, 146, 37,
                     255, 237, 208, 215, 182, 92, 201, 106, 85, 86, 157, 41, 53, 165, 177, 32]);
static CLIENT_EPH_SEC: box_::SecretKey =
    box_::SecretKey([80, 169, 55, 157, 134, 142, 219, 152, 125, 240, 174, 209, 225, 109, 46, 188,
                     97, 224, 193, 187, 198, 58, 226, 193, 24, 235, 213, 214, 49, 55, 213, 104]);

static SERVER_PUB: sign::PublicKey =
    sign::PublicKey([42, 190, 113, 153, 16, 248, 187, 195, 163, 201, 187, 204, 86, 238, 66, 151,
                     52, 115, 160, 4, 244, 1, 12, 76, 170, 129, 66, 12, 202, 54, 1, 70]);
static SERVER_SEC: sign::SecretKey =
    sign::SecretKey([118, 98, 17, 77, 86, 116, 58, 146, 99, 84, 198, 164, 35, 220, 73, 213, 246,
                     224, 242, 230, 175, 116, 71, 218, 56, 37, 212, 66, 163, 14, 74, 209, 42,
                     190, 113, 153, 16, 248, 187, 195, 163, 201, 187, 204, 86, 238, 66, 151, 52,
                     115, 160, 4, 244, 1, 12, 76, 170, 129, 66, 12, 202, 54, 1, 70]);
static SERVER_EPH_PUB: box_::PublicKey =
    box_::PublicKey([166, 12, 63, 218, 235, 136, 61, 99, 232, 142, 165, 147, 88, 93, 79, 177, 23,
                     148, 129, 57, 179, 24, 192, 174, 90, 62, 40, 83, 51, 9, 97, 82]);
static SERVER_EPH_SEC: box_::SecretKey =
    box_::SecretKey([176, 248, 210, 185, 226, 76, 162, 153, 239, 144, 57, 206, 218, 97, 2, 215,
                     155, 5, 223, 189, 22, 28, 137, 85, 228, 233, 93, 79, 217, 203, 63, 125]);

static EXP_CLIENT_ENC_KEY: secretbox::Key =
    secretbox::Key([162, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190, 179, 158, 14,
                    176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199, 7, 34, 157, 174, 24]);
static EXP_CLIENT_ENC_NONCE: secretbox::Nonce =
    secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167, 63, 166,
                      201, 9, 50, 152, 0, 255, 226, 147]);
static EXP_CLIENT_DEC_KEY: secretbox::Key =
    secretbox::Key([125, 136, 153, 7, 109, 241, 239, 84, 228, 176, 141, 23, 58, 129, 90, 228,
                    188, 93, 191, 224, 209, 67, 147, 187, 45, 204, 178, 17, 77, 225, 117, 98]);
static EXP_CLIENT_DEC_NONCE: secretbox::Nonce =
    secretbox::Nonce([211, 6, 20, 155, 178, 209, 30, 107, 1, 3, 140, 242, 73, 101, 116, 234, 249,
                      127, 131, 227, 142, 66, 240, 195]);
static EXP_SERVER_PUB: sign::PublicKey =
    sign::PublicKey([42, 190, 113, 153, 16, 248, 187, 195, 163, 201, 187, 204, 86, 238, 66, 151,
                     52, 115, 160, 4, 244, 1, 12, 76, 170, 129, 66, 12, 202, 54, 1, 70]);

static EXP_SERVER_ENC_KEY: secretbox::Key =
    secretbox::Key([125, 136, 153, 7, 109, 241, 239, 84, 228, 176, 141, 23, 58, 129, 90, 228,
                    188, 93, 191, 224, 209, 67, 147, 187, 45, 204, 178, 17, 77, 225, 117, 98]);
static EXP_SERVER_ENC_NONCE: secretbox::Nonce =
    secretbox::Nonce([211, 6, 20, 155, 178, 209, 30, 107, 1, 3, 140, 242, 73, 101, 116, 234, 249,
                      127, 131, 227, 142, 66, 240, 195]);
static EXP_SERVER_DEC_KEY: secretbox::Key =
    secretbox::Key([162, 29, 153, 150, 123, 225, 10, 173, 175, 201, 160, 34, 190, 179, 158, 14,
                    176, 105, 232, 238, 97, 66, 133, 194, 250, 148, 199, 7, 34, 157, 174, 24]);
static EXP_SERVER_DEC_NONCE: secretbox::Nonce =
    secretbox::Nonce([44, 140, 79, 227, 23, 153, 202, 203, 81, 40, 114, 59, 56, 167, 63, 166,
                      201, 9, 50, 152, 0, 255, 226, 147]);
static EXP_CLIENT_PUB: sign::PublicKey =
    sign::PublicKey([225, 162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245,
                     198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]);

#[test]
// A client and a server can perform a handshake.
fn test_success() {
    let rng = StdGen::new(rand::thread_rng(), 200);
    let mut quickcheck = QuickCheck::new().gen(rng).tests(1000);
    quickcheck.quickcheck(success as
                          fn(usize,
                             usize,
                             PartialWithErrors<GenInterruptedWouldBlock>,
                             PartialWithErrors<GenInterruptedWouldBlock>,
                             PartialWithErrors<GenInterruptedWouldBlock>,
                             PartialWithErrors<GenInterruptedWouldBlock>)
                             -> bool);
}

fn success(buf_size_a: usize,
           buf_size_b: usize,
           write_ops_c: PartialWithErrors<GenInterruptedWouldBlock>,
           read_ops_c: PartialWithErrors<GenInterruptedWouldBlock>,
           write_ops_s: PartialWithErrors<GenInterruptedWouldBlock>,
           read_ops_s: PartialWithErrors<GenInterruptedWouldBlock>)
           -> bool {
    let (writer_a, reader_a) = ring_buffer(buf_size_a + 1);
    let (writer_b, reader_b) = ring_buffer(buf_size_b + 1);

    let mut client_duplex = Duplex::new(PartialAsyncRead::new(reader_a, read_ops_c),
                                        PartialAsyncWrite::new(writer_b, write_ops_c));
    let mut server_duplex = Duplex::new(PartialAsyncRead::new(reader_b, read_ops_s),
                                        PartialAsyncWrite::new(writer_a, write_ops_s));

    let mut network_identifier = [0u8; NETWORK_IDENTIFIER_BYTES];
    randombytes_into(&mut network_identifier[0..32]);
    let (client_longterm_pk, client_longterm_sk) = sign::gen_keypair();
    let (client_ephemeral_pk, client_ephemeral_sk) = box_::gen_keypair();
    let (server_longterm_pk, server_longterm_sk) = sign::gen_keypair();
    let (server_ephemeral_pk, server_ephemeral_sk) = box_::gen_keypair();

    let mut client = ClientHandshaker::new(&mut client_duplex,
                                           &network_identifier,
                                           &client_longterm_pk,
                                           &client_longterm_sk,
                                           &client_ephemeral_pk,
                                           &client_ephemeral_sk,
                                           &server_longterm_pk);

    let mut server = ServerHandshaker::new(&mut server_duplex,
                                           &network_identifier,
                                           &server_longterm_pk,
                                           &server_longterm_sk,
                                           &server_ephemeral_pk,
                                           &server_ephemeral_sk);

    let (client_result, server_result) = client.join(server).wait().unwrap();
    let client_outcome = client_result.unwrap();
    let server_outcome = server_result.unwrap();

    assert_eq!(client_outcome.encryption_key(),
               server_outcome.decryption_key());
    assert_eq!(client_outcome.encryption_nonce(),
               server_outcome.decryption_nonce());
    assert_eq!(client_outcome.decryption_key(),
               server_outcome.encryption_key());
    assert_eq!(client_outcome.decryption_nonce(),
               server_outcome.encryption_nonce());

    assert_eq!(client_outcome.peer_longterm_pk(), server_longterm_pk);
    assert_eq!(server_outcome.peer_longterm_pk(), client_longterm_pk);

    return true;
}

// A client handles partial reads/writes and WouldBlock errors on the underlying stream.
quickcheck! {
      fn test_client_success_randomized_async(write_ops: PartialWithErrors<GenInterruptedWouldBlock>, read_ops: PartialWithErrors<GenInterruptedWouldBlock>) -> bool {
          let data = [
            44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
            72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
          ];
          let stream = TestDuplex::new(&data);
          let stream = PartialAsyncWrite::new(stream, write_ops);
          let mut stream = PartialAsyncRead::new(stream, read_ops);

          let client = ClientHandshaker::new(&mut stream,
                                                 &APP,
                                                 &CLIENT_PUB,
                                                 &CLIENT_SEC,
                                                 &CLIENT_EPH_PUB,
                                                 &CLIENT_EPH_SEC,
                                                 &SERVER_PUB);

          let outcome = client.wait().unwrap().unwrap();
          assert_eq!(outcome.encryption_key(), EXP_CLIENT_ENC_KEY);
          assert_eq!(outcome.encryption_nonce(), EXP_CLIENT_ENC_NONCE);
          assert_eq!(outcome.decryption_key(), EXP_CLIENT_DEC_KEY);
          assert_eq!(outcome.decryption_nonce(), EXP_CLIENT_DEC_NONCE);
          assert_eq!(outcome.peer_longterm_pk(), EXP_SERVER_PUB);
          return true;
      }
  }

#[test]
// A client propagates io errors in the handshake.
fn test_client_io_error() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Err(io::ErrorKind::NotFound)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let client = ClientHandshaker::new(&mut stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    assert_eq!(client.wait().unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[test]
// A client errors WriteZero if writing msg1 to the underlying stream returns Ok(0).
fn test_client_write0_msg1() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);
    let write_ops = vec![PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, write_ops);
    let mut stream = PartialAsyncRead::new(stream, vec![]);

    let client = ClientHandshaker::new(&mut stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    assert_eq!(client.wait().unwrap_err().kind(), io::ErrorKind::WriteZero);
}

#[test]
// A client errors UnexpectedEof if reading msg2 from the underlying stream returns Ok(0).
fn test_client_read0_msg2() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let client = ClientHandshaker::new(&mut stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    assert_eq!(client.wait().unwrap_err().kind(),
               io::ErrorKind::UnexpectedEof);
}

#[test]
// A client errors WriteZero if writing msg3 to the underlying stream returns Ok(0).
fn test_client_write0_msg3() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);
    let write_ops = vec![PartialOp::Unlimited,
                         PartialOp::Limited(8),
                         PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, write_ops);
    let mut stream = PartialAsyncRead::new(stream, vec![]);

    let client = ClientHandshaker::new(&mut stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    assert_eq!(client.wait().unwrap_err().kind(), io::ErrorKind::WriteZero);
}

#[test]
// A client errors UnexpectedEof if reading msg4 from the underlying stream returns Ok(0).
fn test_client_read0_msg4() {
    let data = [
      44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147,22,43,84,99,107,198,198,219,166,12,63,218,235,136,61,99,232,142,165,147,88,93,79,177,23,148,129,57,179,24,192,174,90,62,40,83,51,9,97,82, // end valid server challenge
      72,114,92,105,109,48,17,14,25,150,242,50,148,70,49,25,222,254,255,124,194,144,84,114,190,148,252,189,159,132,157,173,92,14,247,198,87,232,141,83,84,79,226,43,194,95,14,8,138,233,96,40,126,153,205,36,95,203,200,202,221,118,126,99,47,216,209,219,3,133,240,216,166,182,182,226,215,116,177,66 // end valid server ack
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Limited(8),
                        PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let client = ClientHandshaker::new(&mut stream,
                                       &APP,
                                       &CLIENT_PUB,
                                       &CLIENT_SEC,
                                       &CLIENT_EPH_PUB,
                                       &CLIENT_EPH_SEC,
                                       &SERVER_PUB);

    assert_eq!(client.wait().unwrap_err().kind(),
               io::ErrorKind::UnexpectedEof);
}

// A server handles partial reads/writes and WouldBlock errors on the underlying stream.
quickcheck! {
        fn test_server_success_randomized_async(write_ops: PartialWithErrors<GenInterruptedWouldBlock>, read_ops: PartialWithErrors<GenInterruptedWouldBlock>) -> bool {
          let data = [
                211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
                80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
            ];
            let stream = TestDuplex::new(&data);
            let stream = PartialAsyncWrite::new(stream, write_ops);
            let mut stream = PartialAsyncRead::new(stream, read_ops);

            let server = ServerHandshaker::new(&mut stream,
                                               &APP,
                                               &SERVER_PUB,
                                               &SERVER_SEC,
                                               &SERVER_EPH_PUB,
                                               &SERVER_EPH_SEC);

           let outcome = server.wait().unwrap().unwrap();
           assert_eq!(outcome.encryption_key(), EXP_SERVER_ENC_KEY);
           assert_eq!(outcome.encryption_nonce(), EXP_SERVER_ENC_NONCE);
           assert_eq!(outcome.decryption_key(), EXP_SERVER_DEC_KEY);
           assert_eq!(outcome.decryption_nonce(), EXP_SERVER_DEC_NONCE);
           assert_eq!(outcome.peer_longterm_pk(), EXP_CLIENT_PUB);
           return true;
        }
    }

#[test]
// A server propagates io errors in the handshake.
fn test_server_io_error() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Err(io::ErrorKind::NotFound)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let server = ServerHandshaker::new(&mut stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    assert_eq!(server.wait().unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[test]
// A server errors UnexpectedEof if reading msg1 from the underlying stream returns Ok(0).
fn test_server_read0_msg1() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let server = ServerHandshaker::new(&mut stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    assert_eq!(server.wait().unwrap_err().kind(),
               io::ErrorKind::UnexpectedEof);
}

#[test]
// A server errors WriteZero if writing msg2 to the underlying stream returns Ok(0).
fn test_server_write0_msg2() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let stream = TestDuplex::new(&data);
    let write_ops = vec![PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, write_ops);
    let mut stream = PartialAsyncRead::new(stream, vec![]);

    let server = ServerHandshaker::new(&mut stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    assert_eq!(server.wait().unwrap_err().kind(), io::ErrorKind::WriteZero);
}

#[test]
// A server errors UnexpectedEof if reading msg3 from the underlying stream returns Ok(0).
fn test_server_read0_msg3() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let stream = TestDuplex::new(&data);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Limited(8),
                        PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);

    let server = ServerHandshaker::new(&mut stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    assert_eq!(server.wait().unwrap_err().kind(),
               io::ErrorKind::UnexpectedEof);
}

#[test]
// A server errors WriteZero if writing msg4 to the underlying stream returns Ok(0).
fn test_server_write0_msg4() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let stream = TestDuplex::new(&data);
    let write_ops = vec![PartialOp::Unlimited,
                         PartialOp::Limited(8),
                         PartialOp::Limited(0)];
    let stream = PartialAsyncWrite::new(stream, write_ops);
    let mut stream = PartialAsyncRead::new(stream, vec![]);

    let server = ServerHandshaker::new(&mut stream,
                                       &APP,
                                       &SERVER_PUB,
                                       &SERVER_SEC,
                                       &SERVER_EPH_PUB,
                                       &SERVER_EPH_SEC);

    assert_eq!(server.wait().unwrap_err().kind(), io::ErrorKind::WriteZero);
}

fn const_async_true(_: &sign::PublicKey) -> FutureResult<bool, Void> {
    ok(true)
}

#[test]
// A filtering server accepts a client if the filter function returns true.
fn test_filter_server_accept() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let mut stream = TestDuplex::new(&data);

    let server = ServerHandshakerWithFilter::new(&mut stream,
                                                 const_async_true,
                                                 &APP,
                                                 &SERVER_PUB,
                                                 &SERVER_SEC,
                                                 &SERVER_EPH_PUB,
                                                 &SERVER_EPH_SEC);

    let outcome = server.wait().unwrap().unwrap();
    assert_eq!(outcome.encryption_key(), EXP_SERVER_ENC_KEY);
    assert_eq!(outcome.encryption_nonce(), EXP_SERVER_ENC_NONCE);
    assert_eq!(outcome.decryption_key(), EXP_SERVER_DEC_KEY);
    assert_eq!(outcome.decryption_nonce(), EXP_SERVER_DEC_NONCE);
    assert_eq!(outcome.peer_longterm_pk(), EXP_CLIENT_PUB);
}

fn const_async_false(_: &sign::PublicKey) -> FutureResult<bool, Void> {
    ok(false)
}

#[test]
// A filtering server rejects a client if the filter function returns false.
fn test_filter_server_reject() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let mut stream = TestDuplex::new(&data);

    let server = ServerHandshakerWithFilter::new(&mut stream,
                                                 const_async_false,
                                                 &APP,
                                                 &SERVER_PUB,
                                                 &SERVER_SEC,
                                                 &SERVER_EPH_PUB,
                                                 &SERVER_EPH_SEC);

    assert!(server.wait().unwrap().unwrap_err() ==
            ServerHandshakeFailureWithFilter::UnauthorizedClient);
}

#[test]
// A filtering server propagates io errors in the handshake.
fn test_filter_server_io_error() {
    let valid_client_challenge = [211u8, 6, 20, 155, 178, 209, 30, 107, 1, 3, 140, 242, 73, 101,
                                  116, 234, 249, 127, 131, 227, 142, 66, 240, 195, 13, 50, 38, 96,
                                  7, 208, 124, 180, 79, 79, 77, 238, 254, 215, 129, 197, 235, 41,
                                  185, 208, 47, 32, 146, 37, 255, 237, 208, 215, 182, 92, 201,
                                  106, 85, 86, 157, 41, 53, 165, 177, 32];
    let stream = TestDuplex::new(&valid_client_challenge);
    let read_ops = vec![PartialOp::Unlimited,
                        PartialOp::Err(io::ErrorKind::NotFound)];
    let stream = PartialAsyncWrite::new(stream, vec![]);
    let mut stream = PartialAsyncRead::new(stream, read_ops);
    let server = ServerHandshakerWithFilter::new(&mut stream,
                                                 const_async_true,
                                                 &APP,
                                                 &SERVER_PUB,
                                                 &SERVER_SEC,
                                                 &SERVER_EPH_PUB,
                                                 &SERVER_EPH_SEC);

    match server.wait().unwrap_err() {
        ServerHandshakeError::IoError(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        ServerHandshakeError::FilterFnError(_) => assert!(false),
    }
}

fn const_async_error(_: &sign::PublicKey) -> FutureResult<bool, ()> {
    err(())
}

#[test]
// A filtering server propagates filter function errors in the handshake.
fn test_filter_server_filter_error() {
    let data = [
        211,6,20,155,178,209,30,107,1,3,140,242,73,101,116,234,249,127,131,227,142,66,240,195,13,50,38,96,7,208,124,180,79,79,77,238,254,215,129,197,235,41,185,208,47,32,146,37,255,237,208,215,182,92,201,106,85,86,157,41,53,165,177,32, // end valid client challenge
        80,34,24,195,46,211,235,66,91,89,65,98,137,26,86,197,32,4,153,142,160,18,56,180,12,171,127,38,44,53,74,64,55,188,22,25,161,25,7,243,200,196,145,249,207,211,88,178,0,206,173,234,188,20,251,240,199,169,94,180,212,32,150,226,138,44,141,235,33,152,91,215,31,126,48,48,220,239,97,225,103,79,190,56,227,103,142,195,124,10,21,76,66,11,194,11,220,15,163,66,138,232,228,12,130,172,4,137,52,159,64,98 // end valid client auth
    ];
    let mut stream = TestDuplex::new(&data);

    let server = ServerHandshakerWithFilter::new(&mut stream,
                                                 const_async_error,
                                                 &APP,
                                                 &SERVER_PUB,
                                                 &SERVER_SEC,
                                                 &SERVER_EPH_PUB,
                                                 &SERVER_EPH_SEC);

    match server.wait().unwrap_err() {
        ServerHandshakeError::IoError(_) => assert!(false),
        ServerHandshakeError::FilterFnError(e) => assert_eq!(e, ()),
    }
}
