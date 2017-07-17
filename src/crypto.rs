//! Low-level bindings to shs1-c. You probably don't need to use this
//! module directly.
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::auth;

use std::mem::uninitialized;

pub const CLIENT_CHALLENGE_BYTES: usize = 64;
pub const SERVER_CHALLENGE_BYTES: usize = 64;
pub const CLIENT_AUTH_BYTES: usize = 112;
pub const SERVER_ACK_BYTES: usize = 80;

/// The data resulting from a handshake: Keys and nonces suitable for encrypted
/// two-way communication with the peer via box-stream-rs.
#[repr(C)]
#[derive(Debug)]
pub struct Outcome {
    encryption_key: [u8; secretbox::KEYBYTES],
    encryption_nonce: [u8; secretbox::NONCEBYTES],
    padding_encryption: [u8; 8],
    decryption_key: [u8; secretbox::KEYBYTES],
    decryption_nonce: [u8; secretbox::NONCEBYTES],
    padding_decryption: [u8; 8],
}

/// The struct used in the C code to perform the client side of a handshake.
#[repr(C)]
// #[derive(Debug)]
pub struct Client {
    // inputs
    app: *const [u8; auth::KEYBYTES],
    pub_: *const [u8; sign::PUBLICKEYBYTES],
    sec: *const [u8; sign::SECRETKEYBYTES],
    eph_pub: *const [u8; box_::PUBLICKEYBYTES],
    eph_sec: *const [u8; box_::SECRETKEYBYTES],
    server_pub: *const [u8; sign::PUBLICKEYBYTES],
    // intermediate results
    shared_secret: [u8; scalarmult::GROUPELEMENTBYTES],
    server_lterm_shared: [u8; scalarmult::GROUPELEMENTBYTES],
    hello: [u8; sign::SIGNATUREBYTES + sign::PUBLICKEYBYTES],
    shared_hash: [u8; sha256::DIGESTBYTES],
    server_eph_pub: [u8; box_::PUBLICKEYBYTES],
}

impl Client {
    pub fn new(app: *const [u8; auth::KEYBYTES],
               pub_: *const [u8; sign::PUBLICKEYBYTES],
               sec: *const [u8; sign::SECRETKEYBYTES],
               eph_pub: *const [u8; box_::PUBLICKEYBYTES],
               eph_sec: *const [u8; box_::SECRETKEYBYTES],
               server_pub: *const [u8; sign::PUBLICKEYBYTES])
               -> Client {
        Client {
            app,
            pub_,
            sec,
            eph_pub,
            eph_sec,
            server_pub,
            shared_secret: unsafe { uninitialized() },
            server_lterm_shared: unsafe { uninitialized() },
            hello: unsafe { uninitialized() },
            shared_hash: unsafe { uninitialized() },
            server_eph_pub: unsafe { uninitialized() },
        }
    }

    pub fn create_client_challenge(&mut self, challenge: &mut [u8; CLIENT_CHALLENGE_BYTES]) {
        unsafe { shs1_create_client_challenge(challenge, self) }
    }

    pub fn verify_server_challenge(&mut self, challenge: &[u8; CLIENT_CHALLENGE_BYTES]) -> bool {
        unsafe { shs1_verify_server_challenge(challenge, self) }
    }

    pub fn create_client_auth(&mut self, auth: &mut [u8; CLIENT_AUTH_BYTES]) -> i32 {
        unsafe { shs1_create_client_auth(auth, self) }
    }

    pub fn verify_server_ack(&mut self, ack: &[u8; SERVER_ACK_BYTES]) -> bool {
        unsafe { shs1_verify_server_ack(ack, self) }
    }

    pub fn outcome(&mut self, outcome: &mut Outcome) {
        unsafe { shs1_client_outcome(outcome, self) }
    }

    pub fn clean(&mut self) {
        unsafe { shs1_client_clean(self) }
    }
}

/// The struct used in the C code to perform the server side of a handshake.
#[repr(C)]
// #[derive(Debug)]
pub struct Server {
    app: *const [u8; auth::KEYBYTES],
    pub_: *const [u8; sign::PUBLICKEYBYTES],
    sec: *const [u8; sign::SECRETKEYBYTES],
    eph_pub: *const [u8; box_::PUBLICKEYBYTES],
    eph_sec: *const [u8; box_::SECRETKEYBYTES],
    //intermediate results
    client_hello: [u8; sign::SIGNATUREBYTES + sign::PUBLICKEYBYTES],
    shared_hash: [u8; sha256::DIGESTBYTES],
    client_eph_pub: [u8; box_::PUBLICKEYBYTES],
    client_pub: [u8; sign::PUBLICKEYBYTES],
    box_sec: [u8; sha256::DIGESTBYTES],
}

impl Server {
    pub fn new(app: *const [u8; auth::KEYBYTES],
               pub_: *const [u8; sign::PUBLICKEYBYTES],
               sec: *const [u8; sign::SECRETKEYBYTES],
               eph_pub: *const [u8; box_::PUBLICKEYBYTES],
               eph_sec: *const [u8; box_::SECRETKEYBYTES])
               -> Server {
        Server {
            app,
            pub_,
            sec,
            eph_pub,
            eph_sec,
            client_hello: unsafe { uninitialized() },
            shared_hash: unsafe { uninitialized() },
            client_eph_pub: unsafe { uninitialized() },
            client_pub: unsafe { uninitialized() },
            box_sec: unsafe { uninitialized() },
        }
    }

    pub fn verify_client_challenge(&mut self, challenge: &[u8; CLIENT_CHALLENGE_BYTES]) -> bool {
        unsafe { shs1_verify_client_challenge(challenge, self) }
    }

    pub fn create_server_challenge(&mut self, challenge: &mut [u8; SERVER_CHALLENGE_BYTES]) {
        unsafe { shs1_create_server_challenge(challenge, self) }
    }

    pub fn verify_client_auth(&mut self, auth: &[u8; CLIENT_AUTH_BYTES]) {
        unsafe { shs1_verify_client_auth(auth, self) }
    }

    pub fn create_server_acc(&mut self, ack: *mut [u8; SERVER_ACK_BYTES]) {
        unsafe { shs1_create_server_acc(ack, self) }
    }

    pub fn outcome(&mut self, outcome: &mut Outcome) {
        unsafe { shs1_server_outcome(outcome, self) }
    }

    pub fn clean(&mut self) {
        unsafe { shs1_server_clean(self) }
    }
}

extern "C" {
    // client side
    fn shs1_create_client_challenge(challenge: *mut [u8; CLIENT_CHALLENGE_BYTES],
                                    client: *mut Client);
    fn shs1_verify_server_challenge(challenge: *const [u8; CLIENT_CHALLENGE_BYTES],
                                    client: *mut Client)
                                    -> bool;
    fn shs1_create_client_auth(auth: *mut [u8; CLIENT_AUTH_BYTES], client: *mut Client) -> i32;
    fn shs1_verify_server_ack(ack: *const [u8; SERVER_ACK_BYTES], client: *mut Client) -> bool;
    fn shs1_client_outcome(outcome: *mut Outcome, client: *mut Client);
    fn shs1_client_clean(client: *mut Client);
    // server side
    fn shs1_verify_client_challenge(challenge: *const [u8; CLIENT_CHALLENGE_BYTES],
                                    server: *mut Server)
                                    -> bool;
    fn shs1_create_server_challenge(challenge: *mut [u8; SERVER_CHALLENGE_BYTES],
                                    server: *mut Server);
    fn shs1_verify_client_auth(auth: *const [u8; CLIENT_AUTH_BYTES], server: *mut Server);
    fn shs1_create_server_acc(ack: *mut [u8; SERVER_ACK_BYTES], server: *mut Server);
    fn shs1_server_outcome(outcome: *mut Outcome, server: *mut Server);
    fn shs1_server_clean(server: *mut Server);
}
