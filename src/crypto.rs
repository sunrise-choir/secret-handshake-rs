//! Low-level bindings to shs1-c. You probably don't need to use this
//! module directly.

use std::mem::uninitialized;
use std::io;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::auth;

/// Length of a network identifier in bytes.
pub const NETWORK_IDENTIFIER_BYTES: usize = 32;

/// Length of msg1 in bytes.
pub const MSG1_BYTES: usize = 64;
/// Length of msg2 in bytes.
pub const MSG2_BYTES: usize = 64;
/// Length of msg3 in bytes.
pub const MSG3_BYTES: usize = 112;
/// Length of msg4 in bytes.
pub const MSG4_BYTES: usize = 80;

/// The data resulting from a handshake: Keys and nonces suitable for encrypted
/// two-way communication with the peer via box-stream-rs, and the longterm
/// public key of the peer.
#[repr(C)]
#[derive(Debug)]
pub struct Outcome {
    encryption_key: [u8; secretbox::KEYBYTES],
    encryption_nonce: [u8; secretbox::NONCEBYTES],
    padding_encryption: [u8; 8],
    decryption_key: [u8; secretbox::KEYBYTES],
    decryption_nonce: [u8; secretbox::NONCEBYTES],
    padding_decryption: [u8; 8],
    peer_longterm_pk: [u8; sign::PUBLICKEYBYTES],
}

/// Zero out all sensitive data when going out of scope
impl Drop for Outcome {
    fn drop(&mut self) {
        self.encryption_key = [0; secretbox::KEYBYTES];
        self.encryption_nonce = [0; secretbox::NONCEBYTES];
        self.decryption_key = [0; secretbox::KEYBYTES];
        self.decryption_nonce = [0; secretbox::NONCEBYTES];
    }
}

impl Outcome {
    /// The negotiated key that should be used to encrypt messages to the peer.
    pub fn encryption_key(&self) -> secretbox::Key {
        secretbox::Key(self.encryption_key)
    }

    /// The negotiated initial nonce that should be used to encrypt messages to the peer.
    pub fn encryption_nonce(&self) -> secretbox::Nonce {
        secretbox::Nonce(self.encryption_nonce)
    }

    /// The negotiated key that should be used to decrypt messages from the peer.
    pub fn decryption_key(&self) -> secretbox::Key {
        secretbox::Key(self.encryption_key)
    }

    /// The negotiated initial nonce that should be used to decrypt messages from the peer.
    pub fn decryption_nonce(&self) -> secretbox::Nonce {
        secretbox::Nonce(self.encryption_nonce)
    }

    /// The longterm public key of the peer.
    pub fn peer_longterm_pk(&self) -> sign::PublicKey {
        sign::PublicKey(self.peer_longterm_pk)
    }
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
    /// Creates and initializes a new `Client`.
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

    /// Writes the client challenge into `challenge` and updates the client state.
    pub fn create_msg1(&mut self, challenge: &mut [u8; MSG1_BYTES]) {
        unsafe { shs1_create_client_challenge(challenge, self) }
    }

    /// Verifies the given server `challenge` and updates the client state.
    pub fn verify_msg2(&mut self, challenge: &[u8; MSG1_BYTES]) -> bool {
        unsafe { shs1_verify_server_challenge(challenge, self) }
    }

    /// Writes the client authentication into `auth` and updates the client state.
    pub fn create_msg3(&mut self, auth: &mut [u8; MSG3_BYTES]) -> i32 {
        unsafe { shs1_create_client_auth(auth, self) }
    }

    /// Verifies the given server `ack`knowledgement and updates the client state.
    pub fn verify_msg4(&mut self, ack: &[u8; MSG4_BYTES]) -> bool {
        unsafe { shs1_verify_server_ack(ack, self) }
    }

    /// Computes the outcome of the handshake and writes it into `outcome`.
    pub fn outcome(&mut self, outcome: &mut Outcome) {
        unsafe { shs1_client_outcome(outcome, self) }
    }

    /// Zeros out all sensitive data in the `Client`.
    fn clean(&mut self) {
        unsafe { shs1_client_clean(self) }
    }
}

/// Zero out all sensitive data when going out of scope.
impl Drop for Client {
    fn drop(&mut self) {
        self.clean();
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
    /// Creates and initializes a new `Server`.
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

    /// Verifies the given client `challenge` and updates the server state.
    pub fn verify_msg1(&mut self, challenge: &[u8; MSG1_BYTES]) -> bool {
        unsafe { shs1_verify_client_challenge(challenge, self) }
    }

    /// Writes the server challenge into `challenge` and updates the server state.
    pub fn create_msg2(&mut self, challenge: &mut [u8; MSG2_BYTES]) {
        unsafe { shs1_create_server_challenge(challenge, self) }
    }

    /// Verifies the given client `auth`entication and updates the server state.
    pub fn verify_msg3(&mut self, auth: &[u8; MSG3_BYTES]) -> bool {
        unsafe { shs1_verify_client_auth(auth, self) }
    }

    /// Writes the server acknowledgement into `ack` and updates the server state.
    pub fn create_msg4(&mut self, ack: *mut [u8; MSG4_BYTES]) {
        unsafe { shs1_create_server_ack(ack, self) }
    }

    /// Computes the outcome of the handshake and writes it into `outcome`.
    pub fn outcome(&mut self, outcome: &mut Outcome) {
        unsafe { shs1_server_outcome(outcome, self) }
    }

    /// Zeros out all sensitive data in the `Server`.
    pub fn clean(&mut self) {
        unsafe { shs1_server_clean(self) }
    }

    /// Returns the longterm public key of the client. This will return
    /// uninitialized memory if called before the server verified msg3.
    pub unsafe fn client_longterm_pub(&self) -> [u8; sign::PUBLICKEYBYTES] {
        self.client_pub
    }
}

extern "C" {
    // client side
    fn shs1_create_client_challenge(challenge: *mut [u8; MSG1_BYTES], client: *mut Client);
    fn shs1_verify_server_challenge(challenge: *const [u8; MSG1_BYTES],
                                    client: *mut Client)
                                    -> bool;
    fn shs1_create_client_auth(auth: *mut [u8; MSG3_BYTES], client: *mut Client) -> i32;
    fn shs1_verify_server_ack(ack: *const [u8; MSG4_BYTES], client: *mut Client) -> bool;
    fn shs1_client_outcome(outcome: *mut Outcome, client: *mut Client);
    fn shs1_client_clean(client: *mut Client);
    // server side
    fn shs1_verify_client_challenge(challenge: *const [u8; MSG1_BYTES],
                                    server: *mut Server)
                                    -> bool;
    fn shs1_create_server_challenge(challenge: *mut [u8; MSG2_BYTES], server: *mut Server);
    fn shs1_verify_client_auth(auth: *const [u8; MSG3_BYTES], server: *mut Server) -> bool;
    fn shs1_create_server_ack(ack: *mut [u8; MSG4_BYTES], server: *mut Server);
    fn shs1_server_outcome(outcome: *mut Outcome, server: *mut Server);
    fn shs1_server_clean(server: *mut Server);
}

/// Zero out all sensitive data when going out of scope.
impl Drop for Server {
    fn drop(&mut self) {
        self.clean();
    }
}
