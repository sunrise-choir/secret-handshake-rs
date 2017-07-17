use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;
use std::ptr;
use std::mem;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::scalarmult::{scalarmult, Scalar, GroupElement, GROUPELEMENTBYTES};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox;

// use crypto::ClientChallenge;
// use crypto::ServerChallenge;
// use crypto::ClientAuth;
// use crypto::ServerAuth;
//
// use ffi::ed25519_pk_to_curve25519 as curvify_pub;
// use ffi::ed25519_sk_to_curve25519 as curvify_sec;
//
// // TODO with the current API, the user could write to the original stream when
// // a MidHandshakeClientStream is returned. This could be solved by taking
// // ownership of the stream in Client.shake_hands (which would then return the
// // stream when successful)
// // TODO check whether the above is true, or whether borrow and mutability
// // checker are smart enough
//
// // TODO Result type alias
//
// /// A builder for `Client`s.
// pub struct ClientBuilder {
//     pub_key: sign::PublicKey,
//     sec_key: sign::SecretKey,
//     server_pub: sign::PublicKey,
//     app_key: auth::Key,
//     eph_pub: Option<box_::PublicKey>,
//     eph_sec: Option<box_::SecretKey>,
// }
//
// impl ClientBuilder {
//     fn new(pub_key: sign::PublicKey,
//            sec_key: sign::SecretKey,
//            server_pub: sign::PublicKey,
//            app_key: auth::Key)
//            -> ClientBuilder {
//         ClientBuilder {
//             pub_key,
//             sec_key,
//             server_pub,
//             app_key,
//             eph_pub: None,
//             eph_sec: None,
//         }
//     }
//
//     /// Specify the ephemeral keys to use for the handshake.
//     ///
//     /// If this is not called, a random keypair is generated and used.
//     pub fn ephemeral_keypair(&mut self,
//                              eph_pub: box_::PublicKey,
//                              eph_sec: box_::SecretKey)
//                              -> &mut ClientBuilder {
//         self.eph_pub = Some(eph_pub);
//         self.eph_sec = Some(eph_sec);
//         self
//     }
//
//     /// Consumes the builder, returning an `Client`.
//     pub fn build(self) -> Client {
//         let (eph_pub, eph_sec) = if self.eph_pub.is_none() {
//             box_::gen_keypair()
//         } else {
//             (self.eph_pub.unwrap(), self.eph_sec.unwrap())
//         };
//
//         unsafe {
//             Client {
//                 pub_key: self.pub_key,
//                 sec_key: self.sec_key,
//                 server_pub: self.server_pub,
//                 app_hmac: auth::authenticate(&eph_pub[..], &self.app_key),
//                 app_key: self.app_key,
//                 eph_pub,
//                 eph_sec,
//                 server_eph_pub: mem::uninitialized(),
//                 shared_secret: mem::uninitialized(),
//                 shared_hash: mem::uninitialized(),
//                 server_lterm_shared: mem::uninitialized(),
//                 client_auth: mem::uninitialized(),
//                 box_secret: mem::uninitialized(),
//             }
//         }
//     }
// }
//
// /// Performs the client part of a secret-handshake.
// // This could be optimized because not all fields are required at the same time
// // TODO check which of the fields are actually used in more than one method
// pub struct Client {
//     pub_key: sign::PublicKey,
//     sec_key: sign::SecretKey,
//     server_pub: sign::PublicKey,
//     app_key: auth::Key,
//     eph_pub: box_::PublicKey, // a
//     eph_sec: box_::SecretKey,
//     app_hmac: auth::Tag,
//     server_eph_pub: box_::PublicKey, // b
//     shared_secret: GroupElement, // (a * b)
//     shared_hash: sha256::Digest, // hash(a * b)
//     server_lterm_shared: GroupElement, // (a * B)
//     client_auth: [u8; 96], // H = sign(A)[K | Bp | hash(a * b)] | A_p
//     box_secret: sha256::Digest, // hash(K | a * b | a * B | A * b)
// }
//
// impl Client {
//     /// Returns a new builder for a `Client`. All arguments are
//     /// required for the handshake. Optional arguments may be specified using
//     /// the builder.
//     ///
//     /// `client_pub` is sent to the peer during the handshake. The handshake
//     /// fails if the peer's public key is not `server_pub`.
//     ///
//     /// The handshake also fails if `app_key` does not match the `app_key` of
//     /// the peer.
//     pub fn builder(client_pub: sign::PublicKey,
//                    client_sec: sign::SecretKey,
//                    server_pub: sign::PublicKey,
//                    app_key: auth::Key)
//                    -> ClientBuilder {
//         ClientBuilder::new(client_pub, client_sec, server_pub, app_key)
//     }
//
//     fn create_challenge(&self) -> ClientChallenge {
//         let challenge_ptr: *mut ClientChallenge = &mut [0u8; 64];
//
//         unsafe {
//             ptr::write(challenge_ptr as *mut [u8; 32], self.app_hmac.0);
//             ptr::write((challenge_ptr as *mut [u8; 32]).offset(1), self.eph_pub.0);
//             *challenge_ptr
//         }
//     }
//
//     fn verify_server_challenge(&mut self, challenge: &ServerChallenge) -> bool {
//         let server_eph_pub_slice = &challenge[32..];
//         let sent_hmac = unsafe { &*(challenge as *const ClientChallenge as *const auth::Tag) };
//
//         let ok = auth::verify(sent_hmac, server_eph_pub_slice, &self.app_key);
//
//         if ok {
//             unsafe {
//                 // b
//                 ptr::write(&mut self.server_eph_pub,
//                            box_::PublicKey(*((challenge as *const ServerChallenge) as
//                                              *const [u8; 32])));
//
//                 // (a * b)
//                 ptr::write(&mut self.shared_secret,
//                            scalarmult(&Scalar(self.eph_pub.0),
//                                       &GroupElement(self.server_eph_pub.0))
//                                    .unwrap());
//
//                 // hash(a * b)
//                 ptr::write(&mut self.shared_hash, sha256::hash(&self.shared_secret.0));
//             }
//         }
//
//         ok
//     }
//
//     fn create_client_auth(&mut self) -> ClientAuth {
//         let curve_server_pub = curvify_pub(&self.server_pub);
//
//         // (a * B)
//         unsafe {
//             ptr::write(&mut self.server_lterm_shared,
//                        scalarmult(&Scalar(self.eph_pub.0), &GroupElement(curve_server_pub.0))
//                            .unwrap());
//         }
//
//         // K | a * b | a * B
//         let mut tmp: [u8; auth::KEYBYTES + GROUPELEMENTBYTES + GROUPELEMENTBYTES] = [0; 96];
//         let tmp_ptr = &mut tmp as *mut [u8; 96] as *mut [u8; 32];
//         unsafe {
//             ptr::write(tmp_ptr, self.app_key.0);
//             ptr::write(tmp_ptr.offset(1), self.shared_secret.0);
//             ptr::write(tmp_ptr.offset(2), self.server_lterm_shared.0);
//         }
//         let tmp = tmp;
//
//         // hash(K | a * b | a * B)
//         let box_secret = secretbox::Key(sha256::hash(&tmp).0);
//
//         // K | Bp | hash(a * b)
//         let mut tmp2: [u8; auth::KEYBYTES + sign::PUBLICKEYBYTES + sha256::DIGESTBYTES] = [0; 96];
//         let tmp2_ptr = &mut tmp2 as *mut [u8; 96] as *mut [u8; 32];
//         unsafe {
//             ptr::write(tmp2_ptr, self.app_key.0);
//             ptr::write(tmp2_ptr.offset(1), self.server_pub.0);
//             ptr::write(tmp2_ptr.offset(2), self.shared_hash.0);
//         }
//         let tmp2 = tmp2;
//
//         // sign(A)[K | Bp | hash(a * b)]
//         let signature = sign::sign_detached(&tmp2, &self.sec_key);
//
//         // H = sign(A)[K | Bp | hash(a * b)] | A_p
//         let mut message_to_box: [u8; sign::SIGNATUREBYTES + sign::PUBLICKEYBYTES] = [0; 96];
//         let message_to_box_ptr = &mut message_to_box as *mut [u8; 96] as *mut [u8; 32];
//         unsafe {
//             ptr::write(message_to_box_ptr as *mut [u8; 64], signature.0);
//             ptr::write(message_to_box_ptr.offset(2), self.pub_key.0);
//
//             ptr::write(&mut self.client_auth, message_to_box);
//         }
//         let message_to_box = message_to_box;
//
//         let nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
//
//         // return box(K | a * b | a * B)[H]
//         let client_auth_vec: Vec<u8> = secretbox::seal(&message_to_box, &nonce, &box_secret);
//
//         let mut client_auth = [0u8; 64];
//         unsafe {
//             // TODO write lower-level binding to sodium to secretbox::seal directly into the array
//             ptr::write(&mut client_auth,
//                        *(client_auth_vec.as_ptr() as *const [u8; 64]))
//         }
//         client_auth
//     }
//
//     fn verify_server_auth(&mut self, auth: &ServerAuth) -> bool {
//         let curve_client_sec = curvify_sec(&self.sec_key);
//
//         // (A * b)
//         let local_lterm_shared = scalarmult(&Scalar(curve_client_sec.0),
//                                             &GroupElement(self.server_eph_pub.0))
//                 .unwrap();
//
//         unsafe {
//             // hash(K | _ptra * b | a * B | A * b)
//             let mut tmp: [u8; 128] = mem::uninitialized();
//             let tmp_ptr = &mut tmp as *mut [u8; 128] as *mut [u8; 32];
//             ptr::write(tmp_ptr, self.app_key.0);
//             ptr::write(tmp_ptr.offset(1), self.shared_secret.0);
//             ptr::write(tmp_ptr.offset(2), self.server_lterm_shared.0);
//             ptr::write(tmp_ptr.offset(3), local_lterm_shared.0);
//
//             ptr::write(&mut self.box_secret, sha256::hash(&tmp));
//         }
//
//         let nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
//
//         secretbox::open();
//
//         unimplemented!()
//     }
//
//     /// Initiates a handshake on the given stream.
//     ///
//     /// After the handshake has been performed, the stream can be reused. All
//     /// further communication on the stream remains unencrypted.
//     ///
//     /// If the stream is nonblocking and a `WouldBlock` error is returned during
//     /// the handshake, a `HandshakeError::Interrupted` error will be returned
//     /// which can be used to restart the handshake when the socket is ready
//     /// again.
//     ///
//     /// Note: This function does *not* conform to the secret-handshake protocol.
//     /// Instead it reproduces
//     /// [a mistake](https://github.com/auditdrivencrypto/secret-handshake/issues/7)
//     /// in the reference implementation. Use this if interoperability with peers
//     /// using the old reference implementation is necessary. When the reference
//     /// implementation is fixed, a new major version of this package will be
//     /// released in which `shake_hands` implements the spec-conforming
//     /// behaviour.
//     pub fn shake_hands<'a, 'b, S>(&'b mut self,
//                                   stream: &'a mut S)
//                                   -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         let challenge = self.create_challenge();
//         return self.send_client_challenge(stream, challenge);
//     }
//
//     // The first part of the handshake: Send the client challenge to the server.
//     fn send_client_challenge<'a, 'b, S>(&'b mut self,
//                                         stream: &'a mut S,
//                                         challenge: ClientChallenge)
//                                         -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         match stream.write(&challenge) {
//             Ok(_) => {
//                 return self.receive_server_challenge(stream);
//             }
//             Err(e) => {
//                 match e.kind() {
//                     io::ErrorKind::WouldBlock => {
//                         let resumer = MidHandshakeClientStream {
//                             stream: stream,
//                             client: self,
//                             state: ResumeState::SendClientChallenge(challenge),
//                         };
//                         return Err(ClientHandshakeError::Interrupted(resumer));
//                     }
//                     _ => return Err(ClientHandshakeError::SendChallengeFail(e)),
//                 }
//             }
//         }
//     }
//
//     // The second part of the handshake: Receive the challenge from the server.
//     fn receive_server_challenge<'a, 'b, S>(&'b mut self,
//                                            stream: &'a mut S)
//                                            -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         let mut challenge: ServerChallenge = [0u8; 64];
//         let result = stream.read_exact(&mut challenge);
//         let challenge = challenge;
//
//         match result {
//             Ok(_) => {
//                 if self.verify_server_challenge(&challenge) {
//                     let auth = self.create_client_auth();
//                     return self.send_client_auth(stream, auth);
//                 } else {
//                     return Err(ClientHandshakeError::InvalidChallenge);
//                 }
//             }
//             Err(e) => {
//                 match e.kind() {
//                     io::ErrorKind::WouldBlock => {
//                         let resumer = MidHandshakeClientStream {
//                             stream: stream,
//                             client: self,
//                             state: ResumeState::ReceiveServerChallenge,
//                         };
//                         return Err(ClientHandshakeError::Interrupted(resumer));
//                     }
//                     _ => return Err(ClientHandshakeError::ReceiveChallengeFail(e)),
//                 }
//             }
//         }
//     }
//
//     // The third part of the handshake: Send the client authorization to the server.
//     fn send_client_auth<'a, 'b, S>(&'b mut self,
//                                    stream: &'a mut S,
//                                    auth: ClientAuth)
//                                    -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         match stream.write(&auth) {
//             Ok(_) => {
//                 return self.receive_server_auth(stream);
//             }
//             Err(e) => {
//                 match e.kind() {
//                     io::ErrorKind::WouldBlock => {
//                         let resumer = MidHandshakeClientStream {
//                             stream: stream,
//                             client: self,
//                             state: ResumeState::SendClientAuth(auth),
//                         };
//                         return Err(ClientHandshakeError::Interrupted(resumer));
//                     }
//                     _ => return Err(ClientHandshakeError::SendAuthFail(e)),
//                 }
//             }
//         }
//     }
//
//     // The fourth part of the handshake: Receive authentication from the server.
//     fn receive_server_auth<'a, 'b, S>(&'b mut self,
//                                       stream: &'a mut S)
//                                       -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         let mut auth: ServerAuth = [0u8; 64];
//         let result = stream.read_exact(&mut auth);
//         let auth = auth;
//
//         match result {
//             Ok(_) => {
//                 if self.verify_server_auth(&auth) {
//                     // TODO correct arguments
//                     return Err(ClientHandshakeError::InvalidChallenge); // TODO return Outcome
//                 } else {
//                     return Err(ClientHandshakeError::InvalidAuth);
//                 }
//             }
//             Err(e) => {
//                 match e.kind() {
//                     io::ErrorKind::WouldBlock => {
//                         let resumer = MidHandshakeClientStream {
//                             stream: stream,
//                             client: self,
//                             state: ResumeState::ReceiveServerAuth,
//                         };
//                         return Err(ClientHandshakeError::Interrupted(resumer));
//                     }
//                     _ => return Err(ClientHandshakeError::ReceiveAuthFail(e)),
//                 }
//             }
//         }
//     }
// }
//
// /// An error that occured during the handshake.
// ///
// /// The variants wrapping an io::Error never wrap a `WouldBlock`, these cases
// /// are always handled by the `Interrupted` variant.
// #[derive(Debug)]
// pub enum ClientHandshakeError<'a, 'b, S: 'a> {
//     /// Failed to send the challenge to the server.
//     SendChallengeFail(io::Error),
//     /// Failed to receive the challenge from the server.
//     ReceiveChallengeFail(io::Error),
//     /// The received challenge is invalid, e.g. because the server assumed a
//     /// wrong protocol (version).
//     InvalidChallenge,
//     /// Failed to send authentication to the server.
//     SendAuthFail(io::Error),
//     /// Failed to receive authentication from the server.
//     ReceiveAuthFail(io::Error),
//     /// Received invalid authentication from the server.
//     InvalidAuth,
//     /// A stream interrupted midway through the handshake process due to a
//     /// `WouldBlock` error.
//     ///
//     /// Note that this is not a fatal error and it should be safe to call
//     /// `resume_handshake` at a later time once the stream is ready to perform
//     /// I/O again.
//     Interrupted(MidHandshakeClientStream<'a, 'b, S>),
// }
//
// impl<'a, 'b, S> fmt::Display for ClientHandshakeError<'a, 'b, S>
//     where S: fmt::Debug
// {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         try!(fmt.write_str(self.description()));
//         if let Some(cause) = self.cause() {
//             try!(write!(fmt, ": {}", cause));
//         }
//         Ok(())
//     }
// }
//
// impl<'a, 'b, S> error::Error for ClientHandshakeError<'a, 'b, S>
//     where S: fmt::Debug
// {
//     fn description(&self) -> &str {
//         match *self {
//             ClientHandshakeError::SendChallengeFail(ref err) => err.description(),
//             ClientHandshakeError::ReceiveChallengeFail(ref err) => err.description(),
//             ClientHandshakeError::InvalidChallenge => "received invalid challenge",
//             ClientHandshakeError::SendAuthFail(ref err) => err.description(),
//             ClientHandshakeError::ReceiveAuthFail(ref err) => err.description(),
//             ClientHandshakeError::InvalidAuth => "received invalid authentication",
//             ClientHandshakeError::Interrupted(_) => "underlying stream would have blocked",
//         }
//     }
//
//     fn cause(&self) -> Option<&error::Error> {
//         match *self {
//             ClientHandshakeError::SendChallengeFail(ref err) => Some(err),
//             ClientHandshakeError::ReceiveChallengeFail(ref err) => Some(err),
//             ClientHandshakeError::InvalidChallenge => None,
//             ClientHandshakeError::SendAuthFail(ref err) => Some(err),
//             ClientHandshakeError::ReceiveAuthFail(ref err) => Some(err),
//             ClientHandshakeError::InvalidAuth => None,
//             ClientHandshakeError::Interrupted(_) => None,
//         }
//     }
// }
//
// /// An shs client stream which has been interrupted midway through the handshake
// /// process.
// ///
// /// Instances of this are obtained when the underying stream of a
// /// `Client` returns a `WouldBlock` error on a read or write. The instance
// /// can be used to resume the handshake when the stream is ready to perform I/O
// /// again.
// pub struct MidHandshakeClientStream<'a, 'b, S: 'a> {
//     stream: &'a mut S,
//     client: &'b mut Client,
//     state: ResumeState,
// }
//
// impl<'a, 'b, S> MidHandshakeClientStream<'a, 'b, S>
//     where S: io::Read + io::Write
// {
//     /// Returns a shared reference to the inner stream.
//     pub fn get_ref(&self) -> &S {
//         self.stream
//     }
//
//     /// Returns a mutable reference to the inner stream.
//     pub fn get_mut(&mut self) -> &mut S {
//         &mut self.stream
//     }
//
//     /// Resumes the handshake process.
//     pub fn resume_handshake(self) -> Result<Outcome, ClientHandshakeError<'a, 'b, S>> {
//         self.state.resume(self.client, self.stream)
//     }
// }
//
// impl<'a, 'b, S> fmt::Debug for MidHandshakeClientStream<'a, 'b, S>
//     where S: fmt::Debug
// {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Debug::fmt(self.stream, fmt)
//     }
// }
//
// // indicates where a MidHandshakeClientStream should resume the handshake
// enum ResumeState {
//     SendClientChallenge(ClientChallenge),
//     ReceiveServerChallenge,
//     SendClientAuth(ClientAuth),
//     ReceiveServerAuth,
// }
//
// impl ResumeState {
//     fn resume<'a, 'b, S>(&self,
//                          client: &'b mut Client,
//                          stream: &'a mut S)
//                          -> Result<Outcome, ClientHandshakeError<'a, 'b, S>>
//         where S: io::Read + io::Write
//     {
//         match *self {
//             ResumeState::SendClientChallenge(challenge) => {
//                 client.send_client_challenge(stream, challenge)
//             }
//             ResumeState::ReceiveServerChallenge => client.receive_server_challenge(stream),
//             ResumeState::SendClientAuth(auth) => client.send_client_auth(stream, auth),
//             ResumeState::ReceiveServerAuth => client.receive_server_auth(stream),
//         }
//     }
// }
