use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;

use crypto;

// /// A builder for `Server`s.
// #[derive(Clone)]
// pub struct ServerBuilder {
//     server_pub: sign::PublicKey,
//     server_sec: sign::SecretKey,
//     app_key: auth::Key,
//     ephemeral_pub: Option<box_::PublicKey>,
//     ephemeral_sec: Option<box_::SecretKey>,
//     authorize: Option<fn(sign::PublicKey) -> bool>,
// }
//
// impl ServerBuilder {
//     fn new(server_pub: sign::PublicKey,
//            server_sec: sign::SecretKey,
//            app_key: auth::Key)
//            -> ServerBuilder {
//         ServerBuilder {
//             server_pub,
//             server_sec,
//             app_key,
//             ephemeral_pub: None,
//             ephemeral_sec: None,
//             authorize: None,
//         }
//     }
//
//     /// Specify the ephemeral keys to use for the handshake.
//     ///
//     /// If this is not called, a random keypair is generated and used.
//     pub fn ephemeral_keypair(&mut self,
//                              pub_key: box_::PublicKey,
//                              sec_key: box_::SecretKey)
//                              -> &mut ServerBuilder {
//         self.ephemeral_pub = Some(pub_key);
//         self.ephemeral_sec = Some(sec_key);
//         self
//     }
//
//     /// Specify an authorization function.
//     ///
//     /// This function is called with the public key of the client, and the
//     /// handshake is aborted if the function does not return true. If this is
//     /// not specified, the server will simply accept all clients.
//     pub fn authorize(&mut self, authorize: fn(sign::PublicKey) -> bool) -> &mut ServerBuilder {
//         self.authorize = Some(authorize);
//         self
//     }
//
//     /// Consumes the builder, returning a `Server`.
//     pub fn build(self) -> Server {
//         let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
//         Server {
//             server_pub: self.server_pub,
//             server_sec: self.server_sec,
//             app_key: self.app_key,
//             ephemeral_pub: self.ephemeral_pub.unwrap_or(ephemeral_pub),
//             ephemeral_sec: self.ephemeral_sec.unwrap_or(ephemeral_sec),
//             authorize: self.authorize.unwrap_or(const_true),
//         }
//     }
// }
//
// /// Performs the server part of a secret-handshake.
// #[derive(Clone)]
// pub struct Server {
//     server_pub: sign::PublicKey,
//     server_sec: sign::SecretKey,
//     app_key: auth::Key,
//     ephemeral_pub: box_::PublicKey,
//     ephemeral_sec: box_::SecretKey,
//     authorize: fn(sign::PublicKey) -> bool,
// }
//
// impl Server {
//     /// Returns a new builder for a `Server`. All arguments are
//     /// required for the handshake. Optional arguments may be specified using
//     /// the builder.
//     ///
//     /// `server_pub` is sent to the peer during the handshake.
//     ///
//     /// The handshake fails if `app_key` does not match the `app_key` of
//     /// the peer.
//     pub fn builder(server_pub: sign::PublicKey,
//                    server_sec: sign::SecretKey,
//                    app_key: auth::Key)
//                    -> ServerBuilder {
//         ServerBuilder::new(server_pub, server_sec, app_key)
//     }
//
//     /// Responds to a handshake on the given stream.
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
//     pub fn shake_hands<S>(&self, stream: &S) -> Result<Outcome, ServerHandshakeError<S>>
//         where S: io::Read + io::Write
//     {
//         Err(ServerHandshakeError::InvalidChallenge) // TODO
//     }
// }
//
// /// An error that occured during the handshake.
// ///
// /// The variants wrapping an io::Error never wrap a `WouldBlock`, these cases
// /// are always handled by the `Interrupted` variant.
// #[derive(Debug)]
// pub enum ServerHandshakeError<S> {
//     /// Failed to send the challenge to the peer.
//     SendChallengeFail(io::Error),
//     /// Failed to receive the challenge from the peer.
//     ReceiveChallengeFail(io::Error),
//     /// The received challenge is invalid, e.g. because the peer assumed a wrong
//     /// protocol (version).
//     InvalidChallenge, // TODO add data?
//     /// Failed to send authentication to the peer.
//     SendAuthFail(io::Error),
//     /// Failed to receive authentiction from the peer.
//     ReceiveAuthFail(io::Error),
//     /// Received invalid authentication from the peer.
//     InvalidAuth, // TODO add data?
//     /// A stream interrupted midway through the handshake process due to a
//     /// `WouldBlock` error.
//     ///
//     /// Note that this is not a fatal error and it should be safe to call
//     /// `resume_handshake` at a later time once the stream is ready to perform
//     /// I/O again.
//     Interrupted(MidHandshakeServerStream<S>),
// }
//
// impl<S> fmt::Display for ServerHandshakeError<S>
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
// impl<S> error::Error for ServerHandshakeError<S>
//     where S: fmt::Debug
// {
//     fn description(&self) -> &str {
//         match *self {
//             ServerHandshakeError::SendChallengeFail(ref err) => err.description(),
//             ServerHandshakeError::ReceiveChallengeFail(ref err) => err.description(),
//             ServerHandshakeError::InvalidChallenge => "received invalid challenge",
//             ServerHandshakeError::SendAuthFail(ref err) => err.description(),
//             ServerHandshakeError::ReceiveAuthFail(ref err) => err.description(),
//             ServerHandshakeError::InvalidAuth => "received invalid authentication",
//             ServerHandshakeError::Interrupted(_) => "underlying stream would have blocked",
//         }
//     }
//
//     fn cause(&self) -> Option<&error::Error> {
//         match *self {
//             ServerHandshakeError::SendChallengeFail(ref err) => Some(err),
//             ServerHandshakeError::ReceiveChallengeFail(ref err) => Some(err),
//             ServerHandshakeError::InvalidChallenge => None,
//             ServerHandshakeError::SendAuthFail(ref err) => Some(err),
//             ServerHandshakeError::ReceiveAuthFail(ref err) => Some(err),
//             ServerHandshakeError::InvalidAuth => None,
//             ServerHandshakeError::Interrupted(_) => None,
//         }
//     }
// }
//
// /// A server stream which has been interrupted midway through the handshake
// /// process.
// ///
// /// Instances of this are obtained when the underying stream of an
// /// `Server` returns a `WouldBlock` error on a read or write. The instance
// /// can be used to resume the handshake when the stream is ready to perform I/O
// /// again.
// pub struct MidHandshakeServerStream<S>(S);
//
// impl<S> MidHandshakeServerStream<S>
//     where S: io::Read + io::Write
// {
//     /// Returns a shared reference to the inner stream.
//     pub fn get_ref(&self) -> &S {
//         &self.0
//     }
//
//     /// Returns a mutable reference to the inner stream.
//     pub fn get_mut(&mut self) -> &mut S {
//         &mut self.0
//     }
//
//     /// Resumes the handshake process.
//     pub fn resume_handshake(self) -> Result<Outcome, ServerHandshakeError<S>> {
//         Err(ServerHandshakeError::InvalidChallenge) // TODO
//     }
// }
//
// impl<S> fmt::Debug for MidHandshakeServerStream<S>
//     where S: fmt::Debug
// {
//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Debug::fmt(&self.0, fmt)
//     }
// }
//
// fn const_true<T>(_: T) -> bool {
//     true
// }
