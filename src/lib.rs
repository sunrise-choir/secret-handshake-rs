//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol.
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! shs = "0.1"
//! ```
#![warn(missing_docs)]

extern crate sodiumoxide;

use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;

mod crypto;

// TODO doc comment warning that this does not perform any encryption
// TODO terminology: client/server vs connector/acceptor

/// The data resulting from a handshake: Keys and nonces suitable for encrypted
/// two-way communication with the peer via sodium boxes.
pub struct Outcome {
    /// A secret key for sealing boxes. The `decryption_key` of the peer's
    /// `Outcome` can be used to open these boxes.
    pub encryption_key: box_::SecretKey,
    /// A nonce for sealing boxes. The `decryption_nonce` of the peer's
    /// `Outcome` matches this one.
    pub encryption_nonce: box_::Nonce,
    /// A public key for opening boxes. It can decrypt boxes sealed with the
    /// `encryption_key` of the peer's `Outcome`.
    pub decryption_key: box_::PublicKey,
    /// A nonce for opening boxes. It matches the `encryption_nonce` of the
    /// peer's `Outcome`.
    pub decryption_nonce: box_::Nonce,
}

/// A builder for `ShsConnector`s.
pub struct ShsConnectorBuilder {
    client_pub: sign::PublicKey,
    client_sec: sign::SecretKey,
    server_pub: sign::PublicKey,
    app_key: auth::Key,
    ephemeral_pub: Option<box_::PublicKey>,
    ephemeral_sec: Option<box_::SecretKey>,
}

impl ShsConnectorBuilder {
    fn new(client_pub: sign::PublicKey,
           client_sec: sign::SecretKey,
           server_pub: sign::PublicKey,
           app_key: auth::Key)
           -> ShsConnectorBuilder {
        ShsConnectorBuilder {
            client_pub,
            client_sec,
            server_pub,
            app_key,
            ephemeral_pub: None,
            ephemeral_sec: None,
        }
    }

    /// Specify the ephemeral keys to use for the handshake.
    ///
    /// If this is not called, a random keypair is generated and used.
    pub fn ephemeral_keypair(&mut self,
                             pub_key: box_::PublicKey,
                             sec_key: box_::SecretKey)
                             -> &mut ShsConnectorBuilder {
        self.ephemeral_pub = Some(pub_key);
        self.ephemeral_sec = Some(sec_key);
        self
    }

    /// Consumes the builder, returning an `ShsConnector`.
    pub fn build(self) -> ShsConnector {
        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
        ShsConnector {
            client_pub: self.client_pub,
            client_sec: self.client_sec,
            server_pub: self.server_pub,
            app_key: self.app_key,
            ephemeral_pub: self.ephemeral_pub.unwrap_or(ephemeral_pub),
            ephemeral_sec: self.ephemeral_sec.unwrap_or(ephemeral_sec),
        }
    }
}

/// Performs the client part of a secret-handshake.
pub struct ShsConnector {
    client_pub: sign::PublicKey,
    client_sec: sign::SecretKey,
    server_pub: sign::PublicKey,
    app_key: auth::Key,
    ephemeral_pub: box_::PublicKey,
    ephemeral_sec: box_::SecretKey,
}

impl ShsConnector {
    /// Returns a new builder for an `ShsConnector`. All arguments are
    /// required for the handshake. Optional arguments may be specified using
    /// the builder.
    ///
    /// `client_pub` is sent to the peer during the handshake. The handshake
    /// fails if the peer's public key is not `server_pub`.
    ///
    /// The handshake also fails if `app_key` does not match the `app_key` of
    /// the peer.
    pub fn builder(client_pub: sign::PublicKey,
                   client_sec: sign::SecretKey,
                   server_pub: sign::PublicKey,
                   app_key: auth::Key)
                   -> ShsConnectorBuilder {
        ShsConnectorBuilder::new(client_pub, client_sec, server_pub, app_key)
    }

    /// Initiates a handshake on the given stream.
    ///
    /// After the handshake has been performed, the stream can be reused. All
    /// further communication on the stream remains unencrypted.
    ///
    /// If the stream is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn shake_hands<S>(&self, stream: &S) -> Result<Outcome, ConnectorHandshakeError<S>>
        where S: io::Read + io::Write
    {
        Err(ConnectorHandshakeError::InvalidChallenge) // TODO
    }

    /// Initiates a handshake on the given stream.
    ///
    /// Note: This function does not conform to the secret-handshake protocol.
    /// Instead it reproduces a mistake in the reference implementation. Use
    /// this if interoperability with peers using the old reference
    /// implementation is necessary. If interoperability is not a concern, use
    /// `create_server_challenge` instead.
    ///
    /// After the handshake has been performed, the stream can be reused. All
    /// further communication on the stream remains unencrypted.
    ///
    /// If the stream is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    #[deprecated(note="the legacy methods will be removed when the shs ecosystem stops using the faulty implementation")]
    pub fn legacy_shake_hands<S>(&self, stream: &S) -> Result<Outcome, ConnectorHandshakeError<S>>
        where S: io::Read + io::Write
    {
        // let client_challenge = crypto::create_client_challenge(&self.app_key, &self.ephemeral_pub);
        //
        // stream.write(&[0]);

        Err(ConnectorHandshakeError::InvalidChallenge) // TODO
    }
}

/// An error that occured during the handshake.
///
/// The variants wrapping an io::Error never wrap a `WouldBlock`, these cases
/// are always handled by the `Interrupted` variant.
#[derive(Debug)]
pub enum ConnectorHandshakeError<S> {
    /// Failed to send the challenge to the peer.
    SendChallengeFail(io::Error),
    /// Failed to receive the challenge from the peer.
    ReceiveChallengeFail(io::Error),
    /// The received challenge is invalid, e.g. because the peer assumed a wrong
    /// protocol (version).
    InvalidChallenge, // TODO add data?
    /// Failed to send authentication to the peer.
    SendAuthFail(io::Error),
    /// Failed to receive authentiction from the peer.
    ReceiveAuthFail(io::Error),
    /// Received invalid authentication from the peer.
    InvalidAuth, // TODO add data?
    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `resume_handshake` at a later time once the stream is ready to perform
    /// I/O again.
    Interrupted(MidHandshakeShsConnectorStream<S>),
}

impl<S> fmt::Display for ConnectorHandshakeError<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S> error::Error for ConnectorHandshakeError<S>
    where S: fmt::Debug
{
    fn description(&self) -> &str {
        match *self {
            ConnectorHandshakeError::SendChallengeFail(ref err) => err.description(),
            ConnectorHandshakeError::ReceiveChallengeFail(ref err) => err.description(),
            ConnectorHandshakeError::InvalidChallenge => "received invalid challenge",
            ConnectorHandshakeError::SendAuthFail(ref err) => err.description(),
            ConnectorHandshakeError::ReceiveAuthFail(ref err) => err.description(),
            ConnectorHandshakeError::InvalidAuth => "received invalid authentication",
            ConnectorHandshakeError::Interrupted(_) => "underlying stream would have blocked",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ConnectorHandshakeError::SendChallengeFail(ref err) => Some(err),
            ConnectorHandshakeError::ReceiveChallengeFail(ref err) => Some(err),
            ConnectorHandshakeError::InvalidChallenge => None,
            ConnectorHandshakeError::SendAuthFail(ref err) => Some(err),
            ConnectorHandshakeError::ReceiveAuthFail(ref err) => Some(err),
            ConnectorHandshakeError::InvalidAuth => None,
            ConnectorHandshakeError::Interrupted(_) => None,
        }
    }
}

/// An shs client stream which has been interrupted midway through the handshake
/// process.
///
/// Instances of this are obtained when the underying stream of an
/// `ShsConnector` returns a `WouldBlock` error on a read or write. The instance
/// can be used to resume the handshake when the stream is ready to perform I/O
/// again.
pub struct MidHandshakeShsConnectorStream<S>(S);

impl<S> MidHandshakeShsConnectorStream<S>
    where S: io::Read + io::Write
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.0
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Resumes the handshake process.
    pub fn resume_handshake(self) -> Result<Outcome, ConnectorHandshakeError<S>> {
        Err(ConnectorHandshakeError::InvalidChallenge) // TODO
    }
}

impl<S> fmt::Debug for MidHandshakeShsConnectorStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

/// A builder for `ShsAcceptor`s.
#[derive(Clone)]
pub struct ShsAcceptorBuilder {
    server_pub: sign::PublicKey,
    server_sec: sign::SecretKey,
    app_key: auth::Key,
    ephemeral_pub: Option<box_::PublicKey>,
    ephemeral_sec: Option<box_::SecretKey>,
    authorize: Option<fn(sign::PublicKey) -> bool>,
}

impl ShsAcceptorBuilder {
    fn new(server_pub: sign::PublicKey,
           server_sec: sign::SecretKey,
           app_key: auth::Key)
           -> ShsAcceptorBuilder {
        ShsAcceptorBuilder {
            server_pub,
            server_sec,
            app_key,
            ephemeral_pub: None,
            ephemeral_sec: None,
            authorize: None,
        }
    }

    /// Specify the ephemeral keys to use for the handshake.
    ///
    /// If this is not called, a random keypair is generated and used.
    pub fn ephemeral_keypair(&mut self,
                             pub_key: box_::PublicKey,
                             sec_key: box_::SecretKey)
                             -> &mut ShsAcceptorBuilder {
        self.ephemeral_pub = Some(pub_key);
        self.ephemeral_sec = Some(sec_key);
        self
    }

    /// Specify an authorization function.
    ///
    /// This function is called with the public key of the client, and the
    /// handshake is aborted if the function does not return true. If this is
    /// not specified, the server will simply accept all clients.
    pub fn authorize(&mut self, authorize: fn(sign::PublicKey) -> bool) -> &mut ShsAcceptorBuilder {
        self.authorize = Some(authorize);
        self
    }

    /// Consumes the builder, returning a `ShsAccecptor`.
    pub fn build(self) -> ShsAcceptor {
        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
        ShsAcceptor {
            server_pub: self.server_pub,
            server_sec: self.server_sec,
            app_key: self.app_key,
            ephemeral_pub: self.ephemeral_pub.unwrap_or(ephemeral_pub),
            ephemeral_sec: self.ephemeral_sec.unwrap_or(ephemeral_sec),
            authorize: self.authorize.unwrap_or(const_true),
        }
    }
}

/// Performs the server part of a secret-handshake.
#[derive(Clone)]
pub struct ShsAcceptor {
    server_pub: sign::PublicKey,
    server_sec: sign::SecretKey,
    app_key: auth::Key,
    ephemeral_pub: box_::PublicKey,
    ephemeral_sec: box_::SecretKey,
    authorize: fn(sign::PublicKey) -> bool,
}

impl ShsAcceptor {
    /// Returns a new builder for a `ShsAcceptor`. All arguments are
    /// required for the handshake. Optional arguments may be specified using
    /// the builder.
    ///
    /// `server_pub` is sent to the peer during the handshake.
    ///
    /// The handshake fails if `app_key` does not match the `app_key` of
    /// the peer.
    pub fn builder(server_pub: sign::PublicKey,
                   server_sec: sign::SecretKey,
                   app_key: auth::Key)
                   -> ShsAcceptorBuilder {
        ShsAcceptorBuilder::new(server_pub, server_sec, app_key)
    }

    /// Responds to a handshake on the given stream.
    ///
    /// After the handshake has been performed, the stream can be reused. All
    /// further communication on the stream remains unencrypted.
    ///
    /// If the stream is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn shake_hands<S>(&self, stream: &S) -> Result<Outcome, AccecptorHandshakeError<S>>
        where S: io::Read + io::Write
    {
        Err(AccecptorHandshakeError::InvalidChallenge) // TODO
    }

    /// Responds to a handshake on the given stream.
    ///
    /// Note: This function does not conform to the secret-handshake protocol.
    /// Instead it reproduces a mistake in the reference implementation. Use
    /// this if interoperability with peers using the old reference
    /// implementation is necessary. If interoperability is not a concern, use
    /// `create_server_challenge` instead.
    ///
    /// After the handshake has been performed, the stream can be reused. All
    /// further communication on the stream remains unencrypted.
    ///
    /// If the stream is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    #[deprecated(note="the legacy methods will be removed when the shs ecosystem stops using the faulty implementation")]
    pub fn legacy_shake_hands<S>(&self, stream: &S) -> Result<Outcome, AccecptorHandshakeError<S>>
        where S: io::Read + io::Write
    {
        Err(AccecptorHandshakeError::InvalidChallenge) // TODO
    }
}

/// An error that occured during the handshake.
///
/// The variants wrapping an io::Error never wrap a `WouldBlock`, these cases
/// are always handled by the `Interrupted` variant.
#[derive(Debug)]
pub enum AccecptorHandshakeError<S> {
    /// Failed to send the challenge to the peer.
    SendChallengeFail(io::Error),
    /// Failed to receive the challenge from the peer.
    ReceiveChallengeFail(io::Error),
    /// The received challenge is invalid, e.g. because the peer assumed a wrong
    /// protocol (version).
    InvalidChallenge, // TODO add data?
    /// Failed to send authentication to the peer.
    SendAuthFail(io::Error),
    /// Failed to receive authentiction from the peer.
    ReceiveAuthFail(io::Error),
    /// Received invalid authentication from the peer.
    InvalidAuth, // TODO add data?
    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `resume_handshake` at a later time once the stream is ready to perform
    /// I/O again.
    Interrupted(MidHandshakeShsAccecptorStream<S>),
}

impl<S> fmt::Display for AccecptorHandshakeError<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S> error::Error for AccecptorHandshakeError<S>
    where S: fmt::Debug
{
    fn description(&self) -> &str {
        match *self {
            AccecptorHandshakeError::SendChallengeFail(ref err) => err.description(),
            AccecptorHandshakeError::ReceiveChallengeFail(ref err) => err.description(),
            AccecptorHandshakeError::InvalidChallenge => "received invalid challenge",
            AccecptorHandshakeError::SendAuthFail(ref err) => err.description(),
            AccecptorHandshakeError::ReceiveAuthFail(ref err) => err.description(),
            AccecptorHandshakeError::InvalidAuth => "received invalid authentication",
            AccecptorHandshakeError::Interrupted(_) => "underlying stream would have blocked",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AccecptorHandshakeError::SendChallengeFail(ref err) => Some(err),
            AccecptorHandshakeError::ReceiveChallengeFail(ref err) => Some(err),
            AccecptorHandshakeError::InvalidChallenge => None,
            AccecptorHandshakeError::SendAuthFail(ref err) => Some(err),
            AccecptorHandshakeError::ReceiveAuthFail(ref err) => Some(err),
            AccecptorHandshakeError::InvalidAuth => None,
            AccecptorHandshakeError::Interrupted(_) => None,
        }
    }
}

/// An shs server stream which has been interrupted midway through the handshake
/// process.
///
/// Instances of this are obtained when the underying stream of an
/// `ShsAccecptor` returns a `WouldBlock` error on a read or write. The instance
/// can be used to resume the handshake when the stream is ready to perform I/O
/// again.
pub struct MidHandshakeShsAccecptorStream<S>(S);

impl<S> MidHandshakeShsAccecptorStream<S>
    where S: io::Read + io::Write
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.0
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Resumes the handshake process.
    pub fn resume_handshake(self) -> Result<Outcome, AccecptorHandshakeError<S>> {
        Err(AccecptorHandshakeError::InvalidChallenge) // TODO
    }
}

impl<S> fmt::Debug for MidHandshakeShsAccecptorStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

fn const_true<T>(_: T) -> bool {
    true
}
