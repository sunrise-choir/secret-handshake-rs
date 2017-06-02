use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;

use super::Outcome;
use crypto;

/// A builder for `Client`s.
pub struct ClientBuilder {
    client_pub: sign::PublicKey,
    client_sec: sign::SecretKey,
    server_pub: sign::PublicKey,
    app_key: auth::Key,
    ephemeral_pub: Option<box_::PublicKey>,
    ephemeral_sec: Option<box_::SecretKey>,
}

impl ClientBuilder {
    fn new(client_pub: sign::PublicKey,
           client_sec: sign::SecretKey,
           server_pub: sign::PublicKey,
           app_key: auth::Key)
           -> ClientBuilder {
        ClientBuilder {
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
                             -> &mut ClientBuilder {
        self.ephemeral_pub = Some(pub_key);
        self.ephemeral_sec = Some(sec_key);
        self
    }

    /// Consumes the builder, returning an `Client`.
    pub fn build(self) -> Client {
        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
        Client {
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
pub struct Client {
    client_pub: sign::PublicKey,
    client_sec: sign::SecretKey,
    server_pub: sign::PublicKey,
    app_key: auth::Key,
    ephemeral_pub: box_::PublicKey,
    ephemeral_sec: box_::SecretKey,
}

impl Client {
    /// Returns a new builder for a `Client`. All arguments are
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
                   -> ClientBuilder {
        ClientBuilder::new(client_pub, client_sec, server_pub, app_key)
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
    ///
    /// Note: This function does *not* conform to the secret-handshake protocol.
    /// Instead it reproduces
    /// [a mistake](https://github.com/auditdrivencrypto/secret-handshake/issues/7)
    /// in the reference implementation. Use this if interoperability with peers
    /// using the old reference implementation is necessary. When the reference
    /// implementation is fixed, a new major version of this package will be
    /// released in which `shake_hands` implements the spec-conforming
    /// behaviour.
    pub fn shake_hands<'a, S>(&self,
                              stream: &'a mut S)
                              -> Result<Outcome, ClientHandshakeError<'a, S>>
        where S: io::Read + io::Write
    {
        let client_challenge = crypto::create_client_challenge(&self.app_key, &self.ephemeral_pub);

        // TODO use result combinator functions instead of match blocks
        match stream.write(&client_challenge) {
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        let resumer = MidHandshakeClientStream {
                            stream: stream,
                            resume: ClientResumeState::SendClientChallenge,
                        };
                        return Err(ClientHandshakeError::Interrupted(resumer));
                    }
                    _ => return Err(ClientHandshakeError::SendChallengeFail(e)),
                }
            }
            Ok(_) => {
                // TODO resume stuff
                return Err(ClientHandshakeError::InvalidChallenge);
            }
        }
    }
}

/// An error that occured during the handshake.
///
/// The variants wrapping an io::Error never wrap a `WouldBlock`, these cases
/// are always handled by the `Interrupted` variant.
#[derive(Debug)]
pub enum ClientHandshakeError<'a, S: 'a> {
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
    Interrupted(MidHandshakeClientStream<'a, S>),
}

impl<'a, S> fmt::Display for ClientHandshakeError<'a, S>
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

impl<'a, S> error::Error for ClientHandshakeError<'a, S>
    where S: fmt::Debug
{
    fn description(&self) -> &str {
        match *self {
            ClientHandshakeError::SendChallengeFail(ref err) => err.description(),
            ClientHandshakeError::ReceiveChallengeFail(ref err) => err.description(),
            ClientHandshakeError::InvalidChallenge => "received invalid challenge",
            ClientHandshakeError::SendAuthFail(ref err) => err.description(),
            ClientHandshakeError::ReceiveAuthFail(ref err) => err.description(),
            ClientHandshakeError::InvalidAuth => "received invalid authentication",
            ClientHandshakeError::Interrupted(_) => "underlying stream would have blocked",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ClientHandshakeError::SendChallengeFail(ref err) => Some(err),
            ClientHandshakeError::ReceiveChallengeFail(ref err) => Some(err),
            ClientHandshakeError::InvalidChallenge => None,
            ClientHandshakeError::SendAuthFail(ref err) => Some(err),
            ClientHandshakeError::ReceiveAuthFail(ref err) => Some(err),
            ClientHandshakeError::InvalidAuth => None,
            ClientHandshakeError::Interrupted(_) => None,
        }
    }
}

/// An shs client stream which has been interrupted midway through the handshake
/// process.
///
/// Instances of this are obtained when the underying stream of a
/// `Client` returns a `WouldBlock` error on a read or write. The instance
/// can be used to resume the handshake when the stream is ready to perform I/O
/// again.
pub struct MidHandshakeClientStream<'a, S: 'a> {
    stream: &'a mut S,
    resume: ClientResumeState,
}

impl<'a, S> MidHandshakeClientStream<'a, S>
    where S: io::Read + io::Write
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Resumes the handshake process.
    pub fn resume_handshake(self) -> Result<Outcome, ClientHandshakeError<'a, S>> {
        Err(ClientHandshakeError::InvalidChallenge) // TODO
    }
}

impl<'a, S> fmt::Debug for MidHandshakeClientStream<'a, S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.stream, fmt)
    }
}

// indicates where a MidHandshakeClientStream should resume the handshake
enum ClientResumeState {
    SendClientChallenge,
}
