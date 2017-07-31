use std::error;
use std::error::Error;
use std::io;
use std::fmt;
use std::mem::uninitialized;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::auth;
use futures::{Poll, Async, Future};
use tokio_io::{AsyncRead, AsyncWrite};
use box_stream::BoxDuplex;

use crypto::*;

/// Performs the client side of a handshake, holding state between different steps.
///
/// The API utilizes ownership to ensure that the communication stream with the
/// peer can not be used during the handshake. Ownership of the stream is
/// returned when the handshake terminates (either successfully or via an error).
///
/// `ClientHandshaker` also implements the `Future` trait, which provides a
/// simpler interface hiding the ownership details.
pub struct ClientHandshaker<S> {
    stream: S,
    state: HandshakeState,
}

impl<S: io::Read + io::Write> ClientHandshaker<S> {
    /// Creates a new ClientHandshaker to connect to a server with known public key
    /// and app key over the given `stream`.
    pub fn new(stream: S,
               app: &[u8; auth::KEYBYTES],
               pub_: &[u8; sign::PUBLICKEYBYTES],
               sec: &[u8; sign::SECRETKEYBYTES],
               eph_pub: &[u8; box_::PUBLICKEYBYTES],
               eph_sec: &[u8; box_::SECRETKEYBYTES],
               server_pub: &[u8; sign::PUBLICKEYBYTES])
               -> ClientHandshaker<S> {
        ClientHandshaker {
            stream,
            state: HandshakeState::new(app, pub_, sec, eph_pub, eph_sec, server_pub),
        }
    }

    /// Returns the current phase of the handshake.
    ///
    /// There is no state to mark a completed handshake. After `shake_hands` has
    /// returned an `Ok`, this method will continue to return
    /// `ClientResumeState::ReadServerAck`.
    pub fn get_resume_state(&self) -> ClientResumeState {
        self.state.get_resume_state()
    }

    /// Performs the handshake, using the inner duplex stream to negotiate
    /// an `Outcome`.
    ///
    /// If the handshake succeeds, this returns both an outcome and ownership
    /// of the inner stream. If the server sends invalid data, the handshake
    /// is aborted and ownership of the stream is returned in the `ClientHandshakeError`
    /// variant. If an IO error occurs, the wrapped error contains another owned
    /// `ClientHandshaker` which can be used to resume the handshake if the IO
    /// error was non-fatal. In case of a fatal IO error,
    /// `ClientHandshaker.into_inner()` can be used to retrieve the stream.
    pub fn shake_hands(mut self) -> Result<(Outcome, S), ClientHandshakeError<S>> {
        match self.state.shake_hands(&mut self.stream) {
            Ok(outcome) => Ok((outcome, self.stream)),
            Err(e) => {
                match e {
                    HandshakeError::IoErr(inner_err) => {
                        Err(ClientHandshakeError::IoErr(inner_err, self))
                    }
                    HandshakeError::InvalidChallenge => {
                        Err(ClientHandshakeError::InvalidChallenge(self.stream))
                    }
                    HandshakeError::InvalidAck => {
                        Err(ClientHandshakeError::InvalidAck(self.stream))
                    }
                }
            }
        }
    }

    /// Get back ownership of the inner stream. If a handshake has been in
    /// progress, it can *not* be resumed later.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Performs a handshake, then uses the negotiated data to create an
    /// encrypted duplex stream.
    pub fn negotiate_box_duplex(self) -> Result<BoxDuplex<S>, ClientHandshakeError<S>> {
        let (outcome, stream) = self.shake_hands()?;
        Ok(outcome.initialize_box_duplex(stream))
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S: AsyncRead + AsyncWrite> Future for ClientHandshaker<S> {
    type Item = Outcome;
    type Error = AsyncClientHandshakeError;

    fn poll(&mut self) -> Poll<Outcome, AsyncClientHandshakeError> {
        match self.state.shake_hands(&mut self.stream) {
            Ok(outcome) => Ok(Async::Ready(outcome)),
            Err(e) => {
                match e {
                    AsyncClientHandshakeError::IoErr(inner_err) => {
                        if inner_err.kind() == io::ErrorKind::WouldBlock {
                            Ok(Async::NotReady)
                        } else {
                            Err(AsyncClientHandshakeError::IoErr(inner_err))
                        }
                    }
                    _ => Err(e),
                }
            }
        }
    }
}

impl<S> fmt::Debug for ClientHandshaker<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ClientHandshaker {{state: {:?}}}", self.state.state)
    }
}

/// Indicates where a ClientHandshaker will resume a partial handshake.
///
/// This should mostly be interesting for diagnostic purposes. The implementation
/// details that need to be aware of the current state are hidden.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClientResumeState {
    /// Write the client challenge to the server.
    WriteClientChallenge,
    /// Read the server challenge, then validate it.
    ReadServerChallenge,
    /// Write the client authentication to the server.
    WriteClientAuth,
    /// Read the server acknowledgement, then validate it and end the handshake.
    ReadServerAck,
}

/// An error which occured during the synchronous execution of a handshake.
///
/// `InvalidChallenge` and `InvalidAck` are fatal errors and return ownership of
/// the inner stream. An `IoErr` contains a `ClientHandshaker` which can be used
/// to resume the handshake at a later point if the wrapped IO error is non-fatal.
#[derive(Debug)]
pub enum ClientHandshakeError<S> {
    /// An IO error occured during reading or writing. If the error is not fatal,
    /// you can simply call `shake_hands` on the contained client again.
    IoErr(io::Error, ClientHandshaker<S>),
    /// Received an invalid challenge from the server.
    InvalidChallenge(S),
    /// Received invalid acknowledgement from the server.
    InvalidAck(S),
}

impl<S: fmt::Debug> fmt::Display for ClientHandshakeError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S: fmt::Debug> error::Error for ClientHandshakeError<S> {
    fn description(&self) -> &str {
        match *self {
            ClientHandshakeError::IoErr(ref err, _) => err.description(),
            ClientHandshakeError::InvalidChallenge(_) => "received invalid challenge",
            ClientHandshakeError::InvalidAck(_) => "received invalid authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ClientHandshakeError::IoErr(ref err, _) => Some(err),
            ClientHandshakeError::InvalidChallenge(_) => None,
            ClientHandshakeError::InvalidAck(_) => None,
        }
    }
}

/// An error which occured during the asynchronous execution of a handshake.
///
/// Unlike a simple `ClientHandshakeError`, all of these are considered fatal,
/// the handshake can not be resumed.
#[derive(Debug)]
pub enum AsyncClientHandshakeError {
    /// An IO error occured during reading or writing. The contained error is
    /// guaranteed to not have kind `WouldBlock`.
    IoErr(io::Error),
    /// Received an invalid challenge from the server.
    InvalidChallenge,
    /// Received an invalid acknowledgement from the server.
    InvalidAck,
}

impl fmt::Display for AsyncClientHandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl error::Error for AsyncClientHandshakeError {
    fn description(&self) -> &str {
        match *self {
            AsyncClientHandshakeError::IoErr(ref err) => err.description(),
            AsyncClientHandshakeError::InvalidChallenge => "received invalid challenge",
            AsyncClientHandshakeError::InvalidAck => "received invalid acknowledgement",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AsyncClientHandshakeError::IoErr(ref err) => Some(err),
            AsyncClientHandshakeError::InvalidChallenge => None,
            AsyncClientHandshakeError::InvalidAck => None,
        }
    }
}

use self::AsyncClientHandshakeError as HandshakeError;

////////////////////////////////////
/// begin implementation details ///
////////////////////////////////////

struct HandshakeState {
    client: Client,
    state: ClientResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
}

impl HandshakeState {
    fn new(app: &[u8; auth::KEYBYTES],
           pub_: &[u8; sign::PUBLICKEYBYTES],
           sec: &[u8; sign::SECRETKEYBYTES],
           eph_pub: &[u8; box_::PUBLICKEYBYTES],
           eph_sec: &[u8; box_::SECRETKEYBYTES],
           server_pub: &[u8; sign::PUBLICKEYBYTES])
           -> HandshakeState {
        let mut ret = HandshakeState {
            client: Client::new(app, pub_, sec, eph_pub, eph_sec, server_pub),
            state: ClientResumeState::WriteClientChallenge,
            data: [0; CLIENT_AUTH_BYTES],
            offset: 0,
        };

        ret.client
            .create_client_challenge(unsafe {
                                         &mut *(&mut ret.data as *mut [u8; CLIENT_AUTH_BYTES] as
                                                *mut [u8; CLIENT_CHALLENGE_BYTES])
                                     });

        ret
    }

    fn get_resume_state(&self) -> ClientResumeState {
        self.state
    }

    // Advances through the handshake state machine.
    fn shake_hands<S: io::Read + io::Write>(&mut self,
                                            stream: &mut S)
                                            -> Result<Outcome, HandshakeError> {
        match self.state {
            ClientResumeState::WriteClientChallenge => {
                while self.offset < CLIENT_CHALLENGE_BYTES {
                    match stream.write(&self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                self.offset = 0;
                self.state = ClientResumeState::ReadServerChallenge;
                return self.shake_hands(stream);
            }

            ClientResumeState::ReadServerChallenge => {
                while self.offset < SERVER_CHALLENGE_BYTES {
                    match stream.read(&mut self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                if !self.client
                        .verify_server_challenge(unsafe {
                                                     &*(&self.data as
                                                        *const [u8; CLIENT_AUTH_BYTES] as
                                                        *const [u8; SERVER_CHALLENGE_BYTES])
                                                 }) {
                    return Err(HandshakeError::InvalidChallenge);
                }

                self.offset = 0;
                self.state = ClientResumeState::WriteClientAuth;
                self.client.create_client_auth(&mut self.data);
                return self.shake_hands(stream);
            }

            ClientResumeState::WriteClientAuth => {
                while self.offset < CLIENT_AUTH_BYTES {
                    match stream.write(&self.data[self.offset..CLIENT_AUTH_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                self.offset = 0;
                self.state = ClientResumeState::ReadServerAck;
                return self.shake_hands(stream);
            }

            ClientResumeState::ReadServerAck => {
                while self.offset < SERVER_ACK_BYTES {
                    match stream.read(&mut self.data[self.offset..SERVER_ACK_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                if !self.client
                        .verify_server_ack(unsafe {
                                               &*(&self.data as *const [u8; CLIENT_AUTH_BYTES] as
                                                  *const [u8; SERVER_ACK_BYTES])
                                           }) {
                    return Err(HandshakeError::InvalidAck);
                }

                let mut outcome = unsafe { uninitialized() };
                self.client.outcome(&mut outcome);
                self.data = [0; CLIENT_AUTH_BYTES];
                return Ok(outcome);
            }
        }
    }
}
