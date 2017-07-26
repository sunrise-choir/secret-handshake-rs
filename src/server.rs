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

use crypto::*;

/// Performs the server side of a handshake, holding state between different steps.
///
/// The API utilizes ownership to ensure that the communication stream with the
/// peer can not be used during the handshake. Ownership of the stream is
/// returned when the handshake terminates (either successfully or via an error).
///
/// `ServerHandshaker` also implements the `Future` trait, which provides a
/// simpler interface hiding the ownership details.
pub struct ServerHandshaker<S> {
    stream: S,
    state: HandshakeState,
}

impl<S: io::Read + io::Write> ServerHandshaker<S> {
    /// Creates a new ServerHandshaker to accept connections from a client which
    /// knows the server's public key and use the right app key over the given `stream`.
    pub fn new(stream: S,
               app: &[u8; auth::KEYBYTES],
               pub_: &[u8; sign::PUBLICKEYBYTES],
               sec: &[u8; sign::SECRETKEYBYTES],
               eph_pub: &[u8; box_::PUBLICKEYBYTES],
               eph_sec: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshaker<S> {
        ServerHandshaker {
            stream,
            state: HandshakeState::new(app, pub_, sec, eph_pub, eph_sec),
        }
    }

    /// Returns the current phase of the handshake.
    ///
    /// There is no state to mark a completed handshake. After `shake_hands` has
    /// returned an `Ok`, this method will continue to return
    /// `ServerResumeState::WriteServerAck`.
    pub fn get_resume_state(&self) -> ServerResumeState {
        self.state.get_resume_state()
    }

    /// Performs the handshake, using the inner duplex stream to negotiate
    /// an `Outcome`.
    ///
    /// Ift he handshake succeeds, this returns both an outcome and ownership
    /// of the inner stream. If the client sends invalid data, the handshake
    /// is aborted and ownership of the stream is returned in the `ServerHandshakeError`
    /// variant. If an IO error occurs, the wrapped error contains another owned
    /// ServerHandshaker which can be used to resume the handshake if the IO
    /// error was non-fatal. In case of a fatal IO error,
    /// `ServerHandshaker.into_inner()` can be used to retrieve the stream.
    pub fn shake_hands(mut self) -> Result<(Outcome, S), ServerHandshakeError<S>> {
        match self.state.shake_hands(&mut self.stream) {
            Ok(outcome) => Ok((outcome, self.stream)),
            Err(e) => {
                match e {
                    HandshakeError::IoErr(inner_err) => {
                        Err(ServerHandshakeError::IoErr(inner_err, self))
                    }
                    HandshakeError::InvalidChallenge => {
                        Err(ServerHandshakeError::InvalidChallenge(self.stream))
                    }
                    HandshakeError::InvalidAuth => {
                        Err(ServerHandshakeError::InvalidAuth(self.stream))
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
}

/// Future implementation to asynchronously drive a handshake.
impl<S: AsyncRead + AsyncWrite> Future for ServerHandshaker<S> {
    type Item = Outcome;
    type Error = AsyncServerHandshakeError;

    fn poll(&mut self) -> Poll<Outcome, AsyncServerHandshakeError> {
        match self.state.shake_hands(&mut self.stream) {
            Ok(outcome) => Ok(Async::Ready(outcome)),
            Err(e) => {
                match e {
                    AsyncServerHandshakeError::IoErr(inner_err) => {
                        if inner_err.kind() == io::ErrorKind::WouldBlock {
                            Ok(Async::NotReady)
                        } else {
                            Err(AsyncServerHandshakeError::IoErr(inner_err))
                        }
                    }
                    _ => Err(e),
                }
            }
        }
    }
}

impl<S> fmt::Debug for ServerHandshaker<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ServerHandshaker {{state: {:?}}}", self.state.state)
    }
}

/// Indicates where a ServerHandshaker will resume a partial handshake.
///
/// This should mostly be interesting for diagnostic purposes. The implementation
/// details that need to be aware of the current state are hidden.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ServerResumeState {
    /// Read the client challenge, then validate it.
    ReadClientChallenge,
    /// Write the server challenge to the client.
    WriteServerChallenge,
    /// Read the client authentication, then validate it.
    ReadClientAuth,
    /// Write the server acknowledgement to the client and end the handshake.
    WriteServerAck,
}

/// An error which occured during the handshake.
///
/// `InvalidChallenge` and `InvalidAuth` are fatal errors and return ownership of
/// the inner stream. An `IoErr` contains a `ServerHandshaker` which can be used
/// to resume the handshake at a later point if the wrapped IO error is non-fatal.
#[derive(Debug)]
pub enum ServerHandshakeError<S> {
    /// An IO error occured during reading or writing. If the error is not fatal,
    /// you can simply call `shake_hands` on the contained client again.
    IoErr(io::Error, ServerHandshaker<S>),
    /// Received an invalid challenge from the client.
    InvalidChallenge(S),
    /// Received invalid authentication from the client.
    InvalidAuth(S),
}

impl<S: fmt::Debug> fmt::Display for ServerHandshakeError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S: fmt::Debug> error::Error for ServerHandshakeError<S> {
    fn description(&self) -> &str {
        match *self {
            ServerHandshakeError::IoErr(ref err, _) => err.description(),
            ServerHandshakeError::InvalidChallenge(_) => "received invalid challenge",
            ServerHandshakeError::InvalidAuth(_) => "received invalid authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ServerHandshakeError::IoErr(ref err, _) => Some(err),
            ServerHandshakeError::InvalidChallenge(_) => None,
            ServerHandshakeError::InvalidAuth(_) => None,
        }
    }
}

/// An error which occured during the asynchronous execution of a handshake.
///
/// Unlike a simple `ServerHandshakeError`, all of these are considered fatal,
/// the handshake can not be resumed.
#[derive(Debug)]
pub enum AsyncServerHandshakeError {
    /// An IO error occured during reading or writing. The contained error is
    /// guaranteed to not have kind `WouldBlock`.
    IoErr(io::Error),
    /// Received an invalid challenge from the client.
    InvalidChallenge,
    /// Received invalid authentication from the client.
    InvalidAuth,
}

impl fmt::Display for AsyncServerHandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl error::Error for AsyncServerHandshakeError {
    fn description(&self) -> &str {
        match *self {
            AsyncServerHandshakeError::IoErr(ref err) => err.description(),
            AsyncServerHandshakeError::InvalidChallenge => "received invalid challenge",
            AsyncServerHandshakeError::InvalidAuth => "received invalid authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AsyncServerHandshakeError::IoErr(ref err) => Some(err),
            AsyncServerHandshakeError::InvalidChallenge => None,
            AsyncServerHandshakeError::InvalidAuth => None,
        }
    }
}

use self::AsyncServerHandshakeError as HandshakeError;

////////////////////////////////////
/// begin implementation details ///
////////////////////////////////////

struct HandshakeState {
    server: Server,
    state: ServerResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

impl HandshakeState {
    fn new(app: &[u8; auth::KEYBYTES],
           pub_: &[u8; sign::PUBLICKEYBYTES],
           sec: &[u8; sign::SECRETKEYBYTES],
           eph_pub: &[u8; box_::PUBLICKEYBYTES],
           eph_sec: &[u8; box_::SECRETKEYBYTES])
           -> HandshakeState {
        HandshakeState {
            server: Server::new(app, pub_, sec, eph_pub, eph_sec),
            state: ServerResumeState::ReadClientChallenge,
            data: [0; CLIENT_AUTH_BYTES],
            offset: 0,
        }
    }

    fn get_resume_state(&self) -> ServerResumeState {
        self.state
    }

    // Advances through the handshake state machine.
    fn shake_hands<S: io::Read + io::Write>(&mut self,
                                            stream: &mut S)
                                            -> Result<Outcome, HandshakeError> {

        match self.state {
            ServerResumeState::ReadClientChallenge => {
                while self.offset < CLIENT_CHALLENGE_BYTES {
                    match stream.read(&mut self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                if !self.server
                        .verify_client_challenge(unsafe {
                                                     &*(&self.data as
                                                        *const [u8; CLIENT_AUTH_BYTES] as
                                                        *const [u8; CLIENT_CHALLENGE_BYTES])
                                                 }) {
                    return Err(HandshakeError::InvalidChallenge);
                }

                self.offset = 0;
                self.state = ServerResumeState::WriteServerChallenge;
                self.server
                    .create_server_challenge(unsafe {
                                                 &mut *(&mut self.data as
                                                        *mut [u8; CLIENT_AUTH_BYTES] as
                                                        *mut [u8; SERVER_CHALLENGE_BYTES])
                                             });
                return self.shake_hands(stream);
            }

            ServerResumeState::WriteServerChallenge => {
                while self.offset < SERVER_CHALLENGE_BYTES {
                    match stream.write(&self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                self.offset = 0;
                self.state = ServerResumeState::ReadClientAuth;
                return self.shake_hands(stream);
            }

            ServerResumeState::ReadClientAuth => {
                while self.offset < CLIENT_AUTH_BYTES {
                    match stream.read(&mut self.data[self.offset..CLIENT_AUTH_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                if !self.server.verify_client_auth(&self.data) {
                    return Err(HandshakeError::InvalidAuth);
                }

                self.offset = 0;
                self.state = ServerResumeState::WriteServerAck;
                return self.shake_hands(stream);
            }

            ServerResumeState::WriteServerAck => {
                while self.offset < SERVER_ACK_BYTES {
                    match stream.write(&self.data[self.offset..SERVER_ACK_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(HandshakeError::IoErr(e));
                        }
                    }
                }

                let mut outcome = unsafe { uninitialized() };
                self.server.outcome(&mut outcome);
                self.data = [0; CLIENT_AUTH_BYTES];
                return Ok(outcome);
            }
        }
    }
}
