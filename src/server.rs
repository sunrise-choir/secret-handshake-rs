use std::error;
use std::error::Error;
use std::io;
use std::fmt;
use std::mem::uninitialized;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::auth;
// use futures::{Poll, Async, Future}; // TODO async API

use crypto::*;

/// Performs the server side of a handshake, holding state between different steps.
pub struct ServerHandshaker<S> {
    stream: S,
    server: Server,
    state: ServerResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

impl<S: io::Read + io::Write> ServerHandshaker<S> {
    /// Creates a new ServerHandshaker to accept connections from a client which
    /// know the server's public key and use the right app key over the given `stream`.
    pub fn new(stream: S,
               app: &[u8; auth::KEYBYTES],
               pub_: &[u8; sign::PUBLICKEYBYTES],
               sec: &[u8; sign::SECRETKEYBYTES],
               eph_pub: &[u8; box_::PUBLICKEYBYTES],
               eph_sec: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshaker<S> {
        ServerHandshaker {
            stream,
            server: Server::new(app, pub_, sec, eph_pub, eph_sec),
            state: ServerResumeState::ReadClientChallenge,
            data: [0; CLIENT_AUTH_BYTES],
            offset: 0,
        }
    }

    /// Returns the current phase of the handshake. Useful to determine what happens
    /// next, or when exactly an IO error occured.
    pub fn get_resume_state(&self) -> ServerResumeState {
        self.state
    }

    /// Performs the handshake, using the inner duplex stream to negotiate
    /// an `Outcome`.
    ///
    /// Ift he handshake succeeds, this returns both an outcome and ownership
    /// of the inner stream. If the client sends invalid data, the handshake
    /// is aborted an ownership of the stream is returned in the `ServerHandshakeError`
    /// variant. If an IO error occurs, the wrapped error contains another owned
    /// ServerHandshaker which can be used to resume the handshake if the IO
    /// error was non-fatal.
    pub fn shake_hands(mut self) -> Result<(Outcome, S), ServerHandshakeError<S>> {
        match self.state {
            ServerResumeState::ReadClientChallenge => {
                while self.offset < CLIENT_CHALLENGE_BYTES {
                    match self.stream
                              .read(&mut self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(ServerHandshakeError::IoErr(e, self));
                        }
                    }
                }

                if !self.server
                        .verify_client_challenge(unsafe {
                                                     &*(&self.data as
                                                        *const [u8; CLIENT_AUTH_BYTES] as
                                                        *const [u8; CLIENT_CHALLENGE_BYTES])
                                                 }) {
                    return Err(ServerHandshakeError::InvalidChallenge(self.stream));
                }

                self.offset = 0;
                self.state = ServerResumeState::WriteServerChallenge;
                self.server
                    .create_server_challenge(unsafe {
                                                 &mut *(&mut self.data as
                                                        *mut [u8; CLIENT_AUTH_BYTES] as
                                                        *mut [u8; SERVER_CHALLENGE_BYTES])
                                             });
                return self.shake_hands();
            }

            ServerResumeState::WriteServerChallenge => {
                while self.offset < SERVER_CHALLENGE_BYTES {
                    match self.stream
                              .write(&self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(ServerHandshakeError::IoErr(e, self));
                        }
                    }
                }

                self.offset = 0;
                self.state = ServerResumeState::ReadClientAuth;
                return self.shake_hands();
            }

            ServerResumeState::ReadClientAuth => {
                while self.offset < CLIENT_AUTH_BYTES {
                    match self.stream
                              .read(&mut self.data[self.offset..CLIENT_AUTH_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(ServerHandshakeError::IoErr(e, self));
                        }
                    }
                }

                if !self.server.verify_client_auth(&self.data) {
                    return Err(ServerHandshakeError::InvalidAuth(self.stream));
                }

                self.offset = 0;
                self.state = ServerResumeState::WriteServerAck;
                return self.shake_hands();
            }

            ServerResumeState::WriteServerAck => {
                while self.offset < SERVER_ACK_BYTES {
                    match self.stream
                              .write(&self.data[self.offset..SERVER_ACK_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(ServerHandshakeError::IoErr(e, self));
                        }
                    }
                }

                let mut outcome = unsafe { uninitialized() };
                self.server.outcome(&mut outcome);
                self.data = [0; CLIENT_AUTH_BYTES];
                return Ok((outcome, self.stream));
            }
        }
    }

    /// Get back ownership of the inner stream. If a handshake has been in
    /// progress, it can *not* be resumed later.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

// TODO provide a better implementation
impl<S> fmt::Debug for ServerHandshaker<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ServerHandshaker {{state: {:?}}}", self.state)
    }
}

/// Indicates where a ServerHandshaker will resume a partial handshake.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ServerResumeState {
    /// Read the client challenge, then validate it.
    ReadClientChallenge,
    /// Write the server challenge to the client.
    WriteServerChallenge,
    /// Read the client authentication, then validate it.
    ReadClientAuth,
    /// Write the server ackknowledgement to the client and end the handshake.
    WriteServerAck,
}

/// An error that occured during the handshake. `InvalidChallenge` and `InvalidAuth`
/// are fatal errors and return ownership of the inner stream. An `IoErr`
/// contains a `ClientHandshaker` which can be used to resume the handshake at a
/// later point if the wrapped IO error is non-fatal.
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
