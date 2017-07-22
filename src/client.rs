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

/// Performs the client side of a handshake, holding state between different steps.
pub struct ClientHandshaker<S> {
    stream: S,
    client: Client,
    state: ClientResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
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
        let mut ret = ClientHandshaker {
            stream,
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

    /// Returns the current phase of the handshake. Useful to determine what happens
    /// next, or when exactly an IO error occured.
    pub fn get_resume_state(&self) -> ClientResumeState {
        self.state
    }

    /// Performs the handshake, using the inner duplex stream to negotiate
    /// an `Outcome`.
    ///
    /// Ift he handshake succeeds, this returns both an outcome and ownership
    /// of the inner stream. If the server sends invalid data, the handshake
    /// is aborted an ownership of the stream is returned in the `ClientHandshakeError`
    /// variant. If an IO error occurs, the wrapped error contains another owned
    /// ClientHandshaker which can be used to resume the handshake if the IO
    /// error was non-fatal.
    pub fn shake_hands(mut self) -> Result<(Outcome, S), ClientHandshakeError<S>> {
        match self.state {
            ClientResumeState::WriteClientChallenge => {
                while self.offset < CLIENT_CHALLENGE_BYTES {
                    match self.stream
                              .write(&self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(ClientHandshakeError::IoErr(e, self));
                        }
                    }
                }

                self.offset = 0;
                self.state = ClientResumeState::ReadServerChallenge;
                return self.shake_hands();
            }

            ClientResumeState::ReadServerChallenge => {
                while self.offset < SERVER_CHALLENGE_BYTES {
                    match self.stream
                              .read(&mut self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(ClientHandshakeError::IoErr(e, self));
                        }
                    }
                }

                if !self.client
                        .verify_server_challenge(unsafe {
                                                     &*(&self.data as
                                                        *const [u8; CLIENT_AUTH_BYTES] as
                                                        *const [u8; SERVER_CHALLENGE_BYTES])
                                                 }) {
                    return Err(ClientHandshakeError::InvalidChallenge(self.stream));
                }

                self.offset = 0;
                self.state = ClientResumeState::WriteClientAuth;
                self.client.create_client_auth(&mut self.data);
                return self.shake_hands();
            }

            ClientResumeState::WriteClientAuth => {
                while self.offset < CLIENT_AUTH_BYTES {
                    match self.stream
                              .write(&self.data[self.offset..CLIENT_AUTH_BYTES]) {
                        Ok(written) => self.offset += written,
                        Err(e) => {
                            return Err(ClientHandshakeError::IoErr(e, self));
                        }
                    }
                }

                self.offset = 0;
                self.state = ClientResumeState::ReadServerAck;
                return self.shake_hands();
            }

            ClientResumeState::ReadServerAck => {
                while self.offset < SERVER_ACK_BYTES {
                    match self.stream
                              .read(&mut self.data[self.offset..SERVER_ACK_BYTES]) {
                        Ok(read) => self.offset += read,
                        Err(e) => {
                            return Err(ClientHandshakeError::IoErr(e, self));
                        }
                    }
                }

                if !self.client
                        .verify_server_ack(unsafe {
                                               &*(&self.data as *const [u8; CLIENT_AUTH_BYTES] as
                                                  *const [u8; SERVER_ACK_BYTES])
                                           }) {
                    return Err(ClientHandshakeError::InvalidAck(self.stream));
                }

                let mut outcome = unsafe { uninitialized() };
                self.client.outcome(&mut outcome);
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
impl<S> fmt::Debug for ClientHandshaker<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ClientHandshaker {{state: {:?}}}", self.state)
    }
}

/// Indicates where a ClientHandshaker will resume a partial handshake.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClientResumeState {
    /// Write the client challenge to the server.
    WriteClientChallenge,
    /// Read the server challenge, then validate it.
    ReadServerChallenge,
    /// Write the client authentication to the server.
    WriteClientAuth,
    /// Read the server ackknowledgement, then validate it and end the handshake.
    ReadServerAck,
}

/// An error that occured during the handshake. `InvalidChallenge` and `InvalidAck`
/// are fatal errors and return ownership of the inner stream. An `IoErr`
/// contains a `ClientHandshaker` which can be used to resume the handshake at a
/// later point if the wrapped IO error is non-fatal.
#[derive(Debug)]
pub enum ClientHandshakeError<S> {
    /// An IO error occured during reading or writing. If the error is not fatal,
    /// you can simply call `shake_hands` on the contained client again.
    IoErr(io::Error, ClientHandshaker<S>),
    /// Received an invalid challenge from the server.
    InvalidChallenge(S),
    /// Received invalid ackknowledgement from the server.
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
