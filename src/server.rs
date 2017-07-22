use std::error;
use std::error::Error;
use std::io;
use std::fmt;
use std::mem::uninitialized;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::auth;

use crypto::*;

/// Performs the server side of a handshake, holding state between different steps.
pub struct ServerHandshaker {
    server: Server,
    state: ServerResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

impl ServerHandshaker {
    /// Creates a new ServerHandshaker to accept connections from a client which
    /// know the server's public key and use the right app key.
    pub fn new(app: &[u8; auth::KEYBYTES],
               pub_: &[u8; sign::PUBLICKEYBYTES],
               sec: &[u8; sign::SECRETKEYBYTES],
               eph_pub: &[u8; box_::PUBLICKEYBYTES],
               eph_sec: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshaker {
        ServerHandshaker {
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

    /// Performs the handshake, using the provided duplex stream to negotiate
    /// an `Outcome`.
    ///
    /// To get a correct outcome, always pass the same stream to the same
    /// `ServerHandshaker`, and don't read to or write from that stream until
    /// `shake_hands` has returned `Ok(outcome)`.
    pub fn shake_hands<S: io::Read + io::Write>(&mut self,
                                                stream: &mut S)
                                                -> Result<Outcome, ServerHandshakeError> {
        if self.state == ServerResumeState::ReadClientChallenge {
            while self.offset < CLIENT_CHALLENGE_BYTES {
                match stream.read(&mut self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                    Ok(read) => self.offset += read,
                    Err(e) => {
                        return Err(ServerHandshakeError::IoErr(e));
                    }
                }
            }

            if !self.server
                    .verify_client_challenge(unsafe {
                                                 &*(&self.data as *const [u8; CLIENT_AUTH_BYTES] as
                                                    *const [u8; CLIENT_CHALLENGE_BYTES])
                                             }) {
                return Err(ServerHandshakeError::InvalidChallenge);
            }

            self.offset = 0;
            self.state = ServerResumeState::WriteServerChallenge;
            self.server
                .create_server_challenge(unsafe {
                                             &mut *(&mut self.data as
                                                    *mut [u8; CLIENT_AUTH_BYTES] as
                                                    *mut [u8; SERVER_CHALLENGE_BYTES])
                                         });
        }

        if self.state == ServerResumeState::WriteServerChallenge {
            while self.offset < SERVER_CHALLENGE_BYTES {
                match stream.write(&self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                    Ok(written) => self.offset += written,
                    Err(e) => {
                        return Err(ServerHandshakeError::IoErr(e));
                    }
                }
            }

            self.offset = 0;
            self.state = ServerResumeState::ReadClientAuth;
        }

        if self.state == ServerResumeState::ReadClientAuth {
            while self.offset < CLIENT_AUTH_BYTES {
                match stream.read(&mut self.data[self.offset..CLIENT_AUTH_BYTES]) {
                    Ok(read) => self.offset += read,
                    Err(e) => {
                        return Err(ServerHandshakeError::IoErr(e));
                    }
                }
            }

            if !self.server.verify_client_auth(&self.data) {
                return Err(ServerHandshakeError::InvalidAuth);
            }

            self.offset = 0;
            self.state = ServerResumeState::WriteServerAck;
        }

        if self.state == ServerResumeState::WriteServerAck {
            while self.offset < SERVER_ACK_BYTES {
                match stream.write(&self.data[self.offset..SERVER_ACK_BYTES]) {
                    Ok(written) => self.offset += written,
                    Err(e) => {
                        return Err(ServerHandshakeError::IoErr(e));
                    }
                }
            }

            let mut outcome = unsafe { uninitialized() };
            self.server.outcome(&mut outcome);
            return Ok(outcome);
        }
        unreachable!();
    }
}

/// Zero out all sensitive data when going out of scope
impl Drop for ServerHandshaker {
    fn drop(&mut self) {
        self.server.clean();
        self.data = [0; CLIENT_AUTH_BYTES];
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
/// should be considered fatal errors.
#[derive(Debug)]
pub enum ServerHandshakeError {
    /// An io error occured during reading or writing.
    IoErr(io::Error),
    /// The received challenge is invalid, e.g. because the client assumed a
    /// wrong protocol (version).
    InvalidChallenge,
    /// Received invalid authentication from the client.
    InvalidAuth,
}

impl fmt::Display for ServerHandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl error::Error for ServerHandshakeError {
    fn description(&self) -> &str {
        match *self {
            ServerHandshakeError::IoErr(ref err) => err.description(),
            ServerHandshakeError::InvalidChallenge => "received invalid challenge",
            ServerHandshakeError::InvalidAuth => "received invalid authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ServerHandshakeError::IoErr(ref err) => Some(err),
            ServerHandshakeError::InvalidChallenge => None,
            ServerHandshakeError::InvalidAuth => None,
        }
    }
}
