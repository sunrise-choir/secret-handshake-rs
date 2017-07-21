use std::error;
use std::error::Error;
use std::io;
use std::fmt;
use std::mem::uninitialized;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::auth;

use crypto::*;

pub struct ClientHandshaker {
    client: Client,
    state: ClientResumeState,
    data: [u8; CLIENT_AUTH_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
}

impl ClientHandshaker {
    pub fn new(app: &[u8; auth::KEYBYTES],
               pub_: &[u8; sign::PUBLICKEYBYTES],
               sec: &[u8; sign::SECRETKEYBYTES],
               eph_pub: &[u8; box_::PUBLICKEYBYTES],
               eph_sec: &[u8; box_::SECRETKEYBYTES],
               server_pub: &[u8; sign::PUBLICKEYBYTES])
               -> ClientHandshaker {
        let mut ret = ClientHandshaker {
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

    pub fn get_resume_state(&self) -> ClientResumeState {
        self.state
    }

    pub fn shake_hands<S: io::Read + io::Write>(&mut self,
                                                stream: &mut S)
                                                -> Result<Outcome, ClientHandshakeError> {
        if self.state == ClientResumeState::WriteClientChallenge {
            while self.offset < CLIENT_CHALLENGE_BYTES {
                match stream.write(&self.data[self.offset..CLIENT_CHALLENGE_BYTES]) {
                    Ok(written) => self.offset += written,
                    Err(e) => {
                        return Err(ClientHandshakeError::IoErr(e));
                    }
                }
            }

            self.offset = 0;
            self.state = ClientResumeState::ReadServerChallenge;
        }

        if self.state == ClientResumeState::ReadServerChallenge {
            while self.offset < SERVER_CHALLENGE_BYTES {
                match stream.read(&mut self.data[self.offset..SERVER_CHALLENGE_BYTES]) {
                    Ok(read) => self.offset += read,
                    Err(e) => {
                        return Err(ClientHandshakeError::IoErr(e));
                    }
                }
            }

            if !self.client
                    .verify_server_challenge(unsafe {
                                                 &*(&self.data as *const [u8; CLIENT_AUTH_BYTES] as
                                                    *const [u8; SERVER_CHALLENGE_BYTES])
                                             }) {
                return Err(ClientHandshakeError::InvalidChallenge);
            }

            self.offset = 0;
            self.state = ClientResumeState::WriteClientAuth;
            self.client.create_client_auth(&mut self.data);
        }

        if self.state == ClientResumeState::WriteClientAuth {
            while self.offset < CLIENT_AUTH_BYTES {
                match stream.write(&self.data[self.offset..CLIENT_AUTH_BYTES]) {
                    Ok(written) => self.offset += written,
                    Err(e) => {
                        return Err(ClientHandshakeError::IoErr(e));
                    }
                }
            }

            self.offset = 0;
            self.state = ClientResumeState::ReadServerAck;
        }

        if self.state == ClientResumeState::ReadServerAck {
            while self.offset < SERVER_ACK_BYTES {
                match stream.read(&mut self.data[self.offset..SERVER_ACK_BYTES]) {
                    Ok(read) => self.offset += read,
                    Err(e) => {
                        return Err(ClientHandshakeError::IoErr(e));
                    }
                }
            }

            if !self.client
                    .verify_server_ack(unsafe {
                                           &*(&self.data as *const [u8; CLIENT_AUTH_BYTES] as
                                              *const [u8; SERVER_ACK_BYTES])
                                       }) {
                return Err(ClientHandshakeError::InvalidAck);
            }

            let mut outcome = unsafe { uninitialized() };
            self.client.outcome(&mut outcome);
            return Ok(outcome);
        }
        unreachable!();
    }
}

/// Zero out all sensitive data when going out of scope
impl Drop for ClientHandshaker {
    fn drop(&mut self) {
        self.client.clean();
        self.data = [0; CLIENT_AUTH_BYTES];
    }
}

/// Indicates where a ClientHandshaker will resume a partial handshake.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClientResumeState {
    WriteClientChallenge,
    ReadServerChallenge,
    WriteClientAuth,
    ReadServerAck,
}

/// An error that occured during the handshake. `InvalidChallenge` and `InvalidAck`
/// should be considered fatal errors.
#[derive(Debug)]
pub enum ClientHandshakeError {
    /// An io error occured during reading or writing.
    IoErr(io::Error),
    /// The received challenge is invalid, e.g. because the server assumed a
    /// wrong protocol (version).
    InvalidChallenge,
    /// Received invalid ackknowledgement from the server.
    InvalidAck,
}

impl fmt::Display for ClientHandshakeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl error::Error for ClientHandshakeError {
    fn description(&self) -> &str {
        match *self {
            ClientHandshakeError::IoErr(ref err) => err.description(),
            ClientHandshakeError::InvalidChallenge => "received invalid challenge",
            ClientHandshakeError::InvalidAck => "received invalid authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ClientHandshakeError::IoErr(ref err) => Some(err),
            ClientHandshakeError::InvalidChallenge => None,
            ClientHandshakeError::InvalidAck => None,
        }
    }
}
