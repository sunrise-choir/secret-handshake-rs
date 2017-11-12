//! Asynchronously initiate handshakes.

use std::{error, io, fmt};
use std::error::Error;
use std::mem::uninitialized;
use std::fmt::Debug;

use sodiumoxide::crypto::{box_, sign};
use futures::{Poll, Async, Future};
use tokio_io::{AsyncRead, AsyncWrite};

use crypto::*;

/// Performs the client side of a handshake.
pub struct ClientHandshaker<S> {
    stream: Option<S>,
    client: Client,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
}

impl<S: AsyncRead + AsyncWrite> ClientHandshaker<S> {
    /// Creates a new ClientHandshaker to connect to a server with known public key
    /// and app key over the given `stream`.
    pub fn new(stream: S,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               client_longterm_pk: &[u8; sign::PUBLICKEYBYTES],
               client_longterm_sk: &[u8; sign::SECRETKEYBYTES],
               client_ephemeral_pk: &[u8; box_::PUBLICKEYBYTES],
               client_ephemeral_sk: &[u8; box_::SECRETKEYBYTES],
               server_longterm_pk: &[u8; sign::PUBLICKEYBYTES])
               -> ClientHandshaker<S> {
        let mut ret = ClientHandshaker {
            stream: Some(stream),
            client: Client::new(network_identifier,
                                client_longterm_pk,
                                client_longterm_sk,
                                client_ephemeral_pk,
                                client_ephemeral_sk,
                                server_longterm_pk),
            state: WriteMsg1,
            data: [0; MSG3_BYTES],
            offset: 0,
        };

        ret.client
            .create_msg1(unsafe {
                             &mut *(&mut ret.data as *mut [u8; MSG3_BYTES] as *mut [u8; MSG1_BYTES])
                         });

        ret
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S: AsyncRead + AsyncWrite> Future for ClientHandshaker<S> {
    type Item = (Result<Outcome, ClientHandshakeFailure>, S);
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut stream = self.stream
            .take()
            .expect("Attempted to poll ClientHandshaker after completion");

        match self.state {
            WriteMsg1 => {
                match stream.write(&self.data[self.offset..MSG1_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((e, stream));
                        }
                    }
                    Ok(written) => {
                        self.offset += written;
                        if self.offset < MSG1_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            self.offset = 0;
                            self.state = ReadMsg2;

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            ReadMsg2 => {
                match stream.read(&mut self.data[self.offset..MSG2_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((e, stream));
                        }
                    }
                    Ok(read) => {
                        self.offset += read;
                        if self.offset < MSG2_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            if !self.client
                                    .verify_msg2(unsafe {
                                                     &*(&self.data as *const [u8; MSG3_BYTES] as
                                                        *const [u8; MSG2_BYTES])
                                                 }) {
                                self.data = [0; MSG3_BYTES];
                                return Ok(Async::Ready((Err(ClientHandshakeFailure::InvalidMsg2),
                                                        stream)));
                            }

                            self.offset = 0;
                            self.state = WriteMsg3;
                            self.client.create_msg3(&mut self.data);

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            WriteMsg3 => {
                match stream.write(&self.data[self.offset..MSG3_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((e, stream));
                        }
                    }
                    Ok(written) => {
                        self.offset += written;
                        if self.offset < MSG3_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            self.offset = 0;
                            self.state = ReadMsg4;

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            ReadMsg4 => {
                match stream.read(&mut self.data[self.offset..MSG4_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((e, stream));
                        }
                    }
                    Ok(read) => {
                        self.offset += read;
                        if self.offset < MSG4_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            if !self.client
                                    .verify_msg4(unsafe {
                                                     &*(&self.data as *const [u8; MSG3_BYTES] as
                                                        *const [u8; MSG4_BYTES])
                                                 }) {
                                self.data = [0; MSG3_BYTES];
                                return Ok(Async::Ready((Err(ClientHandshakeFailure::InvalidMsg4),
                                                        stream)));
                            }

                            let mut outcome = unsafe { uninitialized() };
                            self.client.outcome(&mut outcome);
                            self.data = [0; MSG3_BYTES]; // TODO make this a cleanup method, also call this on dropping
                            return Ok(Async::Ready((Ok(outcome), stream)));
                        }
                    }
                }
            }
        }

    }
}

/// Reason why a client might reject the server although the handshake itself
/// was executed without IO errors.
pub enum ClientHandshakeFailure {
    /// Received invalid msg2 from the server.
    InvalidMsg2,
    /// Received invalid msg4 from the server.
    InvalidMsg4,
}

// State for the future state machine.
enum State {
    WriteMsg1,
    ReadMsg2,
    WriteMsg3,
    ReadMsg4,
}
use client::State::*;
