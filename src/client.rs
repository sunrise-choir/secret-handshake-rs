//! Asynchronously initiate handshakes.

use std::mem::uninitialized;
use std::io::ErrorKind::{WriteZero, UnexpectedEof, Interrupted, WouldBlock};
use std::io::Error;

use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::utils::memzero;
use futures::{Poll, Async, Future};
use tokio_io::{AsyncRead, AsyncWrite};

use crypto::*;

/// Performs the client side of a handshake.
pub struct ClientHandshaker<'a, S> {
    stream: Option<S>,
    client: Client<'a>,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
}

impl<'a, S: AsyncRead + AsyncWrite> ClientHandshaker<'a, S> {
    /// Creates a new ClientHandshaker to connect to a server with known public key
    /// and app key over the given `stream`.
    pub fn new(stream: S,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               client_longterm_pk: &'a sign::PublicKey,
               client_longterm_sk: &'a sign::SecretKey,
               client_ephemeral_pk: &'a box_::PublicKey,
               client_ephemeral_sk: &'a box_::SecretKey,
               server_longterm_pk: &'a sign::PublicKey)
               -> ClientHandshaker<'a, S> {
        let mut ret = ClientHandshaker {
            stream: Some(stream),
            client: Client::new(network_identifier,
                                &client_longterm_pk.0,
                                &client_longterm_sk.0,
                                &client_ephemeral_pk.0,
                                &client_ephemeral_sk.0,
                                &server_longterm_pk.0),
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

/// Zero buffered handshake data on dropping.
impl<'a, S> Drop for ClientHandshaker<'a, S> {
    fn drop(&mut self) {
        memzero(&mut self.data);
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<'a, S: AsyncRead + AsyncWrite> Future for ClientHandshaker<'a, S> {
    type Item = (Result<Outcome, ClientHandshakeFailure>, S);
    type Error = (Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut stream = self.stream
            .take()
            .expect("Polled ClientHandshaker after completion");

        match self.state {
            WriteMsg1 => {
                while self.offset < MSG1_BYTES {
                    match stream.write(&self.data[self.offset..MSG1_BYTES]) {
                        Ok(written) => {
                            if written == 0 {
                                return Err((Error::new(WriteZero, "failed to write msg1"), stream));
                            }
                            self.offset += written;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e, stream)),
                    }
                }

                self.stream = Some(stream);
                self.offset = 0;
                self.state = FlushMsg1;

                return self.poll();
            }

            FlushMsg1 => {
                match stream.flush() {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == WouldBlock => {
                        self.stream = Some(stream);
                        return Ok(Async::NotReady);
                    }
                    Err(ref e) if e.kind() == Interrupted => {}
                    Err(e) => return Err((e, stream)),
                }

                self.stream = Some(stream);
                self.state = ReadMsg2;
                return self.poll();
            }

            ReadMsg2 => {
                while self.offset < MSG2_BYTES {
                    match stream.read(&mut self.data[self.offset..MSG2_BYTES]) {
                        Ok(read) => {
                            if read == 0 {
                                return Err((Error::new(UnexpectedEof, "failed to read msg2"),
                                            stream));
                            }
                            self.offset += read;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e, stream)),
                    }
                }

                if !self.client
                        .verify_msg2(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG2_BYTES])
                                     }) {
                    return Ok(Async::Ready((Err(ClientHandshakeFailure::InvalidMsg2), stream)));
                }

                self.stream = Some(stream);
                self.offset = 0;
                self.state = WriteMsg3;
                self.client.create_msg3(&mut self.data);
                return self.poll();
            }

            WriteMsg3 => {
                while self.offset < MSG3_BYTES {
                    match stream.write(&self.data[self.offset..MSG3_BYTES]) {
                        Ok(written) => {
                            if written == 0 {
                                return Err((Error::new(WriteZero, "failed to write msg3"), stream));
                            }
                            self.offset += written;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e, stream)),
                    }
                }

                self.stream = Some(stream);
                self.offset = 0;
                self.state = FlushMsg3;
                return self.poll();
            }

            FlushMsg3 => {
                match stream.flush() {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == WouldBlock => {
                        self.stream = Some(stream);
                        return Ok(Async::NotReady);
                    }
                    Err(ref e) if e.kind() == Interrupted => {}
                    Err(e) => return Err((e, stream)),
                }

                self.stream = Some(stream);
                self.state = ReadMsg4;
                return self.poll();
            }

            ReadMsg4 => {
                while self.offset < MSG4_BYTES {
                    match stream.read(&mut self.data[self.offset..MSG4_BYTES]) {
                        Ok(read) => {
                            if read == 0 {
                                return Err((Error::new(UnexpectedEof, "failed to read msg4"),
                                            stream));
                            }
                            self.offset += read;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e, stream)),
                    }
                }

                if !self.client
                        .verify_msg4(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG4_BYTES])
                                     }) {
                    return Ok(Async::Ready((Err(ClientHandshakeFailure::InvalidMsg4), stream)));
                }

                let mut outcome = unsafe { uninitialized() };
                self.client.outcome(&mut outcome);
                return Ok(Async::Ready((Ok(outcome), stream)));
            }

        }
    }
}

/// Reason why a client might reject the server although the handshake itself
/// was executed without IO errors.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ClientHandshakeFailure {
    /// Received invalid msg2 from the server.
    InvalidMsg2,
    /// Received invalid msg4 from the server.
    InvalidMsg4,
}

// State for the future state machine.
enum State {
    WriteMsg1,
    FlushMsg1,
    ReadMsg2,
    WriteMsg3,
    FlushMsg3,
    ReadMsg4,
}
use client::State::*;
