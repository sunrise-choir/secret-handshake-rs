//! Asynchronously initiate handshakes.

use std::mem::uninitialized;
use std::io;

use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::utils::memzero;
use futures::{Poll, Async, Future};
use tokio_io::{AsyncRead, AsyncWrite};

use crypto::*;

/// Performs the client side of a handshake.
pub struct ClientHandshaker<'s, S: 's> {
    stream: &'s mut S,
    client: Client,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `client.create_client_challenge` and `client.create_client_auth`, and any data read from the server
    offset: usize, // offset into the data array at which to read/write
}

impl<'s, S: AsyncRead + AsyncWrite> ClientHandshaker<'s, S> {
    /// Creates a new ClientHandshaker to connect to a server with known public key
    /// and app key over the given `stream`.
    pub fn new(stream: &'s mut S,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               client_longterm_pk: &sign::PublicKey,
               client_longterm_sk: &sign::SecretKey,
               client_ephemeral_pk: &box_::PublicKey,
               client_ephemeral_sk: &box_::SecretKey,
               server_longterm_pk: &sign::PublicKey)
               -> ClientHandshaker<'s, S> {
        let mut ret = ClientHandshaker {
            stream: stream,
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
impl<'s, S> Drop for ClientHandshaker<'s, S> {
    fn drop(&mut self) {
        memzero(&mut self.data);
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<'s, S: AsyncRead + AsyncWrite> Future for ClientHandshaker<'s, S> {
    type Item = Result<Outcome, ClientHandshakeFailure>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.state {
            WriteMsg1 => {
                while self.offset < MSG1_BYTES {
                    self.offset += try_nb!(self.stream.write(&self.data[self.offset..MSG1_BYTES]));
                }

                self.offset = 0;
                self.state = FlushMsg1;
                return self.poll();
            }

            FlushMsg1 => {
                try_nb!(self.stream.flush());

                self.state = ReadMsg2;
                return self.poll();
            }

            ReadMsg2 => {
                while self.offset < MSG2_BYTES {
                    self.offset += try_nb!(self.stream.read(&mut self.data[self.offset..
                                                                 MSG2_BYTES]));
                }

                if !self.client
                        .verify_msg2(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG2_BYTES])
                                     }) {
                    return Ok(Async::Ready(Err(ClientHandshakeFailure::InvalidMsg2)));
                }

                self.offset = 0;
                self.state = WriteMsg3;
                self.client.create_msg3(&mut self.data);
                return self.poll();
            }

            WriteMsg3 => {
                while self.offset < MSG3_BYTES {
                    self.offset += try_nb!(self.stream.write(&self.data[self.offset..MSG3_BYTES]));
                }

                self.offset = 0;
                self.state = FlushMsg3;
                return self.poll();
            }

            FlushMsg3 => {
                try_nb!(self.stream.flush());

                self.state = ReadMsg4;
                return self.poll();
            }

            ReadMsg4 => {
                while self.offset < MSG4_BYTES {
                    self.offset += try_nb!(self.stream.read(&mut self.data[self.offset..
                                                                 MSG4_BYTES]));
                }

                if !self.client
                        .verify_msg4(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG4_BYTES])
                                     }) {
                    return Ok(Async::Ready(Err(ClientHandshakeFailure::InvalidMsg4)));
                }

                let mut outcome = unsafe { uninitialized() };
                self.client.outcome(&mut outcome);
                return Ok(Async::Ready(Ok(outcome)));
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
