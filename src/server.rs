//! Asynchronously accept handshakes.

use std::{error, io, fmt};
use std::error::Error;
use std::mem::uninitialized;
use std::fmt::Debug;

use sodiumoxide::crypto::{box_, sign, auth};
use futures::{Poll, Async, Future};
use futures::future::{ok, FutureResult};
use tokio_io::{AsyncRead, AsyncWrite};
use void::Void;

use crypto::*;

/// Performs the server side of a handshake.
pub struct ServerHandshaker<S>(ServerHandshakerWithFilter<S,
                                                           fn(&sign::PublicKey)
                                                              -> FutureResult<bool, Void>,
                                                           FutureResult<bool, Void>>);

impl<S: AsyncRead + AsyncWrite> ServerHandshaker<S> {
    /// Creates a new ServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    ///
    /// This consumes ownership of the stream, so that no other reads/writes can
    /// interfere with the handshake. When the Future resolves, ownership of the
    /// stream is returned as well.
    pub fn new(stream: S,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &[u8; sign::PUBLICKEYBYTES],
               server_longterm_sk: &[u8; sign::SECRETKEYBYTES],
               server_ephemeral_pk: &[u8; box_::PUBLICKEYBYTES],
               server_ephemeral_sk: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshaker<S> {
        ServerHandshaker(ServerHandshakerWithFilter::new(stream,
                                                         const_async_true,
                                                         network_identifier,
                                                         server_longterm_pk,
                                                         server_longterm_sk,
                                                         server_ephemeral_pk,
                                                         server_ephemeral_sk))
    }
}

impl<S: AsyncRead + AsyncWrite> Future for ServerHandshaker<S> {
    type Item = (Result<Outcome, ServerHandshakeFailure>, S);
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready((Ok(outcome), s))) => Ok(Async::Ready((Ok(outcome), s))),
            Ok(Async::Ready((Err(failure), s))) => {
                match failure {
                    ServerHandshakeFailureWithFilter::InvalidMsg1 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg1), s)))
                    }
                    ServerHandshakeFailureWithFilter::InvalidMsg3 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg3), s)))
                    }
                    ServerHandshakeFailureWithFilter::UnauthorizedClient => unreachable!(),
                }
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err((e, s)) => {
                let new_err = match e {
                    ServerHandshakeError::FilterFnErr(_) => unreachable!(),
                    ServerHandshakeError::IoErr(io_err) => io_err,
                };

                Err((new_err, s))
            }
        }
    }
}

fn const_async_true(_: &sign::PublicKey) -> FutureResult<bool, Void> {
    ok(true)
}

/// Reason why a server might reject the client although the handshake itself
/// was executed without IO errors.
pub enum ServerHandshakeFailure {
    /// Received invalid msg1 from the client.
    InvalidMsg1,
    /// Received invalid msg3 from the client.
    InvalidMsg3,
}

/// Performs the server side of a handshake. Allows filtering clients based on
/// their longterm public key.
pub struct ServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
    stream: Option<S>,
    filter: Option<FilterStuff<FilterFn, AsyncBool>>,
    server: Server,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

impl<S, FilterFn, AsyncBool> ServerHandshakerWithFilter<S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    /// Creates a new ServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    ///
    /// Once the client has revealed its longterm public key, `filter_fn` is
    /// invoked. If the returned `AsyncBool` resolves to `Ok(Async::Ready(false))`,
    /// the handshake is aborted.
    ///
    /// This consumes ownership of the stream, so that no other reads/writes can
    /// interfere with the handshake. When the Future resolves, ownership of the
    /// stream is returned as well.
    pub fn new(stream: S,
               filter_fn: FilterFn,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &[u8; sign::PUBLICKEYBYTES],
               server_longterm_sk: &[u8; sign::SECRETKEYBYTES],
               server_ephemeral_pk: &[u8; box_::PUBLICKEYBYTES],
               server_ephemeral_sk: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
        ServerHandshakerWithFilter {
            stream: Some(stream),
            filter: Some(FilterFun(filter_fn)),
            server: Server::new(network_identifier,
                                server_longterm_pk,
                                server_longterm_sk,
                                server_ephemeral_pk,
                                server_ephemeral_sk),
            state: ReadMsg1,
            data: [0; MSG3_BYTES],
            offset: 0,
        }
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S, FilterFn, AsyncBool> Future for ServerHandshakerWithFilter<S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = (Result<Outcome, ServerHandshakeFailureWithFilter>, S);
    type Error = (ServerHandshakeError<AsyncBool::Error>, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut stream = self.stream
            .take()
            .expect("Attempted to poll ServerHandshaker after completion");
        match self.state {
            ReadMsg1 => {
                match stream.read(&mut self.data[self.offset..MSG1_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((ServerHandshakeError::IoErr(e), stream));
                        }
                    }
                    Ok(read) => {
                        self.offset += read;
                        if self.offset < MSG1_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            if !self.server
                                    .verify_msg1(unsafe {
                                                     &*(&self.data as *const [u8; MSG3_BYTES] as
                                                        *const [u8; MSG1_BYTES])
                                                 }) {
                                self.data = [0; MSG3_BYTES];
                                return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::InvalidMsg1),
                                                        stream)));
                            }

                            self.offset = 0;
                            self.state = WriteMsg2;
                            self.server
                                .create_msg2(unsafe {
                                                 &mut *(&mut self.data as *mut [u8; MSG3_BYTES] as
                                                        *mut [u8; MSG2_BYTES])
                                             });

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            WriteMsg2 => {
                match stream.write(&self.data[self.offset..MSG2_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((ServerHandshakeError::IoErr(e), stream));
                        }
                    }
                    Ok(written) => {
                        self.offset += written;
                        if self.offset < MSG2_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            self.offset = 0;
                            self.state = ReadMsg3;

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            ReadMsg3 => {
                match stream.read(&mut self.data[self.offset..MSG3_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((ServerHandshakeError::IoErr(e), stream));
                        }
                    }
                    Ok(read) => {
                        self.offset += read;
                        if self.offset < MSG3_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            if !self.server.verify_msg3(&self.data) {
                                self.data = [0; MSG3_BYTES];
                                return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::InvalidMsg3),
                                                        stream)));
                            }

                            let filter_fn = match self.filter
                                .take()
                                .expect("Attempted to poll ServerHandshaker after completion") {
                                    FilterFun(f) => f,
                                    FilterFuture(_) => unreachable!()
                                };

                            self.filter =
                                Some(FilterFuture(filter_fn(&sign::PublicKey(unsafe {
                                                             self.server.client_longterm_pub()
                                                         }))));
                            self.state = FilterClient;

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            FilterClient => {
                let mut filter_future =
                    match self.filter
                              .take()
                              .expect("Attempted to poll ServerHandshaker after completion") {
                        FilterFun(_) => unreachable!(),
                        FilterFuture(f) => f,
                    };

                match filter_future.poll() {
                    Err(e) => return Err((ServerHandshakeError::FilterFnErr(e), stream)),
                    Ok(Async::NotReady) => {
                        self.filter = Some(FilterFuture(filter_future));
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(is_authorized)) => {
                        if !is_authorized {
                            self.data = [0; MSG3_BYTES];
                            return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::UnauthorizedClient), stream)));
                        }

                        self.offset = 0;
                        self.state = WriteMsg4;
                        self.server
                            .create_msg4(unsafe {
                                             &mut *(&mut self.data as *mut [u8; MSG3_BYTES] as
                                                    *mut [u8; MSG4_BYTES])
                                         });

                        self.stream = Some(stream);
                        return self.poll();
                    }
                }
            }

            WriteMsg4 => {
                match stream.write(&self.data[self.offset..MSG4_BYTES]) {
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        } else {
                            self.data = [0; MSG3_BYTES];
                            return Err((ServerHandshakeError::IoErr(e), stream));
                        }
                    }
                    Ok(written) => {
                        self.offset += written;
                        if self.offset < MSG4_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            let mut outcome = unsafe { uninitialized() };
                            self.server.outcome(&mut outcome);
                            self.data = [0; MSG3_BYTES];
                            return Ok(Async::Ready((Ok(outcome), stream)));
                        }
                    }
                }
            }

        }
    }
}

/// A fatal error that occured during the asynchronous execution of a handshake.
#[derive(Debug)]
pub enum ServerHandshakeError<FilterErr> {
    /// An IO error occured during reading or writing. The contained error is
    /// guaranteed to not have kind `WouldBlock`.
    IoErr(io::Error),
    /// The authentication function errored, the error is wrapped in this variant.
    FilterFnErr(FilterErr),
}

impl<FilterErr: error::Error> fmt::Display for ServerHandshakeError<FilterErr> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<FilterErr: error::Error> error::Error for ServerHandshakeError<FilterErr> {
    fn description(&self) -> &str {
        match *self {
            ServerHandshakeError::IoErr(ref err) => "IO error during handshake",
            ServerHandshakeError::FilterFnErr(ref err) => "Error during authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ServerHandshakeError::IoErr(ref err) => Some(err),
            ServerHandshakeError::FilterFnErr(ref err) => Some(err),
        }
    }
}

// State for the future state machine.
enum State {
    ReadMsg1,
    WriteMsg2,
    ReadMsg3,
    FilterClient,
    WriteMsg4,
}
use server::State::*;

enum FilterStuff<FilterFn, AsyncBool> {
    FilterFun(FilterFn),
    FilterFuture(AsyncBool),
}
use server::FilterStuff::*;

/// Reason why a filtering server might reject the client although the handshake itself
/// was executed without IO errors.
pub enum ServerHandshakeFailureWithFilter {
    /// Received invalid msg1 from the client.
    InvalidMsg1,
    /// Received invalid msg3 from the client.
    InvalidMsg3,
    /// Filtered out the client based on its longterm public key.
    UnauthorizedClient,
}
