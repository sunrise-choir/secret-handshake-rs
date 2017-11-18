//! Asynchronously accept handshakes.

use std::{error, io, fmt};
use std::error::Error;
use std::mem::uninitialized;

use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::utils::memzero;
use futures::{Poll, Async, Future};
use futures::future::{ok, FutureResult};
use tokio_io::{AsyncRead, AsyncWrite};
use void::Void;

use crypto::*;

/// Performs the server side of a handshake.
pub struct ServerHandshaker<'s, S: 's>(ServerHandshakerWithFilter<'s,
                                                                   S,
                                                                   fn(&sign::PublicKey)
                                                                      -> FutureResult<bool,
                                                                                       Void>,
                                                                   FutureResult<bool, Void>>);

impl<'s, S: AsyncRead + AsyncWrite> ServerHandshaker<'s, S> {
    /// Creates a new ServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    pub fn new(stream: &'s mut S,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &sign::PublicKey,
               server_longterm_sk: &sign::SecretKey,
               server_ephemeral_pk: &box_::PublicKey,
               server_ephemeral_sk: &box_::SecretKey)
               -> ServerHandshaker<'s, S> {
        ServerHandshaker(ServerHandshakerWithFilter::new(stream,
                                                         const_async_true,
                                                         network_identifier,
                                                         &server_longterm_pk,
                                                         &server_longterm_sk,
                                                         &server_ephemeral_pk,
                                                         &server_ephemeral_sk))
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<'s, S: AsyncRead + AsyncWrite> Future for ServerHandshaker<'s, S> {
    type Item = Result<Outcome, ServerHandshakeFailure>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(Ok(outcome))) => Ok(Async::Ready(Ok(outcome))),
            Ok(Async::Ready(Err(failure))) => {
                match failure {
                    ServerHandshakeFailureWithFilter::InvalidMsg1 => {
                        Ok(Async::Ready(Err(ServerHandshakeFailure::InvalidMsg1)))
                    }
                    ServerHandshakeFailureWithFilter::InvalidMsg3 => {
                        Ok(Async::Ready(Err(ServerHandshakeFailure::InvalidMsg3)))
                    }
                    ServerHandshakeFailureWithFilter::UnauthorizedClient => unreachable!(),
                }
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => {
                let new_err = match e {
                    ServerHandshakeError::FilterFnError(_) => unreachable!(),
                    ServerHandshakeError::IoError(io_err) => io_err,
                };

                Err(new_err)
            }
        }
    }
}

fn const_async_true(_: &sign::PublicKey) -> FutureResult<bool, Void> {
    ok(true)
}

/// Reason why a server might reject the client although the handshake itself
/// was executed without IO errors.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerHandshakeFailure {
    /// Received invalid msg1 from the client.
    InvalidMsg1,
    /// Received invalid msg3 from the client.
    InvalidMsg3,
}

/// Performs the server side of a handshake. Allows filtering clients based on
/// their longterm public key.
pub struct ServerHandshakerWithFilter<'s, S: 's, FilterFn, AsyncBool> {
    stream: &'s mut S,
    filter: Option<FilterStuff<FilterFn, AsyncBool>>,
    server: Server,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

/// Zero buffered handshake data on dropping.
impl<'s, S, FilterFn, AsyncBool> Drop for ServerHandshakerWithFilter<'s, S, FilterFn, AsyncBool> {
    fn drop(&mut self) {
        memzero(&mut self.data);
    }
}

impl<'s, S, FilterFn, AsyncBool> ServerHandshakerWithFilter<'s, S, FilterFn, AsyncBool>
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
    pub fn new(stream: &'s mut S,
               filter_fn: FilterFn,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &sign::PublicKey,
               server_longterm_sk: &sign::SecretKey,
               server_ephemeral_pk: &box_::PublicKey,
               server_ephemeral_sk: &box_::SecretKey)
               -> ServerHandshakerWithFilter<'s, S, FilterFn, AsyncBool> {
        ServerHandshakerWithFilter {
            stream: stream,
            filter: Some(FilterFun(filter_fn)),
            server: Server::new(network_identifier,
                                &server_longterm_pk.0,
                                &server_longterm_sk.0,
                                &server_ephemeral_pk.0,
                                &server_ephemeral_sk.0),
            state: ReadMsg1,
            data: [0; MSG3_BYTES],
            offset: 0,
        }
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<'s, S, FilterFn, AsyncBool> Future for ServerHandshakerWithFilter<'s, S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = Result<Outcome, ServerHandshakeFailureWithFilter>;
    type Error = ServerHandshakeError<AsyncBool::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.state {
            ReadMsg1 => {
                while self.offset < MSG1_BYTES {
                    self.offset += try_nb!(self.stream.read(&mut self.data[self.offset..
                                                                 MSG1_BYTES]));
                }

                if !self.server
                        .verify_msg1(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG1_BYTES])
                                     }) {
                    return Ok(Async::Ready(Err(ServerHandshakeFailureWithFilter::InvalidMsg1)));
                }

                self.offset = 0;
                self.state = WriteMsg2;
                self.server
                    .create_msg2(unsafe {
                                     &mut *(&mut self.data as *mut [u8; MSG3_BYTES] as
                                            *mut [u8; MSG2_BYTES])
                                 });
                return self.poll();
            }

            WriteMsg2 => {
                while self.offset < MSG2_BYTES {
                    self.offset += try_nb!(self.stream.write(&self.data[self.offset..MSG2_BYTES]));
                }

                self.offset = 0;
                self.state = FlushMsg2;
                return self.poll();
            }

            FlushMsg2 => {
                try_nb!(self.stream.flush());

                self.state = ReadMsg3;
                return self.poll();
            }

            ReadMsg3 => {
                while self.offset < MSG3_BYTES {
                    self.offset += try_nb!(self.stream.read(&mut self.data[self.offset..
                                                                 MSG3_BYTES]));
                }

                if !self.server.verify_msg3(&self.data) {
                    return Ok(Async::Ready(Err(ServerHandshakeFailureWithFilter::InvalidMsg3)));
                }

                let filter_fn =
                    match self.filter
                              .take()
                              .expect("Attempted to poll ServerHandshaker after completion") {
                        FilterFun(f) => f,
                        FilterFuture(_) => unreachable!(),
                    };

                self.filter =
                    Some(FilterFuture(filter_fn(&sign::PublicKey(unsafe {
                                                 self.server.client_longterm_pub()
                                             }))));

                self.offset = 0;
                self.state = FilterClient;
                return self.poll();
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
                    Err(e) => return Err(ServerHandshakeError::FilterFnError(e)),
                    Ok(Async::NotReady) => {
                        self.filter = Some(FilterFuture(filter_future));
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(is_authorized)) => {
                        if !is_authorized {
                            return Ok(Async::Ready(Err(ServerHandshakeFailureWithFilter::UnauthorizedClient)));
                        }

                        self.state = WriteMsg4;
                        self.server
                            .create_msg4(unsafe {
                                             &mut *(&mut self.data as *mut [u8; MSG3_BYTES] as
                                                    *mut [u8; MSG4_BYTES])
                                         });

                        return self.poll();
                    }
                }
            }

            WriteMsg4 => {
                while self.offset < MSG4_BYTES {
                    self.offset += try_nb!(self.stream.write(&self.data[self.offset..MSG4_BYTES]));
                }

                self.offset = 0;
                self.state = FlushMsg4;
                return self.poll();
            }

            FlushMsg4 => {
                try_nb!(self.stream.flush());

                let mut outcome = unsafe { uninitialized() };
                self.server.outcome(&mut outcome);
                return Ok(Async::Ready(Ok(outcome)));
            }

        }
    }
}

/// A fatal error that occured during the execution of a handshake by a
/// filtering server.
#[derive(Debug)]
pub enum ServerHandshakeError<FilterErr> {
    /// An IO error occured during reading or writing. The contained error is
    /// guaranteed to not have kind `WouldBlock`.
    IoError(io::Error),
    /// The filter function errored, the error is wrapped in this variant.
    FilterFnError(FilterErr),
}

impl<FilterErr> From<io::Error> for ServerHandshakeError<FilterErr> {
    fn from(error: io::Error) -> Self {
        ServerHandshakeError::IoError(error)
    }
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
            ServerHandshakeError::IoError(_) => "IO error during handshake",
            ServerHandshakeError::FilterFnError(_) => "Error during authentication",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ServerHandshakeError::IoError(ref err) => Some(err),
            ServerHandshakeError::FilterFnError(ref err) => Some(err),
        }
    }
}

// State for the future state machine.
enum State {
    ReadMsg1,
    WriteMsg2,
    FlushMsg2,
    ReadMsg3,
    FilterClient,
    WriteMsg4,
    FlushMsg4,
}
use server::State::*;

enum FilterStuff<FilterFn, AsyncBool> {
    FilterFun(FilterFn),
    FilterFuture(AsyncBool),
}
use server::FilterStuff::*;

/// Reason why a filtering server might reject the client although the handshake itself
/// was executed without IO errors.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerHandshakeFailureWithFilter {
    /// Received invalid msg1 from the client.
    InvalidMsg1,
    /// Received invalid msg3 from the client.
    InvalidMsg3,
    /// Filtered out the client based on its longterm public key.
    UnauthorizedClient,
}
