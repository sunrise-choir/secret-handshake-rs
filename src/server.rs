//! Asynchronously accept handshakes.

use std::{error, io, fmt};
use std::error::Error;
use std::io::ErrorKind::{WriteZero, UnexpectedEof, Interrupted, WouldBlock};
use std::marker::PhantomData;
use std::mem::uninitialized;

use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::utils::memzero;
use futures::{Poll, Async, Future};
use futures::future::{ok, FutureResult};
use tokio_io::{AsyncRead, AsyncWrite};
use void::Void;

use crypto::*;

/// Performs the server side of a handshake.
pub struct ServerHandshaker<'a, S>(ServerHandshakerWithFilter<'a,
                                                               S,
                                                               fn(&sign::PublicKey)
                                                                  -> FutureResult<bool, Void>,
                                                               FutureResult<bool, Void>>);

impl<'a, S: AsyncRead + AsyncWrite> ServerHandshaker<'a, S> {
    /// Creates a new ServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    pub fn new(stream: S,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &'a sign::PublicKey,
               server_longterm_sk: &'a sign::SecretKey,
               server_ephemeral_pk: &'a box_::PublicKey,
               server_ephemeral_sk: &'a box_::SecretKey)
               -> ServerHandshaker<'a, S> {
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
impl<'a, S: AsyncRead + AsyncWrite> Future for ServerHandshaker<'a, S> {
    type Item = (Result<Outcome, ServerHandshakeFailure>, S);
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready((Ok(outcome), stream))) => Ok(Async::Ready((Ok(outcome), stream))),
            Ok(Async::Ready((Err(failure), stream))) => {
                match failure {
                    ServerHandshakeFailureWithFilter::InvalidMsg1 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg1), stream)))
                    }
                    ServerHandshakeFailureWithFilter::InvalidMsg3 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg3), stream)))
                    }
                    ServerHandshakeFailureWithFilter::UnauthorizedClient => unreachable!(),
                }
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err((e, stream)) => {
                let new_err = match e {
                    ServerHandshakeError::FilterFnError(_) => unreachable!(),
                    ServerHandshakeError::IoError(io_err) => io_err,
                };

                Err((new_err, stream))
            }
        }
    }
}

/// Performs the server side of a handshake. This copies the keys so that it isn't constrainted by
/// their lifetime.
pub struct OwningServerHandshaker<S>(OwningServerHandshakerWithFilter<S,
                                                                       fn(&sign::PublicKey)
                                                                          -> FutureResult<bool,
                                                                                           Void>,
                                                                       FutureResult<bool, Void>>);

impl<S: AsyncRead + AsyncWrite> OwningServerHandshaker<S> {
    /// Creates a new ServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    pub fn new(stream: S,
               network_identifier: [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: sign::PublicKey,
               server_longterm_sk: sign::SecretKey,
               server_ephemeral_pk: box_::PublicKey,
               server_ephemeral_sk: box_::SecretKey)
               -> OwningServerHandshaker<S> {
        OwningServerHandshaker(OwningServerHandshakerWithFilter::new(stream,
                                                                     const_async_true,
                                                                     network_identifier,
                                                                     server_longterm_pk,
                                                                     server_longterm_sk,
                                                                     server_ephemeral_pk,
                                                                     server_ephemeral_sk))
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S: AsyncRead + AsyncWrite> Future for OwningServerHandshaker<S> {
    type Item = (Result<Outcome, ServerHandshakeFailure>, S);
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready((Ok(outcome), stream))) => Ok(Async::Ready((Ok(outcome), stream))),
            Ok(Async::Ready((Err(failure), stream))) => {
                match failure {
                    ServerHandshakeFailureWithFilter::InvalidMsg1 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg1), stream)))
                    }
                    ServerHandshakeFailureWithFilter::InvalidMsg3 => {
                        Ok(Async::Ready((Err(ServerHandshakeFailure::InvalidMsg3), stream)))
                    }
                    ServerHandshakeFailureWithFilter::UnauthorizedClient => unreachable!(),
                }
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err((e, stream)) => {
                let new_err = match e {
                    ServerHandshakeError::FilterFnError(_) => unreachable!(),
                    ServerHandshakeError::IoError(io_err) => io_err,
                };

                Err((new_err, stream))
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
pub struct ServerHandshakerWithFilter<'a, S, FilterFn, AsyncBool>(UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool>, PhantomData<&'a u8>);

impl<'a, S, FilterFn, AsyncBool> ServerHandshakerWithFilter<'a, S, FilterFn, AsyncBool>
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
    pub fn new(stream: S,
               filter_fn: FilterFn,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &'a sign::PublicKey,
               server_longterm_sk: &'a sign::SecretKey,
               server_ephemeral_pk: &'a box_::PublicKey,
               server_ephemeral_sk: &'a box_::SecretKey)
               -> ServerHandshakerWithFilter<'a, S, FilterFn, AsyncBool> {
        ServerHandshakerWithFilter(UnsafeServerHandshakerWithFilter::new(stream,
                                                                         filter_fn,
                                                                         network_identifier,
                                                                         server_longterm_pk,
                                                                         server_longterm_sk,
                                                                         server_ephemeral_pk,
                                                                         server_ephemeral_sk),
                                   PhantomData)
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<'a, S, FilterFn, AsyncBool> Future for ServerHandshakerWithFilter<'a, S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = (Result<Outcome, ServerHandshakeFailureWithFilter>, S);
    type Error = (ServerHandshakeError<AsyncBool::Error>, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// Performs the server side of a handshake. Allows filtering clients based on
/// their longterm public key. This copies the keys so that it isn't constrainted by
/// their lifetime.
pub struct OwningServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
    network_identifier: Box<[u8; NETWORK_IDENTIFIER_BYTES]>,
    server_longterm_pk: Box<sign::PublicKey>,
    server_longterm_sk: Box<sign::SecretKey>,
    server_ephemeral_pk: Box<box_::PublicKey>,
    server_ephemeral_sk: Box<box_::SecretKey>,
    inner: UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool>,
}

impl<S, FilterFn, AsyncBool> OwningServerHandshakerWithFilter<S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    /// Creates a new OwningServerHandshakerWithFilter to accept a connection from a
    /// client which knows the server's public key and uses the right app key
    /// over the given `stream`.
    ///
    /// Once the client has revealed its longterm public key, `filter_fn` is
    /// invoked. If the returned `AsyncBool` resolves to `Ok(Async::Ready(false))`,
    /// the handshake is aborted.
    pub fn new(stream: S,
               filter_fn: FilterFn,
               network_identifier: [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: sign::PublicKey,
               server_longterm_sk: sign::SecretKey,
               server_ephemeral_pk: box_::PublicKey,
               server_ephemeral_sk: box_::SecretKey)
               -> OwningServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
        let network_identifier = Box::new(network_identifier.clone());
        let server_longterm_pk = Box::new(server_longterm_pk.clone());
        let server_longterm_sk = Box::new(server_longterm_sk.clone());
        let server_ephemeral_pk = Box::new(server_ephemeral_pk.clone());
        let server_ephemeral_sk = Box::new(server_ephemeral_sk.clone());

        OwningServerHandshakerWithFilter {
            inner: UnsafeServerHandshakerWithFilter::new(stream,
                                                         filter_fn,
                                                         network_identifier.as_ref(),
                                                         server_longterm_pk.as_ref(),
                                                         server_longterm_sk.as_ref(),
                                                         server_ephemeral_pk.as_ref(),
                                                         server_ephemeral_sk.as_ref()),
            network_identifier,
            server_longterm_pk,
            server_longterm_sk,
            server_ephemeral_pk,
            server_ephemeral_sk,
        }
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S, FilterFn, AsyncBool> Future for OwningServerHandshakerWithFilter<S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = (Result<Outcome, ServerHandshakeFailureWithFilter>, S);
    type Error = (ServerHandshakeError<AsyncBool::Error>, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

// Performs the server side of a handshake. Allows filtering clients based on
// their longterm public key.
struct UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
    stream: Option<S>,
    filter: Option<FilterStuff<FilterFn, AsyncBool>>,
    server: Server,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

// Zero buffered handshake data on dropping.
impl<S, FilterFn, AsyncBool> Drop for UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
    fn drop(&mut self) {
        memzero(&mut self.data);
    }
}

impl<S, FilterFn, AsyncBool> UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool>
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
    pub fn new(stream: S,
               filter_fn: FilterFn,
               network_identifier: *const [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: *const sign::PublicKey,
               server_longterm_sk: *const sign::SecretKey,
               server_ephemeral_pk: *const box_::PublicKey,
               server_ephemeral_sk: *const box_::SecretKey)
               -> UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool> {
        unsafe {
            UnsafeServerHandshakerWithFilter {
                stream: Some(stream),
                filter: Some(FilterFun(filter_fn)),
                server: Server::new(network_identifier,
                                    &(*server_longterm_pk).0,
                                    &(*server_longterm_sk).0,
                                    &(*server_ephemeral_pk).0,
                                    &(*server_ephemeral_sk).0),
                state: ReadMsg1,
                data: [0; MSG3_BYTES],
                offset: 0,
            }
        }
    }
}

/// Future implementation to asynchronously drive a handshake.
impl<S, FilterFn, AsyncBool> Future for UnsafeServerHandshakerWithFilter<S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = (Result<Outcome, ServerHandshakeFailureWithFilter>, S);
    type Error = (ServerHandshakeError<AsyncBool::Error>, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut stream = self.stream
            .take()
            .expect("Polled ServerHandshaker after completion");

        match self.state {
            ReadMsg1 => {
                while self.offset < MSG1_BYTES {
                    match stream.read(&mut self.data[self.offset..MSG1_BYTES]) {
                        Ok(read) => {
                            if read == 0 {
                                return Err((io::Error::new(UnexpectedEof, "failed to read msg1")
                                                .into(),
                                            stream));
                            }
                            self.offset += read;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e.into(), stream)),
                    }
                }

                if !self.server
                        .verify_msg1(unsafe {
                                         &*(&self.data as *const [u8; MSG3_BYTES] as
                                            *const [u8; MSG1_BYTES])
                                     }) {
                    return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::InvalidMsg1),
                                            stream)));
                }

                self.stream = Some(stream);
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
                    match stream.write(&self.data[self.offset..MSG2_BYTES]) {
                        Ok(written) => {
                            if written == 0 {
                                return Err((io::Error::new(WriteZero, "failed to write msg2")
                                                .into(),
                                            stream));
                            }
                            self.offset += written;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e.into(), stream)),
                    }
                }

                self.stream = Some(stream);
                self.offset = 0;
                self.state = FlushMsg2;
                return self.poll();
            }

            FlushMsg2 => {
                match stream.flush() {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == WouldBlock => {
                        self.stream = Some(stream);
                        return Ok(Async::NotReady);
                    }
                    Err(ref e) if e.kind() == Interrupted => {}
                    Err(e) => return Err((e.into(), stream)),
                }

                self.stream = Some(stream);
                self.state = ReadMsg3;
                return self.poll();
            }

            ReadMsg3 => {
                while self.offset < MSG3_BYTES {
                    match stream.read(&mut self.data[self.offset..MSG3_BYTES]) {
                        Ok(read) => {
                            if read == 0 {
                                return Err((io::Error::new(UnexpectedEof, "failed to read msg3")
                                                .into(),
                                            stream));
                            }
                            self.offset += read;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e.into(), stream)),
                    }
                }

                if !self.server.verify_msg3(&self.data) {
                    return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::InvalidMsg3),
                                            stream)));
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

                self.stream = Some(stream);
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
                    Err(e) => return Err((ServerHandshakeError::FilterFnError(e), stream)),
                    Ok(Async::NotReady) => {
                        self.filter = Some(FilterFuture(filter_future));
                        self.stream = Some(stream);
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(is_authorized)) => {
                        if !is_authorized {
                            return Ok(Async::Ready((Err(ServerHandshakeFailureWithFilter::UnauthorizedClient), stream)));
                        }

                        self.stream = Some(stream);
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
                    match stream.write(&self.data[self.offset..MSG4_BYTES]) {
                        Ok(written) => {
                            if written == 0 {
                                return Err((io::Error::new(WriteZero, "failed to write msg4")
                                                .into(),
                                            stream));
                            }
                            self.offset += written;
                        }
                        Err(ref e) if e.kind() == WouldBlock => {
                            self.stream = Some(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(ref e) if e.kind() == Interrupted => {}
                        Err(e) => return Err((e.into(), stream)),
                    }
                }

                self.stream = Some(stream);
                self.offset = 0;
                self.state = FlushMsg4;
                return self.poll();
            }

            FlushMsg4 => {
                match stream.flush() {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == WouldBlock => {
                        self.stream = Some(stream);
                        return Ok(Async::NotReady);
                    }
                    Err(ref e) if e.kind() == Interrupted => {}
                    Err(e) => return Err((e.into(), stream)),
                }

                let mut outcome = unsafe { uninitialized() };
                self.server.outcome(&mut outcome);
                return Ok(Async::Ready((Ok(outcome), stream)));
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
