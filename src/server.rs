use std::{error, io, fmt};
use std::error::Error;
use std::mem::uninitialized;
use std::fmt::Debug;

use sodiumoxide::crypto::{box_, sign, auth};
use futures::{Poll, Async, Future};
use tokio_io::{AsyncRead, AsyncWrite};

use crypto::*;

/// Performs the server side of a handshake.
pub struct ServerHandshaker<S, AuthFn, AsyncBool> {
    stream: Option<S>,
    auth: Option<AuthStuff<AuthFn, AsyncBool>>,
    server: Server,
    state: State,
    data: [u8; MSG3_BYTES], // used to hold and cache the results of `server.create_server_challenge` and `server.create_server_ack`, and any data read from the client
    offset: usize, // offset into the data array at which to read/write
}

impl<S, AuthFn, AsyncBool> ServerHandshaker<S, AuthFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          AuthFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    /// Creates a new ServerHandshaker to accept a connection from a client which
    /// knows the server's public key and uses the right app key over the given `stream`.
    ///
    /// This consumes ownership of the stream, so that no other reads/writes can
    /// interfere with the handshake. When the Future resolves, ownership of the
    /// stream is returned as well.
    pub fn new(stream: S,
               auth_fn: AuthFn,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &[u8; sign::PUBLICKEYBYTES],
               server_longterm_sk: &[u8; sign::SECRETKEYBYTES],
               server_ephemeral_pk: &[u8; box_::PUBLICKEYBYTES],
               server_ephemeral_sk: &[u8; box_::SECRETKEYBYTES])
               -> ServerHandshaker<S, AuthFn, AsyncBool> {
        ServerHandshaker {
            stream: Some(stream),
            auth: Some(AuthFun(auth_fn)),
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
impl<S, AuthFn, AsyncBool> Future for ServerHandshaker<S, AuthFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          AuthFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    type Item = (Outcome, S);
    type Error = ServerHandshakeError<S, AsyncBool::Error>;

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
                            return Err(ServerHandshakeError::IoErr(e, stream));
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
                                return Err(ServerHandshakeError::InvalidMsg1(stream));
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
                            return Err(ServerHandshakeError::IoErr(e, stream));
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
                            return Err(ServerHandshakeError::IoErr(e, stream));
                        }
                    }
                    Ok(read) => {
                        self.offset += read;
                        if self.offset < MSG3_BYTES {
                            self.stream = Some(stream);
                            return self.poll();
                        } else {
                            if !self.server.verify_msg3(&self.data) {
                                return Err(ServerHandshakeError::InvalidMsg3(stream));
                            }

                            let auth_fn = match self.auth
                                .take()
                                .expect("Attempted to poll ServerHandshaker after completion") {
                                    AuthFun(f) => f,
                                    AuthFuture(_) => unreachable!()
                                };

                            self.auth =
                                Some(AuthFuture(auth_fn(&sign::PublicKey(unsafe {
                                                             self.server.client_longterm_pub()
                                                         }))));
                            self.state = AuthenticateClient;

                            self.stream = Some(stream);
                            return self.poll();
                        }
                    }
                }
            }

            AuthenticateClient => {
                let mut auth_future =
                    match self.auth
                              .take()
                              .expect("Attempted to poll ServerHandshaker after completion") {
                        AuthFun(_) => unreachable!(),
                        AuthFuture(f) => f,
                    };

                match auth_future.poll() {
                    Err(e) => return Err(ServerHandshakeError::AuthFnErr(e, stream)),
                    Ok(Async::NotReady) => {
                        self.auth = Some(AuthFuture(auth_future));
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(_)) => {
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
                            return Err(ServerHandshakeError::IoErr(e, stream));
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
                            return Ok(Async::Ready((outcome, stream)));
                        }
                    }
                }
            }

        }
    }
}

/// A fatal error that occured during the asynchronous execution of a handshake.
///
/// All variants return ownership of the inner stream.
#[derive(Debug)]
pub enum ServerHandshakeError<S, AuthErr> {
    /// An IO error occured during reading or writing. The contained error is
    /// guaranteed to not have kind `WouldBlock`.
    IoErr(io::Error, S),
    /// The authentication function errored, the error is wrapped in this variant.
    AuthFnErr(AuthErr, S),
    /// Received invalid msg1 from the client.
    InvalidMsg1(S),
    /// Received invalid msg3 from the client.
    InvalidMsg3(S),
}

impl<S: Debug, AuthErr: error::Error> fmt::Display for ServerHandshakeError<S, AuthErr> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

impl<S: Debug, AuthErr: error::Error> error::Error for ServerHandshakeError<S, AuthErr> {
    fn description(&self) -> &str {
        match *self {
            ServerHandshakeError::IoErr(ref err, _) => "IO error during handshake",
            ServerHandshakeError::AuthFnErr(ref err, _) => "Error during authentication",
            ServerHandshakeError::InvalidMsg1(_) => "received invalid msg1",
            ServerHandshakeError::InvalidMsg3(_) => "received invalid msg3",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ServerHandshakeError::IoErr(ref err, _) => Some(err),
            ServerHandshakeError::AuthFnErr(ref err, _) => Some(err),
            ServerHandshakeError::InvalidMsg1(_) => None,
            ServerHandshakeError::InvalidMsg3(_) => None,
        }
    }
}

// State for the future state machine.
enum State {
    ReadMsg1,
    WriteMsg2,
    ReadMsg3,
    AuthenticateClient,
    WriteMsg4,
}
use server::State::*;

enum AuthStuff<AuthFn, AsyncBool> {
    AuthFun(AuthFn),
    AuthFuture(AsyncBool),
}
use server::AuthStuff::*;
