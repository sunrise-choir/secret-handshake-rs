//! An implementation of the [secret-handshake](https://github.com/auditdrivencrypto/secret-handshake) protocol..
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! shs = "0.1"
//! ```
#![warn(missing_docs)]

use std::any::Any;
use std::error;
use std::error::Error as StdError;
use std::io;
use std::fmt;
use std::result;

/// A TLS stream which has been interrupted midway through the handshake process.
pub struct MidHandshakeShsStream<S>(S); // TODO

impl<S> fmt::Debug for MidHandshakeShsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        Ok(()) // TODO
    }
}

impl<S> MidHandshakeShsStream<S>
    where S: io::Read + io::Write
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.0 // TODO
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0 // TODO
    }

    /// Restarts the handshake process.
    ///
    /// If the handshake completes successfully then the negotiated stream is
    /// returned. If there is a problem, however, then an error is returned.
    /// Note that the error may not be fatal. For example if the underlying
    /// stream is an asynchronous one then `HandshakeError::Interrupted` may
    /// just mean to wait for more I/O to happen later.
    pub fn handshake(self) -> result::Result<ShsStream<S>, HandshakeError<S>> {
        match self.0.handshake() { // TODO
            Ok(s) => Ok(ShsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    Interrupted(MidHandshakeShsStream<S>),
}

impl<S> error::Error for HandshakeError<S>
    where S: Any + fmt::Debug
{
    fn description(&self) -> &str {
        match *self {
            HandshakeError::Failure(ref e) => e.description(),
            HandshakeError::Interrupted(_) => "the handshake process was interrupted",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            HandshakeError::Failure(ref e) => Some(e),
            HandshakeError::Interrupted(_) => None,
        }
    }
}

impl<S> fmt::Display for HandshakeError<S>
    where S: Any + fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(self.description()));
        if let Some(cause) = self.cause() {
            try!(write!(fmt, ": {}", cause));
        }
        Ok(())
    }
}

/// A builder for `ShsConnector`s.
pub struct ShsConnectorBuilder; // TODO

impl ShsConnectorBuilder {
    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, pkcs12: Pkcs12) -> Result<&mut TlsConnectorBuilder> {
        try!(self.0.identity(pkcs12.0));
        Ok(self)
    }

    /// Consumes the builder, returning a `ShsConnector`.
    pub fn build(self) -> Result<ShsConnector> {
        let connector = try!(self.0.build());
        Ok(ShsConnector(connector))
    }
}

/// A builder for client-side Shs connections.
#[derive(Clone)]
pub struct ShsConnector; // TODO

impl ShsConnector {
    /// Returns a new builder for an `ShsConnector`.
    pub fn builder() -> Result<ShsConnectorBuilder> {
        let builder = try!(ShsConnector::builder());
        Ok(ShsConnectorBuilder(builder))
    }

    /// Initiates an shs handshake.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn connect<S>(&self,
                      domain: &str,
                      stream: S)
                      -> result::Result<ShsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        let s = try!(self.0.connect(domain, stream));
        Ok(ShsStream(s))
    }
}

/// A builder for `ShsAcceptor`s.
pub struct ShsAcceptorBuilder(); // TODO

impl ShsAcceptorBuilder {
    /// Consumes the builder, returning an `ShsAcceptor`.
    pub fn build(self) -> Result<TlsAcceptor> {
        let acceptor = try!(self.0.build());
        Ok(ShsAcceptor(acceptor))
    }
}

#[derive(Clone)]
pub struct ShsAcceptor; // TODO

impl ShsAcceptor {
    /// Returns a new builder for a `TlsAcceptor`.
    ///
    /// This builder is created with a key/certificate pair in the `pkcs12`
    /// archived passed in. The returned builder will use that key/certificate
    /// to send to clients which it connects to.
    pub fn builder(pkcs12: Pkcs12) -> Result<ShsAcceptorBuilder> {
        let builder = try!(imp::TlsAcceptor::builder(pkcs12.0));
        Ok(ShsAcceptorBuilder(builder))
    }

    /// Initiates an shs handshake.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::Interrupted` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn accept<S>(&self, stream: S) -> result::Result<ShsStream<S>, HandshakeError<S>>
        where S: io::Read + io::Write
    {
        match self.0.accept(stream) {
            Ok(s) => Ok(ShsStream(s)),
            Err(e) => Err(e.into()),
        }
    }
}

/// A stream managing an shs session.
pub struct ShsStream<S>(S); // TODO

impl<S: fmt::Debug> fmt::Debug for ShsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> ShsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns the number of bytes that can be read without resulting in any
    /// network calls.
    pub fn buffered_read_size(&self) -> Result<usize> {
        Ok(try!(self.0.buffered_read_size()))
    }

    /// Shuts down the shs session.
    pub fn shutdown(&mut self) -> io::Result<()> {
        try!(self.0.shutdown());
        Ok(())
    }
}

impl<S: io::Read + io::Write> io::Read for ShsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for ShsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
