//! The errors that an be emitted when performing handshakes.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use futures_io;

/// Errors that can occur during a handshake.
#[derive(Debug)]
pub enum HandshakeError {
    /// An io error occured during the handshake.
    IoError(futures_io::Error),
    /// The peer did not provide correct authentication.
    ///
    /// This error is non-fatal, and the underyling connection should be closed when it is emitted.
    CryptoError,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            HandshakeError::IoError(ref err) => write!(f, "Handshake error: {}", err),
            HandshakeError::CryptoError => write!(f, "Handshake error: crypto error"),
        }
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        match *self {
            HandshakeError::IoError(ref err) => err.description(),
            HandshakeError::CryptoError => "the peer did not provide valid authentication",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            HandshakeError::IoError(ref err) => Some(err),
            HandshakeError::CryptoError => None,
        }
    }
}

impl From<futures_io::Error> for HandshakeError {
    fn from(err: futures_io::Error) -> HandshakeError {
        HandshakeError::IoError(err)
    }
}

/// Errors that can occur during a filtering handshake.
#[derive(Debug)]
pub enum FilteringHandshakeError<FnErr> {
    /// An io error occured during the handshake.
    IoError(futures_io::Error),
    /// The filter function errored.
    ///
    /// This error is non-fatal, and the underyling connection should be closed when it is emitted.
    FilterError(FnErr),
    /// The peer did not provide correct authentication.
    ///
    /// This error is non-fatal, and the underyling connection should be closed when it is emitted.
    CryptoError,
    /// The peer was rejected by the filter function.
    ///
    /// This error is non-fatal, and the underyling connection should be closed when it is emitted.
    Rejected,
}

impl<FnErr: Display> Display for FilteringHandshakeError<FnErr> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            FilteringHandshakeError::IoError(ref err) => write!(f, "Handshake error: {}", err),
            FilteringHandshakeError::FilterError(ref err) => write!(f, "Handshake error: {}", err),
            FilteringHandshakeError::CryptoError => write!(f, "Handshake error: crypto error"),
            FilteringHandshakeError::Rejected => write!(f, "Handshake error: peer rejected"),
        }
    }
}

impl<FnErr: Error> Error for FilteringHandshakeError<FnErr> {
    fn description(&self) -> &str {
        match *self {
            FilteringHandshakeError::IoError(ref err) => err.description(),
            FilteringHandshakeError::FilterError(ref err) => err.description(),
            FilteringHandshakeError::CryptoError => "the peer did not provide valid authentication",
            FilteringHandshakeError::Rejected => "the peer was rejected by the filter function",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            FilteringHandshakeError::IoError(ref err) => Some(err),
            FilteringHandshakeError::FilterError(ref err) => Some(err),
            FilteringHandshakeError::CryptoError => None,
            FilteringHandshakeError::Rejected => None,
        }
    }
}

impl<FnErr> From<futures_io::Error> for FilteringHandshakeError<FnErr> {
    fn from(err: futures_io::Error) -> FilteringHandshakeError<FnErr> {
        FilteringHandshakeError::IoError(err)
    }
}
