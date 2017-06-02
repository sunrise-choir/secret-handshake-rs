//! This module provides the raw crypto operations performed in the handshake. You probably do not need to use this directly, but can use the higher-level api instead.

use std::ptr::copy_nonoverlapping;

use sodiumoxide::crypto::auth;
// use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::box_;

/// In the first phase of the handshake, the client sends a challenge to the server. This challenge
/// consists of the HMAC-SHA-512-256 of an ephemeral public key using the appkey as the hmac key,
/// and of the ephemeral public key itself. While it is returned as a simple `[u8; 64]`,
/// conceptually its type is `(auth::Tag, box_::PublicKey)`.
pub fn create_client_challenge(app_key: &auth::Key,
                               client_eph_pub_key: &box_::PublicKey)
                               -> [u8; 64] {
    let mut ret = [0u8; 64];

    let auth::Tag(client_app_hmac) = auth::authenticate(&client_eph_pub_key[..], app_key);
    let &box_::PublicKey(client_eph_pub) = client_eph_pub_key;

    let client_app_hmac_ptr: *const [u8; 32] = &client_app_hmac;
    let client_eph_pub_ptr: *const [u8; 32] = &client_eph_pub;

    let ret_ptr: *mut [u8; 64] = &mut ret;

    unsafe {
        copy_nonoverlapping(client_app_hmac_ptr, ret_ptr as *mut [u8; 32], 1);
        copy_nonoverlapping(client_eph_pub_ptr, (ret_ptr as *mut [u8; 32]).offset(1), 1);
    }

    return ret;
}

/// When the server receives the client's challenge, it needs to verify it. The challenge is considered valid, if the first 32 bytes match the HMAC-SHA-512-256 of the last 32 bytes using the appkey as the hmac key.
// TODO
pub fn verify_client_challenge(client_challenge: &[u8; 64]) -> bool {
    false
}

/// Note: This function does not conform to the secret-handshake protocol.
/// Instead it reproduces a mistake in the reference implementation. Use
/// this if interoperability with peers using the old reference
/// implementation is necessary. If interoperability is not a concern, use
/// `create_server_challenge` instead.
///
/// After receiving and verifying the client's challenge, the server creates it's own challenge. This challenge consists of the HMAC-SHA-512-256 of an ephemeral public key using the appkey as the hmac key, and of the ephemeral public key itself. This is the same as `create_client_challenge` (exept for using a different ephemeral key).
#[deprecated(note="the legacy methods will be removed when the shs ecosystem stops using the faulty implementation")]
pub fn legacy_create_server_challenge(app_key: &auth::Key,
                                      server_eph_pub_key: &box_::PublicKey)
                                      -> (auth::Tag, box_::PublicKey) {
    let server_app_hmac = auth::authenticate(&server_eph_pub_key[..], app_key);
    return (server_app_hmac, *server_eph_pub_key);
}

/// After receiving and verifying the client's challenge, the server creates it's own challenge. This challenge consists of the HMAC-SHA-512-256 of an ephemeral public key using `sha256(appkey ++ scalar_mult())` as the hmac key, and of the ephemeral public key itself.
// TODO
pub fn create_server_challenge(app_key: &auth::Key,
                               server_eph_pub_key: &box_::PublicKey)
                               -> (auth::Tag, box_::PublicKey) {
    let server_app_hmac = auth::authenticate(&server_eph_pub_key[..], app_key); // TODO
    return (server_app_hmac, *server_eph_pub_key);
}

/// Note: This function does not conform to the secret-handshake protocol.
/// Instead it reproduces a mistake in the reference implementation. Use
/// this if interoperability with peers using the old reference
/// implementation is necessary. If interoperability is not a concern, use
/// `create_server_challenge` instead.
///
/// When the client receives the server's challenge, it needs to verify it. The challenge is considered valid, if the first 32 bytes match the HMAC-SHA-512-256 of the last 32 bytes using the appkey as the hmac key. This is the same as `verify_client_challenge`
// TODO
#[deprecated(note="the legacy methods will be removed when the shs ecosystem stops using the faulty implementation")]
pub fn legacy_verify_server_challenge(server_challenge: &[u8]) -> bool {
    // return verify_client_challenge(server_challenge);
    false
}

/// When the client receives the server's challenge, it needs to verify it. The challenge is considered valid, if the first 32 bytes match the HMAC-SHA-512-256 of the last 32 bytes using the appkey as the hmac key. This is the same as `verify_client_challenge`
// TODO
pub fn verify_server_challenge() -> bool {
    false
}

pub fn create_client_authentication() -> () {}

pub fn verify_client_authentication() -> bool {
    false
}

pub fn create_server_authentication() -> () {}

pub fn verify_server_authentication() -> bool {
    false
}
