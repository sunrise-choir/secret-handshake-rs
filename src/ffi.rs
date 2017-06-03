// Some bindings missing from sodiumoxide due to opiniated maintainer.

extern crate libc;

use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::box_;
use libc::c_int;

extern "C" {
    fn crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: *mut [u8; box_::PUBLICKEYBYTES],
                                            ed25519_pk: *const [u8; sign::PUBLICKEYBYTES])
                                            -> c_int;

    fn crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: *mut [u8; box_::SECRETKEYBYTES],
                                            ed25519_sk: *const [u8; sign::SECRETKEYBYTES])
                                            -> c_int;
}

pub fn ed25519_pk_to_curve25519(ed25519_pub: &sign::PublicKey) -> box_::PublicKey {
    let mut curve = [0u8; box_::PUBLICKEYBYTES];
    unsafe {
        crypto_sign_ed25519_pk_to_curve25519(&mut curve, &ed25519_pub.0);
    }
    box_::PublicKey(curve)
}

pub fn ed25519_sk_to_curve25519(ed25519_sec: &sign::SecretKey) -> box_::SecretKey {
    let mut curve = [0u8; box_::SECRETKEYBYTES];
    unsafe {
        crypto_sign_ed25519_sk_to_curve25519(&mut curve, &ed25519_sec.0);
    }
    box_::SecretKey(curve)
}
