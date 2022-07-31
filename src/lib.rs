#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bytes::Bytes;
use std::sync::Once;
use thiserror::Error;

static INIT: Once = Once::new();

fn tee_setup() {
    INIT.call_once(|| {
        helium_init();
    });
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("tee error: {0}")]
    TeeError(i32),
}
pub type Result<T> = std::result::Result<T, Error>;

fn helium_init() {
    unsafe {
        ffi::helium_init();
    };
}

#[allow(dead_code)]
fn helium_deinit() {
    unsafe {
        ffi::helium_deinit();
    };
}

pub fn ecdsa_sign_digest(slot: u8, msg_digest: &[u8]) -> Result<Bytes> {
    tee_setup();
    let inbuf =
        msg_digest.as_ptr() as *const ::std::os::raw::c_char as *const ::std::os::raw::c_void;
    let inlen = msg_digest.len() as ffi::size_t;
    let mut outbuf = [0u8; 256];
    let mut outlen = outbuf.len() as ffi::size_t;
    let result = unsafe {
        ffi::ecdsa_sign_digest(
            slot,
            inbuf as *mut ::std::os::raw::c_void,
            inlen,
            outbuf.as_mut_ptr() as *mut ::std::os::raw::c_void,
            &mut outlen,
        )
    };
    match result {
        0 => Ok(bytes::Bytes::copy_from_slice(&outbuf[..outlen as usize])),
        _ => Err(Error::TeeError(result)),
    }
}

pub fn ecdsa_verify(slot: u8, msg: &[u8], signature: &[u8]) -> Result<bool> {
    tee_setup();
    let digestbuf = msg.as_ptr() as *const ::std::os::raw::c_char as *const ::std::os::raw::c_void;
    let digestlen = msg.len() as ffi::size_t;
    let signaturebuf =
        signature.as_ptr() as *const ::std::os::raw::c_char as *const ::std::os::raw::c_void;
    let signaturelen = signature.len() as ffi::size_t;
    let result = unsafe {
        ffi::ecdsa_verify(
            slot,
            digestbuf as *mut ::std::os::raw::c_void,
            digestlen,
            signaturebuf as *mut ::std::os::raw::c_void,
            signaturelen,
        )
    };
    match result {
        0 => Ok(true),
        _ => Err(Error::TeeError(result)),
    }
}

pub fn ecdh(slot: u8, x: &[u8], y: &[u8]) -> Result<Bytes> {
    tee_setup();
    let xbuf = x.as_ptr() as *const ::std::os::raw::c_char as *const ::std::os::raw::c_void;
    let xlen = x.len() as ffi::size_t;
    let ybuf = y.as_ptr() as *const ::std::os::raw::c_char as *const ::std::os::raw::c_void;
    let ylen = y.len() as ffi::size_t;
    let mut secret = [0u8; 256];
    let mut sectlen = secret.len() as ffi::size_t;
    let result = unsafe {
        ffi::ecdh(
            slot,
            xbuf,
            xlen,
            ybuf,
            ylen,
            secret.as_mut_ptr() as *mut ::std::os::raw::c_void,
            &mut sectlen,
        )
    };

    match result {
        0 => Ok(Bytes::copy_from_slice(&secret[..sectlen as usize])),
        e => Err(Error::TeeError(e)),
    }
}

pub fn publickey(slot: u8) -> Result<([u8; 32], [u8; 32])> {
    tee_setup();
    let mut x = [0u8; 32];
    let mut xlen = x.len() as ffi::size_t;
    let mut y = [0u8; 32];
    let mut ylen = y.len() as ffi::size_t;

    let result = unsafe {
        ffi::get_ecc_publickey(
            slot,
            x.as_mut_ptr() as *mut ::std::os::raw::c_void,
            &mut xlen,
            y.as_mut_ptr() as *mut ::std::os::raw::c_void,
            &mut ylen,
        )
    };

    match result {
        0 => {
            Ok((x, y))
            // use std::convert::{From, TryFrom, TryInto};
            // use p256::{
            //     self,
            //     elliptic_curve::{
            //         bigint::Encoding,
            //         sec1::{self, FromEncodedPoint, ToCompactEncodedPoint},
            //         Curve,
            //     },
            //     CompressedPoint, EncodedPoint, NistP256, PublicKey,
            // };
            // let mut key_bytes = [0u8; 65];
            // key_bytes[0] = sec1::Tag::Uncompressed.into();
            // key_bytes[1..(<NistP256 as Curve>::UInt::BYTE_SIZE + 1)].copy_from_slice(&x);
            // key_bytes[(<NistP256 as Curve>::UInt::BYTE_SIZE + 1)..].copy_from_slice(&y);
            // // Decode PublicKey (compressed or uncompressed) from
            // // the Elliptic-Curve-Point-to-Octet-String encoding
            // // described in SEC 1: Elliptic Curve Cryptography
            // // (Version 2.0) section 2.3.3 (page 10).

            // // <http://www.secg.org/sec1-v2.pdf>
            // let pubkey = p256::PublicKey::from_sec1_bytes(&key_bytes)
            //     .expect("failed to convert from sec1_bytes to public key");
            // Ok(pubkey)
        }
        e => Err(Error::TeeError(e)),
    }
}

pub fn gen_ecc_keypair(slot: u8) -> Result<()> {
    tee_setup();
    let result = unsafe { ffi::gen_ecc_keypair(slot) };
    match result {
        0 => Ok(()),
        e => Err(Error::TeeError(e)),
    }
}

pub fn del_ecc_keypair(slot: u8) -> Result<()> {
    tee_setup();
    let result = unsafe { ffi::del_ecc_keypair(slot) };
    match result {
        0 => Ok(()),
        e => Err(Error::TeeError(e)),
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi;
    use crate::*;
    use sha2::{Digest, Sha256};

    fn teardown() {
        // unsafe { ffi::helium_deinit() };
    }

    #[test]
    fn test_del_ecc_keypair() {
        let pk = del_ecc_keypair(0);
        assert!(pk.is_ok());

        teardown();
    }

    #[test]
    fn test_sign_and_verify() {
        let msg: [u8; 256] = (0..=255)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("failed generate msg");

        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();

        let ret = ecdsa_sign_digest(0, digest.as_slice());
        assert!(ret.is_ok());

        let sig = ret.unwrap();
        let ret = ecdsa_verify(0, digest.as_slice(), &sig);
        assert!(ret.is_ok());
        assert!(ret.unwrap());

        teardown();
    }

    #[test]
    fn test_ecc_public() {
        let pk = publickey(0);
        assert!(pk.is_ok());

        teardown();
    }

    #[test]
    fn test_gen_ecc_keypair() {
        let pk = gen_ecc_keypair(0);
        assert!(pk.is_ok());

        teardown();
    }
}
