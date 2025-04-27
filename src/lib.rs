//! # aes-wasm
//!
//! High-performance AEAD, stream cipher, and MAC primitives for WebAssembly/WASI.
//!
//! This crate provides a simple, dependency-free API for cryptography in WASI environments.
//!
//! ## Example: AES-128-GCM
//! ```rust
//! use aes_wasm::aes128gcm::{encrypt, decrypt, Key, Nonce};
//! let key = Key::default();
//! let nonce = Nonce::default();
//! let msg = b"hello world";
//! let ad = b"extra data";
//! let ciphertext = encrypt(msg, ad, &key, nonce);
//! let plaintext = decrypt(ciphertext, ad, &key, nonce).unwrap();
//! assert_eq!(plaintext, msg);
//! ```
//!
//! AEAD ciphers for WebAssembly, including AEGIS, AES-GCM, AES-OCB, AES-CBC, AES-CTR, and CMAC.
//!
//! This crate provides high-performance AEAD and MAC primitives for use in WebAssembly environments.
//! It exposes a simple API for encryption, decryption, and authentication using modern ciphers.
//!
//! # Example
//! ```
//! use aes_wasm::aes128gcm::{encrypt, decrypt, Key, Nonce};
//! let key = Key::default();
//! let nonce = Nonce::default();
//! let msg = b"hello";
//! let ad = b"ad";
//! let ciphertext = encrypt(msg, ad, &key, nonce);
//! let plaintext = decrypt(ciphertext, ad, &key, nonce).unwrap();
//! assert_eq!(plaintext, msg);
//! ```

use core::fmt::{self, Display};

/// Error type for AEAD operations.
///
/// This error is returned when authentication fails during decryption.
///
/// # Example
/// ```
/// use aes_wasm::aes128gcm::{decrypt, Key, Nonce};
/// use aes_wasm::Error;
/// let key = Key::default();
/// let nonce = Nonce::default();
/// let ad = b"ad";
/// // Intentionally use invalid ciphertext
/// let ciphertext = b"invalid";
/// let result = decrypt(ciphertext, ad, &key, nonce);
/// assert_eq!(result, Err(Error::VerificationFailed));
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Ciphertext verification failed.
    VerificationFailed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

pub mod aegis128l;
pub mod aegis128x2;
pub mod aegis128x4;
pub mod aegis256;
pub mod aegis256x2;
pub mod aegis256x4;
pub mod aes128cbc;
pub mod aes128ctr;
pub mod aes128gcm;
pub mod aes128ocb;
pub mod aes256cbc;
pub mod aes256ctr;
pub mod aes256gcm;
pub mod aes256ocb;
pub mod cmac_aes128;
