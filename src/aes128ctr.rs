//! AES-128-CTR stream cipher for WASI (WebAssembly System Interface).
//!
//! Provides encryption and decryption using AES-128 in CTR mode.
//!
//! ## Example
//! ```rust
//! use aes_wasm::aes128ctr::{encrypt, decrypt, Key, IV};
//! let key = Key::default();
//! let iv = IV::default();
//! let msg = b"hello";
//! let ciphertext = encrypt(msg, &key, iv);
//! let plaintext = decrypt(ciphertext, &key, iv);
//! assert_eq!(plaintext, msg);
//! ```

mod zig {
    extern "C" {
        pub fn aes128ctr(
            c: *mut u8,
            c_len: usize,
            m: *const u8,
            m_len: usize,
            iv: *const u8,
            k: *const u8,
        ) -> i32;
    }
}

pub use crate::*;

/// The length of the key in bytes.
///
/// This constant is used for key array sizing.
pub const KEY_LEN: usize = 16;
/// The length of the IV in bytes.
///
/// This constant is used for IV array sizing.
pub const IV_LEN: usize = 16;

/// Key type for AES-128-CTR (16 bytes).
pub type Key = [u8; KEY_LEN];
/// IV type for AES-128-CTR (16 bytes).
pub type IV = [u8; IV_LEN];

/// Encrypts a message using AES-128 in CTR mode.
///
/// # Arguments
/// * `msg` - The plaintext message to encrypt.
/// * `key` - Reference to the secret key.
/// * `iv` - Initialization vector.
///
/// # Returns
/// Ciphertext as a `Vec<u8>`.
///
/// # Example
/// ```
/// use aes_wasm::aes128ctr::{encrypt, Key, IV};
/// let key = Key::default();
/// let iv = IV::default();
/// let msg = b"hello";
/// let ciphertext = encrypt(msg, &key, iv);
/// ```
pub fn encrypt(msg: impl AsRef<[u8]>, key: &Key, iv: IV) -> Vec<u8> {
    let msg = msg.as_ref();
    let ciphertext_len = msg.len();
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    unsafe {
        zig::aes128ctr(
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            msg.as_ptr(),
            msg.len(),
            iv.as_ptr(),
            key.as_ptr(),
        );
        ciphertext.set_len(ciphertext_len);
    };
    ciphertext
}

/// Decrypts a ciphertext using AES-128 in CTR mode.
///
/// # Arguments
/// * `ciphertext` - The ciphertext to decrypt.
/// * `key` - Reference to the secret key.
/// * `iv` - Initialization vector.
///
/// # Returns
/// Plaintext as a `Vec<u8>`.
///
/// # Example
/// ```
/// use aes_wasm::aes128ctr::{encrypt, decrypt, Key, IV};
/// let key = Key::default();
/// let iv = IV::default();
/// let msg = b"hello";
/// let ciphertext = encrypt(msg, &key, iv);
/// let plaintext = decrypt(ciphertext, &key, iv);
/// ```
pub fn decrypt(ciphertext: impl AsRef<[u8]>, key: &Key, iv: IV) -> Vec<u8> {
    encrypt(ciphertext, key, iv)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes128ctr() {
        let key = Key::default();
        let iv = IV::default();
        let msg = b"hello world";
        let ciphertext = encrypt(msg, &key, iv);
        let plaintext = decrypt(ciphertext, &key, iv);
        assert_eq!(plaintext, msg);
    }
}
