//! CMAC-AES-128 message authentication code for WASI (WebAssembly System Interface).
//!
//! Provides message authentication using AES-128 as a MAC (Cipher-based Message Authentication Code).
//!
//! ## Example
//! ```rust
//! use aes_wasm::cmac_aes128::{mac, Key};
//! let key = Key::default();
//! let msg = b"hello";
//! let tag = mac(msg, &key);
//! ```

mod zig {
    extern "C" {
        pub fn cmac_aes128(tag: *mut u8, m: *const u8, m_len: usize, k: *const u8) -> i32;
    }
}

pub use crate::*;

/// The length of the key in bytes.
///
/// This constant is used for key array sizing.
pub const KEY_LEN: usize = 16;
/// The length of the authentication tag in bytes.
///
/// This constant is used for tag array sizing.
pub const TAG_LEN: usize = 16;

/// Key type for CMAC-AES128 (16 bytes).
pub type Key = [u8; KEY_LEN];
/// Tag type for CMAC-AES128 (16 bytes).
pub type Tag = [u8; TAG_LEN];

/// Computes the CMAC (Cipher-based Message Authentication Code) for a message using AES-128.
///
/// # Arguments
/// * `msg` - The message to authenticate.
/// * `key` - Reference to the secret key.
///
/// # Returns
/// Authentication tag as a 16-byte array.
///
/// # Example
/// ```
/// use aes_wasm::cmac_aes128::{mac, Key};
/// let key = Key::default();
/// let msg = b"hello";
/// let tag = mac(msg, &key);
/// ```
pub fn mac(msg: impl AsRef<[u8]>, key: &Key) -> Tag {
    let msg = msg.as_ref();
    let mut tag = Tag::default();
    unsafe {
        zig::cmac_aes128(tag.as_mut_ptr(), msg.as_ptr(), msg.len(), key.as_ptr());
    };
    tag
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cmac_aes128() {
        let key = Key::default();
        let msg = b"hello world";
        _ = mac(msg, &key);
    }
}
