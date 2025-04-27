mod zig {
    extern "C" {
        pub fn aes128cbc_encrypt(
            c: *mut u8,
            c_len: usize,
            m: *const u8,
            m_len: usize,
            iv: *const u8,
            k: *const u8,
        ) -> i32;

        pub fn aes128cbc_decrypt(
            m: *mut u8,
            m_len: usize,
            c: *const u8,
            c_len: usize,
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
/// The length of the authentication tag in bytes (not used for authentication, but for block size).
///
/// This constant is used for tag array sizing.
pub const TAG_LEN: usize = 16;
/// The length of the IV in bytes.
///
/// This constant is used for IV array sizing.
pub const IV_LEN: usize = 16;

/// Key type for AES-128-CBC (16 bytes).
pub type Key = [u8; KEY_LEN];
/// Tag type for AES-128-CBC (16 bytes, block size).
pub type Tag = [u8; TAG_LEN];
/// IV type for AES-128-CBC (16 bytes).
pub type IV = [u8; IV_LEN];

/// Encrypts a message using AES-128 in CBC mode.
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
/// use aes_wasm::aes128cbc::{encrypt, Key, IV};
/// let key = Key::default();
/// let iv = IV::default();
/// let msg = b"hello";
/// let ciphertext = encrypt(msg, &key, iv);
/// ```
pub fn encrypt(msg: impl AsRef<[u8]>, key: &Key, iv: IV) -> Vec<u8> {
    let msg = msg.as_ref();
    let ciphertext_len = (msg.len() + 16) & !15;
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    unsafe {
        zig::aes128cbc_encrypt(
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

/// Decrypts a ciphertext using AES-128 in CBC mode.
///
/// # Arguments
/// * `ciphertext` - The ciphertext to decrypt.
/// * `key` - Reference to the secret key.
/// * `iv` - Initialization vector.
///
/// # Returns
/// `Ok(plaintext)` if decryption succeeds, or `Err(Error)` if it fails.
///
/// # Example
/// ```
/// use aes_wasm::aes128cbc::{encrypt, decrypt, Key, IV};
/// let key = Key::default();
/// let iv = IV::default();
/// let msg = b"hello";
/// let ciphertext = encrypt(msg, &key, iv);
/// let plaintext = decrypt(ciphertext, &key, iv).unwrap();
/// ```
pub fn decrypt(ciphertext: impl AsRef<[u8]>, key: &Key, iv: IV) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    let msg_max_len = ciphertext
        .len()
        .checked_sub(1)
        .ok_or(Error::VerificationFailed)?;
    let mut msg: Vec<u8> = Vec::with_capacity(msg_max_len);
    unsafe {
        let res = zig::aes128cbc_decrypt(
            msg.as_mut_ptr(),
            msg_max_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
            iv.as_ptr(),
            key.as_ptr(),
        );
        if res < 0 {
            return Err(Error::VerificationFailed);
        }
        let msg_len = res as usize;
        msg.set_len(msg_len);
    };
    Ok(msg)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes128cbc() {
        let key = Key::default();
        let iv = IV::default();
        let msg = b"Hello world";
        let ciphertext = encrypt(msg, &key, iv);
        let plaintext = decrypt(ciphertext, &key, iv).unwrap();
        assert_eq!(plaintext, msg);
    }
}
