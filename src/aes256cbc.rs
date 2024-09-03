mod zig {
    extern "C" {
        pub fn aes256cbc_encrypt(
            c: *mut u8,
            c_len: usize,
            m: *const u8,
            m_len: usize,
            iv: *const u8,
            k: *const u8,
        ) -> i32;

        pub fn aes256cbc_decrypt(
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

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const IV_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];
pub type Tag = [u8; TAG_LEN];
pub type IV = [u8; IV_LEN];

pub fn encrypt(msg: impl AsRef<[u8]>, key: &Key, iv: IV) -> Vec<u8> {
    let msg = msg.as_ref();
    let ciphertext_len = (msg.len() + 16) & !15;
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    unsafe {
        zig::aes256cbc_encrypt(
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

pub fn decrypt(ciphertext: impl AsRef<[u8]>, key: &Key, iv: IV) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    let msg_max_len = ciphertext
        .len()
        .checked_sub(1)
        .ok_or(Error::VerificationFailed)?;
    let mut msg: Vec<u8> = Vec::with_capacity(msg_max_len);
    unsafe {
        let res = zig::aes256cbc_decrypt(
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
    fn aes256cbc() {
        let key = Key::default();
        let iv = IV::default();
        let msg = b"Hello world";
        let ciphertext = encrypt(msg, &key, iv);
        let plaintext = decrypt(ciphertext, &key, iv).unwrap();
        assert_eq!(plaintext, msg);
    }
}
