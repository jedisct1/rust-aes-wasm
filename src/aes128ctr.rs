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

pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];
pub type IV = [u8; IV_LEN];

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
