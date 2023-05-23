mod zig {
    extern "C" {
        pub fn aes128ocb_encrypt(
            c: *mut u8,
            c_len: usize,
            tag: *mut u8,
            m: *const u8,
            m_len: usize,
            ad: *const u8,
            ad_len: usize,
            nonce: *const u8,
            k: *const u8,
        ) -> i32;

        pub fn aes128ocb_decrypt(
            m: *mut u8,
            m_len: usize,
            c: *const u8,
            c_len: usize,
            tag: *const u8,
            ad: *const u8,
            ad_len: usize,
            nonce: *const u8,
            k: *const u8,
        ) -> i32;
    }
}

pub use crate::*;

pub const KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub type Key = [u8; KEY_LEN];
pub type Tag = [u8; TAG_LEN];
pub type Nonce = [u8; NONCE_LEN];

pub fn encrypt_detached(
    msg: impl AsRef<[u8]>,
    ad: impl AsRef<[u8]>,
    key: &Key,
    nonce: Nonce,
) -> (Vec<u8>, Tag) {
    let msg = msg.as_ref();
    let ad = ad.as_ref();
    let ciphertext_len = msg.len();
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    let mut tag = Tag::default();
    unsafe {
        zig::aes128ocb_encrypt(
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            tag.as_mut_ptr(),
            msg.as_ptr(),
            msg.len(),
            ad.as_ptr(),
            ad.len(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
        ciphertext.set_len(ciphertext_len);
    };
    (ciphertext, tag)
}

pub fn encrypt(msg: impl AsRef<[u8]>, ad: impl AsRef<[u8]>, key: &Key, nonce: Nonce) -> Vec<u8> {
    let mut res = encrypt_detached(msg, ad, key, nonce);
    res.0.extend_from_slice(res.1.as_ref());
    res.0
}

pub fn decrypt_detached(
    ciphertext: impl AsRef<[u8]>,
    tag: &Tag,
    ad: impl AsRef<[u8]>,
    key: &Key,
    nonce: Nonce,
) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    let ad = ad.as_ref();
    let msg_len = ciphertext.len();
    let mut msg = Vec::with_capacity(msg_len);
    unsafe {
        let res = zig::aes128ocb_decrypt(
            msg.as_mut_ptr(),
            msg_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
        if res != 0 {
            return Err(Error::VerificationFailed);
        }
        msg.set_len(msg_len);
    };
    Ok(msg)
}

pub fn decrypt(
    ciphertext_and_tag: impl AsRef<[u8]>,
    ad: impl AsRef<[u8]>,
    key: &Key,
    nonce: Nonce,
) -> Result<Vec<u8>, Error> {
    let ciphertext_and_tag = ciphertext_and_tag.as_ref();
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(Error::VerificationFailed);
    }
    let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - TAG_LEN];
    let tag = &ciphertext_and_tag[ciphertext_and_tag.len() - TAG_LEN..];
    decrypt_detached(ciphertext, tag.try_into().unwrap(), ad, key, nonce)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes128ocb() {
        let key = Key::default();
        let nonce = Nonce::default();
        let msg = b"hello world";
        let ad = b"additional data";
        let (ciphertext, tag) = encrypt_detached(msg, ad, &key, nonce);
        let plaintext = decrypt_detached(ciphertext, &tag, ad, &key, nonce).unwrap();
        assert_eq!(plaintext, msg);
        let ciphertext_and_tag = encrypt(msg, ad, &key, nonce);
        let plaintext = decrypt(ciphertext_and_tag, ad, &key, nonce).unwrap();
        assert_eq!(plaintext, msg);
    }
}
