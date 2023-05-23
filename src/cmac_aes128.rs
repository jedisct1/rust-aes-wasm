mod zig {
    extern "C" {
        pub fn cmac_aes128(tag: *mut u8, m: *const u8, m_len: usize, k: *const u8) -> i32;
    }
}

pub use crate::*;

pub const KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];
pub type Tag = [u8; TAG_LEN];

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
