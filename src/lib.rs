use core::fmt::{self, Display};

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
pub mod aegis256;
pub mod aes128ctr;
pub mod aes128gcm;
pub mod aes128ocb;
pub mod aes256ctr;
pub mod aes256gcm;
pub mod aes256ocb;
pub mod cmac_aes128;
