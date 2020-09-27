use crate::error::Errno;
use crate::{Key, MAX_VALUE_SIZE};
use urkel_sys as sys;

#[derive(Debug)]
pub struct Proof {
    raw: Vec<u8>,
}

impl Proof {
    pub(crate) unsafe fn from_ptr(proof_raw: *mut u8, proof_len: usize) -> Self {
        let raw = std::slice::from_raw_parts(proof_raw, proof_len);
        Self { raw: raw.to_vec() }
    }

    pub fn new_unchecked(raw: Vec<u8>) -> Proof {
        Proof { raw }
    }

    pub fn verify(&self, key: &Key, root: [u8; 32]) -> Result<Option<Vec<u8>>, VerifyError> {
        let mut exists = 0;
        let mut v = Vec::with_capacity(MAX_VALUE_SIZE);
        let mut v_len = 0usize;

        let ret = unsafe {
            sys::urkel_verify(
                &mut exists as *mut _,
                v.as_mut_ptr(),
                &mut v_len as *mut usize,
                self.raw.as_ptr(),
                self.raw.len(),
                key.as_ptr(),
                root.as_ptr(),
            )
        };
        if ret == 0 {
            return Err(VerifyError::from_errno());
        }

        Ok(if exists == 1 {
            unsafe {
                v.set_len(v_len);
            }
            Some(v)
        } else {
            None
        })
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.raw
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Computed hash did not match expected hash")]
    HashMismatch,
    #[error("Expected different key")]
    SameKey,
    #[error("Expected different prefix bits")]
    SamePath,
    #[error("Depth went negative")]
    NegativeDepth,
    #[error("Prefix bits do not match key")]
    PathMismatch,
    #[error("Depth is not satisfied by proof nodes")]
    TooDeep,
    #[error("The proof is invalid")]
    InvalidProof,
    #[error("Unknown error occured")]
    Unknown,
}

impl VerifyError {
    fn from_errno() -> VerifyError {
        match Errno::fetch().into_raw() {
            sys::URKEL_EHASHMISMATCH => VerifyError::HashMismatch,
            sys::URKEL_ESAMEKEY => VerifyError::SameKey,
            sys::URKEL_ESAMEPATH => VerifyError::SamePath,
            sys::URKEL_ENEGDEPTH => VerifyError::NegativeDepth,
            sys::URKEL_EPATHMISMATCH => VerifyError::PathMismatch,
            sys::URKEL_ETOODEEP => VerifyError::TooDeep,
            sys::URKEL_EINVAL => VerifyError::InvalidProof,
            err => {
                debug_assert!(false, "{} is not known", err);
                VerifyError::Unknown
            },
        }
    }
}
