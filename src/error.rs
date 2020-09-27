#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("a path is incorrect")]
    PathErr,
    #[error("the value is larger than supported")]
    ValueTooLarge,
    #[error("given value is not found")]
    NotFound,
    #[error("unknown error happened")]
    Unknown,
}

impl Error {}

pub(crate) struct Errno(u32);

impl Errno {
    pub fn fetch() -> Self {
        let errno = unsafe { *urkel_sys::__urkel_get_errno() };
        Errno(errno as u32)
    }

    pub fn is_not_found(&self) -> bool {
        self.0 == urkel_sys::URKEL_ENOTFOUND
    }

    pub fn is_iter_end(&self) -> bool {
        self.0 == urkel_sys::URKEL_EITEREND
    }

    pub fn into_error(self) -> Error {
        match self.0 {
            urkel_sys::URKEL_ENOTFOUND => Error::NotFound,
            err => {
                dbg!(err);
                // TODO:
                Error::Unknown
            }
        }
    }

    pub fn into_raw(self) -> u32 {
        self.0
    }
}
