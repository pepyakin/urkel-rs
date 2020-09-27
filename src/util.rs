use crate::Error;
use std::ffi::CString;
use std::path::Path;

/// Convert a `Path` into a `CString`.
pub(crate) fn path_into_c_string(path: &Path) -> Result<CString, Error> {
    let os_string = path.as_os_str().to_os_string();

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            use std::os::unix::prelude::*;
            CString::new(os_string.as_bytes()).map_err(|_| Error::PathErr)
        } else {
            std::compile_error!("not supported platform");
        }
    }
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    unsafe {
        urkel_sys::urkel_hash(out.as_mut_ptr(), data.as_ptr() as *const _, data.len());
    }
    out
}
