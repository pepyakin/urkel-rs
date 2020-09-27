use crate::error::{Errno, Error};
use crate::proof::Proof;
use std::{marker::PhantomData, path::Path, ptr};
use urkel_sys as sys;

pub const MAX_VALUE_SIZE: usize = 1024;
pub type Key = [u8; 32];

#[derive(Debug)]
pub struct Database {
    tree: *mut sys::urkel_t,
}

// urkel provides inherent thread-safety
unsafe impl Send for Database {}
unsafe impl Sync for Database {}

impl Database {
    pub fn open(prefix: impl AsRef<Path>) -> Result<Self, Error> {
        let prefix = crate::util::path_into_c_string(prefix.as_ref())?;
        let tree = unsafe { sys::urkel_open(prefix.as_ptr()) };
        if tree.is_null() {
            return Err(Errno::fetch().into_error());
        }
        Ok(Database { tree })
    }

    pub fn destroy(prefix: impl AsRef<Path>) -> Result<(), Error> {
        let prefix = crate::util::path_into_c_string(prefix.as_ref())?;
        let ret = unsafe { sys::urkel_destroy(prefix.as_ptr()) };
        if ret == 0 {
            return Err(Errno::fetch().into_error());
        }
        Ok(())
    }

    pub fn new_tx(&self) -> Result<Transaction, Error> {
        let tx = unsafe { sys::urkel_tx_create(self.tree, ptr::null()) };
        if tx.is_null() {
            return Err(Errno::fetch().into_error());
        }
        Ok(Transaction {
            tx,
            _marker: PhantomData,
        })
    }

    pub fn new_tx_at(&self, root: [u8; 32]) -> Result<Transaction, Error> {
        let tx = unsafe { sys::urkel_tx_create(self.tree, root.as_ptr()) };
        if tx.is_null() {
            return Err(Errno::fetch().into_error());
        }
        Ok(Transaction {
            tx,
            _marker: PhantomData,
        })
    }

    pub fn prove(&self, key: &Key, root: [u8; 32]) -> Result<Proof, Error> {
        let mut proof_raw = ptr::null_mut();
        let mut proof_len = 0usize;
        let ret = unsafe {
            sys::urkel_prove(
                self.tree,
                &mut proof_raw as *mut *mut _,
                &mut proof_len as *mut usize,
                key.as_ptr(),
                root.as_ptr(),
            )
        };
        if ret == 0 {
            // we assume that the buf wasn't allocated.
            debug_assert_eq!(proof_raw, ptr::null_mut());
            return Err(Errno::fetch().into_error());
        }

        let proof = unsafe {
            let proof = Proof::from_ptr(proof_raw, proof_len);
            libc::free(proof_raw as *mut _);
            proof
        };
        Ok(proof)
    }

    /// Returns the root hash of the tree at its current state.
    ///
    /// The root of a freshly created database is all zeroes.
    ///
    /// ```
    /// # use urkel::Database;
    /// # let prefix_dir = tempfile::tempdir().unwrap();
    /// # let prefix = prefix_dir.path().display().to_string();
    /// let db = Database::open(&prefix).unwrap();
    /// assert_eq!(db.root(), [0; 32]);
    /// ```
    pub fn root(&self) -> [u8; 32] {
        let mut root = [0; 32];
        unsafe { sys::urkel_root(self.tree, root.as_mut_ptr()) }
        root
    }

    pub fn iter(&self, at: [u8; 32]) -> Result<Iter, Error> {
        let iter = unsafe { sys::urkel_iterate(self.tree, at.as_ptr()) };
        if iter.is_null() {
            return Err(Errno::fetch().into_error());
        }
        Ok(Iter {
            iter,
            _marker: PhantomData,
        })
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        unsafe {
            sys::urkel_close(self.tree);
        }
    }
}

pub struct Transaction<'a> {
    tx: *mut sys::urkel_tx_t,
    _marker: PhantomData<&'a ()>,
}

unsafe impl Send for Transaction<'_> {}
unsafe impl Sync for Transaction<'_> {}

impl<'a> Transaction<'a> {
    /// Empty tx root is all zeroes.
    pub fn root(&self) -> [u8; 32] {
        let mut root = [0; 32];
        unsafe { sys::urkel_tx_root(self.tx, root.as_mut_ptr()) }
        root
    }

    /// Doesn't support values more than 1024 bytes long.
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge);
        }
        let ret =
            unsafe { sys::urkel_tx_insert(self.tx, key.as_ptr(), value.as_ptr(), value.len()) };
        if ret == 0 {
            return Err(Errno::fetch().into_error());
        }
        Ok(())
    }

    pub fn remove(&self, key: &[u8]) -> Result<(), Error> {
        let ret = unsafe { sys::urkel_tx_remove(self.tx, key.as_ptr()) };
        if ret == 0 {
            return Err(Errno::fetch().into_error());
        }
        Ok(())
    }

    pub fn has(&self, key: &[u8]) -> Result<bool, Error> {
        let ret = unsafe { sys::urkel_tx_has(self.tx, key.as_ptr()) };
        if ret == 1 {
            Ok(true)
        } else {
            let errno = Errno::fetch();
            if errno.is_not_found() {
                Ok(false)
            } else {
                return Err(errno.into_error());
            }
        }
    }

    pub fn prove(&self, key: &[u8]) -> Result<Proof, Error> {
        let mut proof_raw = ptr::null_mut();
        let mut proof_len = 0usize;
        let ret = unsafe {
            sys::urkel_tx_prove(
                self.tx,
                &mut proof_raw as *mut *mut _,
                &mut proof_len as *mut usize,
                key.as_ptr(),
            )
        };
        if ret == 0 {
            // we assume that the buf wasn't allocated.
            debug_assert_eq!(proof_raw, ptr::null_mut());
            return Err(Errno::fetch().into_error());
        }

        let proof = unsafe {
            let proof = Proof::from_ptr(proof_raw, proof_len);
            libc::free(proof_raw as *mut _);
            proof
        };
        Ok(proof)
    }

    pub fn revert(&self, root: [u8; 32]) -> Result<(), Error> {
        let ret = unsafe { sys::urkel_tx_inject(self.tx, root.as_ptr()) };
        if ret == 0 {
            return Err(Errno::fetch().into_error());
        }
        Ok(())
    }

    pub fn commit(&self) -> Result<(), Error> {
        let ret = unsafe { sys::urkel_tx_commit(self.tx) };
        if ret == 0 {
            return Err(Errno::fetch().into_error());
        }
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut value = Vec::with_capacity(MAX_VALUE_SIZE);
        let mut size = 0;
        let ret = unsafe {
            sys::urkel_tx_get(
                self.tx,
                value.as_mut_ptr(),
                &mut size as *mut usize,
                key.as_ptr(),
            )
        };
        if ret == 1 {
            unsafe {
                value.set_len(size);
            }
            Ok(Some(value))
        } else {
            let errno = Errno::fetch();
            if errno.is_not_found() {
                Ok(None)
            } else {
                return Err(errno.into_error());
            }
        }
    }

    pub fn iter(&self) -> Result<Iter, Error> {
        let iter = unsafe { sys::urkel_iter_create(self.tx) };
        if iter.is_null() {
            return Err(Errno::fetch().into_error());
        }
        Ok(Iter {
            iter,
            _marker: PhantomData,
        })
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::urkel_tx_destroy(self.tx);
        }
    }
}

pub struct Iter<'a> {
    iter: *mut sys::urkel_iter_t,
    _marker: PhantomData<&'a mut ()>,
}

unsafe impl Send for Iter<'_> {}
unsafe impl Sync for Iter<'_> {}

impl<'a> Iter<'a> {
    pub fn next(&self) -> Result<Option<(Key, Vec<u8>)>, Error> {
        let mut k = [0; 32];
        let mut v = Vec::with_capacity(MAX_VALUE_SIZE);
        let mut size = 0;
        let ret = unsafe {
            sys::urkel_iter_next(
                self.iter,
                k.as_mut_ptr(),
                v.as_mut_ptr(),
                &mut size as *mut usize,
            )
        };
        if ret == 1 {
            unsafe {
                v.set_len(size);
            }
            return Ok(Some((k, v)));
        }

        let errno = Errno::fetch();
        if errno.is_iter_end() {
            return Ok(None);
        } else {
            return Err(errno.into_error());
        }
    }
}

impl<'a> Drop for Iter<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::urkel_iter_destroy(self.iter);
        }
    }
}
