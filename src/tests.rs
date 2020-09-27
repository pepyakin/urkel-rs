use crate::{Database, Proof, VerifyError};
use assert_matches::assert_matches;
use hex_literal::hex;
use std::fs::File;
use tempfile::{tempdir, TempDir};

type AnyErr = Box<dyn std::error::Error>;

struct TmpDatabase {
    db: Database,
    prefix_dir: TempDir,
}

impl TmpDatabase {
    fn new() -> Result<Self, AnyErr> {
        let prefix_dir = tempdir()?;
        let db = Database::open(prefix_dir.path().display().to_string())?;
        Ok(Self { db, prefix_dir })
    }

    fn reopen(self) -> Result<Self, AnyErr> {
        let TmpDatabase { prefix_dir, db } = self;
        drop(db);

        let db = Database::open(prefix_dir.path().display().to_string())?;
        Ok(Self { prefix_dir, db })
    }
}

#[test]
fn smoke() -> Result<(), AnyErr> {
    let _tmp_db = TmpDatabase::new()?;
    Ok(())
}

#[test]
fn blake2() {
    fn blake2_ref(data: &[u8]) -> [u8; 32] {
        let mut r = [0; 32];
        r.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
        r
    }

    for data in &[&b""[..], &b"hello_world"[..], &[1, 2, 3]] {
        assert_eq!(crate::util::blake2b_256(data), blake2_ref(data));
    }
}

#[test]
fn open_err_handle() -> Result<(), AnyErr> {
    // create a temp _file_
    let tmp_dir = tempdir()?;
    let file_path = tmp_dir.path().join("mock");
    let _ = File::create(&file_path)?;

    // a database cannot be opened at a file
    let _ = Database::open(file_path).unwrap_err();
    Ok(())
}

#[test]
fn destroy_existing() -> Result<(), AnyErr> {
    let TmpDatabase { prefix_dir, db } = TmpDatabase::new()?;
    {
        let tx = db.new_tx()?;
        let key = [1; 1024 * 1024];
        tx.insert(&key, b"hello")?;
        tx.commit()?;
    }
    drop(db);

    Database::destroy(prefix_dir.path())?;

    Ok(())
}

#[test]
fn destroy_non_existent() -> Result<(), AnyErr> {
    let tmp_dir = tempdir()?;
    Database::destroy(tmp_dir.path())?;
    Ok(())
}

#[test]
fn mk_empty_tx() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let _tx = tmp_db.db.new_tx()?;
    Ok(())
}

#[test]
fn mk_two_empty_tx() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let _tx1 = tmp_db.db.new_tx()?;
    let _tx2 = tmp_db.db.new_tx()?;
    Ok(())
}

#[test]
fn mk_empty_tx_root() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    assert_eq!(tx.root(), [0; 32]);
    Ok(())
}

#[test]
fn mk_tx_bogus_root() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    assert!(matches!(
        tmp_db.db.new_tx_at([3; 32]),
        Err(crate::Error::NotFound)
    ));
    Ok(())
}

#[test]
fn tx_insert_key_too_large() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    let key = [1; 1024 * 1024];
    tx.insert(&key, b"hello")?;
    tx.commit()?;
    assert!(tx.has(&key)?);
    Ok(())
}

#[test]
fn tx_insert_value_too_large() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    assert_matches!(
        tx.insert(&[1; 31], &[0u8; 1025]),
        Err(crate::Error::ValueTooLarge)
    );
    Ok(())
}

#[test]
fn tx_insert() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    tx.insert(&[1; 32], b"hello")?;
    assert!(tx.has(&[1; 32])?);
    assert_eq!(
        tx.root(),
        hex!("58f8fd75fe4ebe990b2e84e497932ae7c4e29c841035a6fa9b6879d44902d73a")
    );
    Ok(())
}

#[test]
fn tx_insert_has_no_effect_without_commit() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;
    {
        let tx = tmp_db.db.new_tx()?;
        tx.insert(&[1; 32], b"hello")?;
        drop(tx);
    }

    {
        let tx = tmp_db.db.new_tx()?;
        assert!(!tx.has(&[1; 32])?);
    }

    Ok(())
}

#[test]
fn tx_is_isolated() -> Result<(), AnyErr> {
    let tmp_db = TmpDatabase::new()?;

    let key1 = [1; 32];
    let key2 = [2; 32];

    let tx1 = tmp_db.db.new_tx()?;
    tx1.insert(&key1, b"hello")?;
    assert!(tx1.has(&key1)?);

    let tx2 = tmp_db.db.new_tx()?;
    tx2.insert(&key2, b"hello")?;
    assert!(!tx2.has(&key1)?);
    assert!(tx2.has(&key2)?);

    tx1.commit()?;
    assert!(!tx2.has(&key1)?);

    Ok(())
}

#[test]
fn tx_insert_reopen() -> Result<(), AnyErr> {
    let mut tmp_db = TmpDatabase::new()?;
    {
        let tx = tmp_db.db.new_tx()?;
        tx.insert(&[1; 32], b"hello")?;
        tx.commit()?;
    }

    tmp_db = tmp_db.reopen()?;
    {
        let tx = tmp_db.db.new_tx()?;
        assert!(tx.has(&[1; 32])?);
        assert_eq!(
            tx.root(),
            hex!("58f8fd75fe4ebe990b2e84e497932ae7c4e29c841035a6fa9b6879d44902d73a")
        );
    }

    Ok(())
}

#[test]
fn tx_iter() -> Result<(), AnyErr> {
    let key1 = [1; 32];
    let key2 = [2; 32];

    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    tx.insert(&key1, b"hello")?;
    tx.insert(&key2, b"world")?;

    let iter = tx.iter()?;
    assert_eq!(iter.next()?, Some((key1.clone(), b"hello".to_vec())));
    assert_eq!(iter.next()?, Some((key2.clone(), b"world".to_vec())));
    assert_eq!(iter.next()?, None);

    Ok(())
}

#[test]
fn proof_of_existence() -> Result<(), AnyErr> {
    let key = [1; 32];

    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;
    tx.insert(&key, b"hello")?;
    let proof = tx.prove(&key)?;
    let root = tx.root();

    let ok = proof.verify(&key, root)?;
    assert_eq!(ok, Some(b"hello".to_vec()));

    Ok(())
}

#[test]
fn proof_of_non_existence() -> Result<(), AnyErr> {
    let key = [2; 32];

    let tmp_db = TmpDatabase::new()?;
    let tx = tmp_db.db.new_tx()?;

    let proof = tx.prove(&key)?;
    let root = tx.root();

    let ok = proof.verify(&key, root)?;
    assert_eq!(ok, None);

    Ok(())
}

#[test]
fn bogus_proofs() -> Result<(), AnyErr> {
    let key1 = [1; 32];
    let key2 = [2; 32];

    let tmp_db = TmpDatabase::new()?;

    let tx = tmp_db.db.new_tx()?;
    tx.insert(&key1, b"hello")?;
    let proof = tx.prove(&key1)?;
    let root = tx.root();

    assert_matches!(proof.verify(&key2, root), Err(VerifyError::HashMismatch));

    let proof = Proof::new_unchecked(b"bogus".to_vec());
    assert_matches!(proof.verify(&key1, root), Err(VerifyError::InvalidProof));

    let bogus_root = [3; 32];
    assert_matches!(tmp_db.db.prove(&key1, bogus_root), Err(_));

    Ok(())
}
