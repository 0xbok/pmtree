use async_trait::async_trait;
use hex_literal::hex;
use pmtree::*;
use std::collections::HashMap;
use std::fs;
use tiny_keccak::{Hasher as _, Keccak};

struct MyKeccak(Keccak);
struct MySled(sled::Db);

#[derive(Default)]
struct SledConfig {
    path: String,
}

#[async_trait]
impl Database for MySled {
    type Config = SledConfig;
    type PreImage = ();

    async fn new(db_config: SledConfig) -> PmtreeResult<Self> {
        let db = sled::open(db_config.path).unwrap();
        if db.was_recovered() {
            return Err(PmtreeErrorKind::DatabaseError(
                DatabaseErrorKind::DatabaseExists,
            ));
        }

        Ok(MySled(db))
    }

    async fn load(db_config: SledConfig) -> PmtreeResult<Self> {
        let db = sled::open(&db_config.path).unwrap();

        if !db.was_recovered() {
            fs::remove_dir_all(&db_config.path).expect("Error removing db");
            return Err(PmtreeErrorKind::DatabaseError(
                DatabaseErrorKind::CannotLoadDatabase,
            ));
        }

        Ok(MySled(db))
    }

    async fn get(&self, key: DBKey) -> PmtreeResult<Option<Value>> {
        Ok(self.0.get(key).unwrap().map(|val| val.to_vec()))
    }

    async fn get_pre_image(&self, _key: DBKey) -> PmtreeResult<Option<Self::PreImage>> {
        Err(PmtreeErrorKind::TreeError(
            TreeErrorKind::PreImageNotSupported,
        ))
    }

    async fn put_with_pre_image(
        &mut self,
        key: DBKey,
        value: Value,
        _pre_image: Option<Self::PreImage>,
    ) -> PmtreeResult<()> {
        self.put(key, value).await
    }

    async fn put(&mut self, key: DBKey, value: Value) -> PmtreeResult<()> {
        self.0.insert(key, value).unwrap();

        self.0.flush().unwrap();

        Ok(())
    }

    async fn put_batch(&mut self, subtree: HashMap<DBKey, Value>) -> PmtreeResult<()> {
        let mut batch = sled::Batch::default();

        for (key, value) in subtree {
            batch.insert(&key, value);
        }

        self.0.apply_batch(batch).unwrap();

        Ok(())
    }
}

impl Hasher for MyKeccak {
    type Fr = [u8; 32];

    fn default_leaf() -> Self::Fr {
        [0; 32]
    }

    fn serialize(value: Self::Fr) -> Value {
        value.to_vec()
    }

    fn deserialize(value: Value) -> Self::Fr {
        value.to_vec().try_into().unwrap()
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for element in input {
            hasher.update(element);
        }
        hasher.finalize(&mut output);
        output
    }
}

#[tokio::test]
async fn insert_delete() -> PmtreeResult<()> {
    let mut mt = MerkleTree::<MySled, MyKeccak>::new(
        2,
        SledConfig {
            path: String::from("abacabas"),
        },
    )
    .await?;

    assert_eq!(mt.capacity(), 4);
    assert_eq!(mt.depth(), 2);

    let leaves = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ];

    let default_tree_root =
        hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30");

    assert_eq!(mt.root(), default_tree_root);

    let roots = [
        hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95"),
        hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b"),
        hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c"),
        hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
    ];

    for i in 0..leaves.len() {
        mt.update_next(leaves[i], None).await?;
        assert_eq!(mt.root(), roots[i]);
    }

    for (i, &leaf) in leaves.iter().enumerate() {
        let x = &mt.proof(i).await?;
        assert!(mt.verify(&leaf, x));
    }

    for i in (0..leaves.len()).rev() {
        mt.delete(i).await?;
    }

    assert_eq!(mt.root(), default_tree_root);

    assert!(mt.update_next(leaves[0], None).await.is_err());

    fs::remove_dir_all("abacabas").expect("Error removing db");

    Ok(())
}

#[tokio::test]
async fn batch_insertions() -> PmtreeResult<()> {
    let mut mt = MerkleTree::<MySled, MyKeccak>::new(
        2,
        SledConfig {
            path: String::from("abacabasa"),
        },
    )
    .await?;

    let leaves = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        hex!("0000000000000000000000000000000000000000000000000000000000000004"),
    ];

    mt.batch_insert(None, &leaves).await?;

    assert_eq!(
        mt.root(),
        hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
    );

    drop(mt);
    let mt = MerkleTree::<MySled, MyKeccak>::load(SledConfig {
        path: String::from("abacabasa"),
    })
    .await?;

    assert_eq!(
        mt.root(),
        hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
    );

    fs::remove_dir_all("abacabasa").expect("Error removing db");
    Ok(())
}

#[tokio::test]
async fn set_range() -> PmtreeResult<()> {
    let mut mt = MerkleTree::<MySled, MyKeccak>::new(
        2,
        SledConfig {
            path: String::from("abacabasab"),
        },
    )
    .await?;

    let leaves = [
        hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        hex!("0000000000000000000000000000000000000000000000000000000000000002"),
    ];

    mt.set_range(2, leaves).await?;

    assert_eq!(
        mt.root(),
        hex!("1e9f6c8d3fd5b7ae3a29792adb094c6d4cc6149d0c81c8c8e57cf06c161a92b8")
    );

    fs::remove_dir_all("abacabasab").expect("Error removing db");

    Ok(())
}
