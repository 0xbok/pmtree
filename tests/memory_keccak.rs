use hex_literal::hex;
use pmtree::*;
use std::collections::HashMap;
use tiny_keccak::{Hasher as _, Keccak};

pub struct MemoryDB(HashMap<DBKey, Value>);
pub struct MyKeccak(Keccak);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MyFr([u8; 32]);

impl Database for MemoryDB {
    fn new(_dbpath: &str) -> Self {
        MemoryDB(HashMap::new())
    }

    fn load(_dbpath: &str) -> Self {
        panic!("Cannot load in-memory db!")
    }

    fn get(&self, key: DBKey) -> Option<Value> {
        self.0.get(&key).cloned()
    }

    fn put(&mut self, key: DBKey, value: Value) {
        self.0.insert(key, value);
    }
}

impl From<Vec<u8>> for MyFr {
    fn from(v: Vec<u8>) -> Self {
        let v = v.try_into().unwrap();
        MyFr(v)
    }
}

impl From<MyFr> for Vec<u8> {
    fn from(v: MyFr) -> Self {
        v.0.to_vec()
    }
}

impl Hasher for MyKeccak {
    type Fr = MyFr;

    fn default_leaf() -> Self::Fr {
        MyFr([0; 32])
    }

    fn hash(input: &[Self::Fr]) -> Self::Fr {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for element in input {
            hasher.update(&element.0);
        }
        hasher.finalize(&mut output);
        MyFr(output)
    }
}

#[test]
fn insert_delete() {
    let mut mt = MerkleTree::<MemoryDB, MyKeccak>::new(2, "abacaba");

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

    assert_eq!(mt.root(), MyFr(default_tree_root));

    let roots = [
        hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95"),
        hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b"),
        hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c"),
        hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
    ];

    for i in 0..leaves.len() {
        mt.insert(MyFr(leaves[i]));
        assert_eq!(mt.root(), MyFr(roots[i]));
    }

    for i in (0..leaves.len()).rev() {
        mt.delete(i);
    }

    assert_eq!(mt.root(), MyFr(default_tree_root));
}