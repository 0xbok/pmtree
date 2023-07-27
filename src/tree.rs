use crate::*;

use async_recursion::async_recursion;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// db[DEPTH_KEY] = depth
const DEPTH_KEY: DBKey = (u64::MAX - 1).to_be_bytes();

// db[NEXT_INDEX_KEY] = next_index;
const NEXT_INDEX_KEY: DBKey = u64::MAX.to_be_bytes();

// Denotes keys (depth, index) in Merkle Tree. Can be converted to DBKey
// TODO! Think about using hashing for that
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(pub usize, pub usize);
impl From<Key> for DBKey {
    fn from(key: Key) -> Self {
        let cantor_pairing = ((key.0 + key.1) * (key.0 + key.1 + 1) / 2 + key.1) as u64;
        cantor_pairing.to_be_bytes()
    }
}

impl From<DBKey> for Key {
    fn from(db_key: DBKey) -> Self {
        let z = usize::from_be_bytes(db_key);

        let w = ((8.0 * (z as f64) + 1.0).sqrt() - 1.0) / 2.0;
        let w = w.floor() as usize;
        let t = w * (w + 1) / 2;
        let y = z - t;
        let x = w - y;

        Key(x, y)
    }
}

/// The Merkle Tree structure
pub struct MerkleTree<D, H>
where
    D: Database,
    H: Hasher,
{
    db: D,
    depth: usize,
    next_index: usize,
    cache: Vec<H::Fr>,
    root: H::Fr,
}

/// The Merkle proof structure
#[derive(Clone, PartialEq, Eq)]
pub struct MerkleProof<H: Hasher>(pub Vec<(H::Fr, u8)>);

impl<D, H> MerkleTree<D, H>
where
    D: Database,
    H: Hasher,
{
    /// Creates new `MerkleTree` and store it to the specified path/db
    pub async fn new(depth: usize, db_config: D::Config) -> PmtreeResult<Self> {
        // Create new db instance
        let mut db = D::new(db_config).await?;

        // Insert depth val into db
        let depth_val = depth.to_be_bytes().to_vec();
        db.put(DEPTH_KEY, depth_val).await?;

        // Insert next_index val into db
        let next_index = 0usize;
        let next_index_val = next_index.to_be_bytes().to_vec();
        db.put(NEXT_INDEX_KEY, next_index_val).await?;

        // Cache nodes
        let mut cache = vec![H::default_leaf(); depth + 1];

        // Initialize one branch of the `Merkle Tree` from bottom to top
        cache[depth] = H::default_leaf();
        db.put(Key(depth, 0).into(), H::serialize(cache[depth]))
            .await?;
        for i in (0..depth).rev() {
            cache[i] = H::hash(&[cache[i + 1], cache[i + 1]]);
            db.put(Key(i, 0).into(), H::serialize(cache[i])).await?;
        }

        let root = cache[0];

        Ok(Self {
            db,
            depth,
            next_index,
            cache,
            root,
        })
    }

    /// Loads existing Merkle Tree from the specified path/db
    pub async fn load(db_config: D::Config) -> PmtreeResult<Self> {
        // assumes v.len() <= 8
        fn to_8_be_bytes(v: Vec<u8>) -> [u8; 8] {
            let mut array: [u8; 8] = [0; 8];
            let src_len = v.len();
            array[8 - src_len..].copy_from_slice(&v);
            array
        }
        // Load existing db instance
        let db = D::load(db_config).await?;

        // Load root
        let root = H::deserialize(db.get(Key(0, 0).into()).await?.unwrap());

        // Load depth & next_index values from db
        let depth = to_8_be_bytes(db.get(DEPTH_KEY).await?.unwrap());
        let depth = usize::from_be_bytes(depth);

        let next_index = to_8_be_bytes(db.get(NEXT_INDEX_KEY).await?.unwrap());
        let next_index = usize::from_be_bytes(next_index);

        // Load cache vec
        let mut cache = vec![H::default_leaf(); depth + 1];
        cache[depth] = H::default_leaf();
        for i in (0..depth).rev() {
            cache[i] = H::hash(&[cache[i + 1], cache[i + 1]]);
        }

        Ok(Self {
            db,
            depth,
            next_index,
            cache,
            root,
        })
    }

    /// Sets a leaf at the specified tree index
    pub async fn set(
        &mut self,
        key: usize,
        leaf: H::Fr,
        pre_image: Option<D::PreImage>,
    ) -> PmtreeResult<()> {
        if key >= self.capacity() {
            return Err(PmtreeErrorKind::TreeError(TreeErrorKind::IndexOutOfBounds));
        }

        self.db
            .put_with_pre_image(Key(self.depth, key).into(), H::serialize(leaf), pre_image)
            .await?;
        self.recalculate_from(key).await?;

        // Update next_index in memory
        self.next_index = max(self.next_index, key + 1);

        // Update next_index in db
        let next_index_val = self.next_index.to_be_bytes().to_vec();
        self.db.put(NEXT_INDEX_KEY, next_index_val).await?;

        Ok(())
    }

    // Recalculates `Merkle Tree` from the specified key
    async fn recalculate_from(&mut self, key: usize) -> PmtreeResult<()> {
        let mut depth = self.depth;
        let mut i = key;

        loop {
            let value = self.hash_couple(depth, i).await?;
            i >>= 1;
            depth -= 1;
            self.db
                .put(Key(depth, i).into(), H::serialize(value))
                .await?;

            if depth == 0 {
                self.root = value;
                break;
            }
        }

        Ok(())
    }

    // Hashes the correct couple for the key
    async fn hash_couple(&mut self, depth: usize, key: usize) -> PmtreeResult<H::Fr> {
        let b = key & !1;
        Ok(H::hash(&[
            self.get_elem(Key(depth, b)).await?,
            self.get_elem(Key(depth, b + 1)).await?,
        ]))
    }

    // Returns elem by the key
    async fn get_elem(&mut self, key: Key) -> PmtreeResult<H::Fr> {
        let res = self
            .db
            .get(key.into())
            .await?
            .map_or(self.cache[key.0], |value| H::deserialize(value));

        Ok(res)
    }

    /// Deletes a leaf at the `key` by setting it to its default value
    pub async fn delete(&mut self, key: usize) -> PmtreeResult<()> {
        if key >= self.next_index {
            return Err(PmtreeErrorKind::TreeError(TreeErrorKind::InvalidKey));
        }

        self.set(key, H::default_leaf(), None).await?;

        Ok(())
    }

    /// Inserts a leaf to the next available index
    pub async fn update_next(
        &mut self,
        leaf: H::Fr,
        pre_image: Option<D::PreImage>,
    ) -> PmtreeResult<()> {
        self.set(self.next_index, leaf, pre_image).await?;

        Ok(())
    }

    /// Batch insertion from starting index
    pub async fn set_range<I: IntoIterator<Item = H::Fr>>(
        &mut self,
        start: usize,
        leaves: I,
    ) -> PmtreeResult<()> {
        self.batch_insert(
            Some(start),
            leaves.into_iter().collect::<Vec<_>>().as_slice(),
        )
        .await
    }

    /// Batch insertion, updates the tree in parallel.
    pub async fn batch_insert(
        &mut self,
        start: Option<usize>,
        leaves: &[H::Fr],
    ) -> PmtreeResult<()> {
        let start = start.unwrap_or(self.next_index);
        let end = start + leaves.len();

        if end > self.capacity() {
            return Err(PmtreeErrorKind::TreeError(TreeErrorKind::MerkleTreeIsFull));
        }

        let mut subtree = HashMap::<Key, H::Fr>::new();

        let root_key = Key(0, 0);

        subtree.insert(root_key, self.root);
        self.fill_nodes(root_key, start, end, &mut subtree, leaves, start)
            .await?;

        let subtree = Arc::new(RwLock::new(subtree));

        let root_val = rayon::ThreadPoolBuilder::new()
            .num_threads(rayon::current_num_threads())
            .build()
            .unwrap()
            .install(|| Self::batch_recalculate(root_key, Arc::clone(&subtree), self.depth));

        let subtree = RwLock::into_inner(Arc::try_unwrap(subtree).unwrap()).unwrap();

        self.db
            .put_batch(
                subtree
                    .into_iter()
                    .map(|(key, value)| (key.into(), H::serialize(value)))
                    .collect(),
            )
            .await?;

        // Update next_index value in db
        if end > self.next_index {
            self.next_index = end;
            self.db
                .put(NEXT_INDEX_KEY, self.next_index.to_be_bytes().to_vec())
                .await?;
        }

        // Update root value in memory
        self.root = root_val;

        Ok(())
    }

    // Fills hashmap subtree
    #[async_recursion(?Send)]
    async fn fill_nodes(
        &mut self,
        key: Key,
        start: usize,
        end: usize,
        subtree: &mut HashMap<Key, H::Fr>,
        leaves: &[H::Fr],
        from: usize,
    ) -> PmtreeResult<()> {
        if key.0 == self.depth {
            if key.1 >= from {
                subtree.insert(key, leaves[key.1 - from]);
            }
            return Ok(());
        }

        let left = Key(key.0 + 1, key.1 * 2);
        let right = Key(key.0 + 1, key.1 * 2 + 1);

        let left_val = self.get_elem(left).await?;
        let right_val = self.get_elem(right).await?;

        subtree.insert(left, left_val);
        subtree.insert(right, right_val);

        let half = 1 << (self.depth - key.0 - 1);

        if start < half {
            self.fill_nodes(left, start, min(end, half), subtree, leaves, from)
                .await?;
        }

        if end > half {
            self.fill_nodes(right, 0, end - half, subtree, leaves, from)
                .await?;
        }

        Ok(())
    }

    // Recalculates tree in parallel (in-memory)
    fn batch_recalculate(
        key: Key,
        subtree: Arc<RwLock<HashMap<Key, H::Fr>>>,
        depth: usize,
    ) -> H::Fr {
        let left_child = Key(key.0 + 1, key.1 * 2);
        let right_child = Key(key.0 + 1, key.1 * 2 + 1);

        if key.0 == depth || !subtree.read().unwrap().contains_key(&left_child) {
            return *subtree.read().unwrap().get(&key).unwrap();
        }

        let (left, right) = rayon::join(
            || Self::batch_recalculate(left_child, Arc::clone(&subtree), depth),
            || Self::batch_recalculate(right_child, Arc::clone(&subtree), depth),
        );

        let result = H::hash(&[left, right]);

        subtree.write().unwrap().insert(key, result);

        result
    }

    /// Computes a Merkle proof for the leaf at the specified index
    pub async fn proof(&mut self, index: usize) -> PmtreeResult<MerkleProof<H>> {
        if index >= self.capacity() {
            return Err(PmtreeErrorKind::TreeError(TreeErrorKind::IndexOutOfBounds));
        }

        let mut witness = Vec::with_capacity(self.depth);

        let mut i = index;
        let mut depth = self.depth;
        while depth != 0 {
            i ^= 1;
            witness.push((
                self.get_elem(Key(depth, i)).await?,
                (1 - (i & 1)).try_into().unwrap(),
            ));
            i >>= 1;
            depth -= 1;
        }

        Ok(MerkleProof(witness))
    }

    /// Verifies a Merkle proof with respect to the input leaf and the tree root
    pub fn verify(&self, leaf: &H::Fr, witness: &MerkleProof<H>) -> bool {
        let expected_root = witness.compute_root_from(leaf);

        self.root() == expected_root
    }

    /// Returns the leaf by the key
    pub async fn get(&mut self, key: usize) -> PmtreeResult<H::Fr> {
        if key >= self.capacity() {
            return Err(PmtreeErrorKind::TreeError(TreeErrorKind::IndexOutOfBounds));
        }

        self.get_elem(Key(self.depth, key)).await
    }

    /// Returns the root of the tree
    pub fn root(&self) -> H::Fr {
        self.root
    }

    /// Returns the total number of leaves set
    pub fn leaves_set(&self) -> usize {
        self.next_index
    }

    /// Returns the capacity of the tree, i.e. the maximum number of leaves
    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    /// Returns the depth of the tree
    pub fn depth(&self) -> usize {
        self.depth
    }
}

impl<H: Hasher> MerkleProof<H> {
    /// Computes the Merkle root by iteratively hashing specified Merkle proof with specified leaf
    pub fn compute_root_from(&self, leaf: &H::Fr) -> H::Fr {
        let mut acc = *leaf;
        for w in self.0.iter() {
            if w.1 == 0 {
                acc = H::hash(&[acc, w.0]);
            } else {
                acc = H::hash(&[w.0, acc]);
            }
        }

        acc
    }

    /// Computes the leaf index corresponding to a Merkle proof
    pub fn leaf_index(&self) -> usize {
        self.get_path_index()
            .into_iter()
            .rev()
            .fold(0, |acc, digit| (acc << 1) + usize::from(digit))
    }

    /// Returns the path indexes forming a Merkle Proof
    pub fn get_path_index(&self) -> Vec<u8> {
        self.0.iter().map(|x| x.1).collect()
    }

    /// Returns the path elements forming a Merkle proof
    pub fn get_path_elements(&self) -> Vec<H::Fr> {
        self.0.iter().map(|x| x.0).collect()
    }

    /// Returns the length of a Merkle proof
    pub fn length(&self) -> usize {
        self.0.len()
    }
}

#[tokio::test]
async fn test_key_index_conversion() {
    let key = Key(100, 2004);
    assert_eq!(key, Key::from(DBKey::from(key)));

    let key = Key(101, 205);
    assert_eq!(key, Key::from(DBKey::from(key)));

    let key = Key(101, 2004);
    assert_eq!(key, Key::from(DBKey::from(key)));

    let key = Key(100, 205);
    assert_eq!(key, Key::from(DBKey::from(key)));
}
