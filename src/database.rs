use crate::*;

use std::collections::HashMap;
use async_trait::async_trait;

/// Trait that must be implemented for a Database
#[async_trait]
pub trait Database {
    /// Config for database.
    type Config;

    /// Creates new instance of db
    async fn new(config: Self::Config) -> PmtreeResult<Self>
    where
        Self: Sized;

    /// Loades existing db (existence check required)
    async fn load(config: Self::Config) -> PmtreeResult<Self>
    where
        Self: Sized;

    /// Returns value from db by the key
    async fn get(&mut self, key: DBKey) -> PmtreeResult<Option<Value>>;

    /// Puts the value to the db by the key
    async fn put(&mut self, key: DBKey, value: Value) -> PmtreeResult<()>;

    /// Puts the leaves batch to the db
    async fn put_batch(&mut self, subtree: HashMap<DBKey, Value>) -> PmtreeResult<()>;
}
