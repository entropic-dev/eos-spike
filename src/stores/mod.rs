use crate::object::Object;
use async_std::stream::Stream;
use async_trait::async_trait;
use sha2::Digest;

pub mod loose;
pub mod multiple;
pub mod packed;

// WritableStore
// - add(Hashable) -> <present | not present>
// - remove(Hashable) -> <removed | not removed>
// - clear()
// ReadableStore
// - list() -> Iter<Hash>
// - get(Into<Hash>)
// - has(Into<Hash>)

#[async_trait]
pub trait WritableStore<D: Digest + Send + Sync> {
    async fn add<T: AsRef<[u8]> + Send>(&self, object: Object<T>) -> anyhow::Result<bool>;
    async fn add_stream<'a, S: Stream<Item = &'a [u8]> + Send>(
        &mut self,
        item: S,
        size_hint: Option<usize>,
    ) -> anyhow::Result<()>;
    async fn remove<T: Into<D> + Send>(&mut self, item: T) -> bool;
    async fn clear(&mut self) -> bool;
}

#[async_trait]
pub trait ReadableStore {
    type ObjectStream;

    async fn get<T: AsRef<[u8]> + Send + Sync>(
        &self,
        item: T,
    ) -> anyhow::Result<Option<Object<Vec<u8>>>>;
    async fn list(&self) -> Self::ObjectStream;
    async fn get_stream<'a, T: AsRef<[u8]> + Send, R: Stream<Item = &'a [u8]>>(
        &self,
        item: T,
    ) -> Option<R>;
}
