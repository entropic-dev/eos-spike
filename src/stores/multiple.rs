use crate::object::Object;
use crate::stores::{ReadableStore, WritableStore};
use async_std::io::prelude::*;
use async_std::stream::Stream;
use async_trait::async_trait;
use digest::Digest;

struct MultipleStore<R0: ReadableStore, R1: ReadableStore>(R0, R1);
struct FusedObjectStream;

#[async_trait]
impl<R0: ReadableStore + Send + Sync, R1: ReadableStore + Send + Sync> ReadableStore
    for MultipleStore<R0, R1>
{
    type ObjectStream = FusedObjectStream;

    async fn get<T: AsRef<[u8]> + Send + Sync>(
        &self,
        item: T,
    ) -> anyhow::Result<Option<Object<Vec<u8>>>> {
        if let Some(obj) = self.0.get(item.as_ref()).await? {
            Ok(Some(obj))
        } else {
            self.1.get(item.as_ref()).await
        }
    }

    async fn list(&self) -> Self::ObjectStream {
        unimplemented!()
    }

    async fn get_stream<'a, T: AsRef<[u8]> + Send, R: Stream<Item = &'a [u8]>>(
        &self,
        item: T,
    ) -> Option<R> {
        unimplemented!()
    }
}
