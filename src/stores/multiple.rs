use crate::object::Object;
use crate::stores::ReadableStore;
use async_std::stream::Stream;
use async_trait::async_trait;

pub struct FusedObjectStream;

#[async_trait]
impl<R0: ReadableStore + Send + Sync, R1: ReadableStore + Send + Sync> ReadableStore
    for (R0, R1)
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
        _item: T,
    ) -> Option<R> {
        unimplemented!()
    }
}

#[async_trait]
impl<Reader: ReadableStore + Send + Sync> ReadableStore
    for Vec<Reader>
{
    type ObjectStream = FusedObjectStream;

    async fn get<T: AsRef<[u8]> + Send + Sync>(
        &self,
        item: T,
    ) -> anyhow::Result<Option<Object<Vec<u8>>>> {
        for store in self {
            if let Some(obj) = store.get(item.as_ref()).await? {
                return Ok(Some(obj))
            }
        }
        Ok(None)
    }

    async fn list(&self) -> Self::ObjectStream {
        unimplemented!()
    }

    async fn get_stream<'a, T: AsRef<[u8]> + Send, R: Stream<Item = &'a [u8]>>(
        &self,
        _item: T,
    ) -> Option<R> {
        unimplemented!()
    }
}