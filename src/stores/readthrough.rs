use crate::stores::{ ReadableStore, WritableStore };
use std::collections::HashSet;
use chrono::{ Utc, Duration };

pub struct ReadThrough<T: ReadableStore + WritableStore> {
    inner_store: T,
    upstream_url: String,
    allow: Option<HashSet<String>>,
    block: Option<HashSet<String>>,
    fetch_after: Duration
}
/*
impl<Store: ReadableStore + WritableStore> ReadableStore for ReadThrough<Store> {
    fn get_packument_raw<T: AsRef<str>>(&self, package: T) -> Option<(Box<dyn Read>, [u8; 32])> {

        if let Some(ref block) = self.block {
            if block.has(package.as_ref().to_string()) {
                return None
            }
        }

        if let Some(ref allow) = self.allow {
            if !allow.has(package.as_ref().to_string()) {
                return None
            }
        }

        if let Some((reader, metadata)) = self.inner_store.get_packument_raw(package) {
            let now = Utc::now();
            let dur = now.signed_duration_since(metadata.last_fetched_at);

            if dur >= self.fetch_after {
                // refetch and update. if it's a 304, update
                // the metadata and store that, otherwise walk
                // and grab each tarball and store those.
            }

            Some((reader, metadata))
        }

        // Ok, go fetch it and store it in the inner store.

        None
    }

}
*/
