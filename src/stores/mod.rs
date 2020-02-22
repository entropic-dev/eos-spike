use crate::packument::{ Packument, Human };
use std::io::Read;
use futures::io::AsyncRead;
use futures::future::BoxFuture;
use chrono::{ DateTime, Utc };

mod readthrough;

pub struct PackageMetadata {
    integrity: String,
    last_fetched_at: DateTime<Utc>
}

pub use readthrough::ReadThrough;
pub trait ReadableStore {
    fn get_packument<T: AsRef<str>>(&self, package: T) -> Option<Packument> {
        if let Some((reader, hash)) = self.get_packument_raw(package) {
            let packument = serde_json::from_reader(reader).ok()?;
            return Some(packument)
        }

        None
    }

    fn get_packument_raw<T: AsRef<str>>(&self, package: T) -> Option<(Box<dyn Read>, PackageMetadata)> {
        None
    }

    fn get_packument_readme<T: AsRef<str>>(&self, package: T) -> Option<Box<dyn Read>> {
        None
    }

    fn get_tarball<T: AsRef<str>, S: AsRef<str>>(&self, package: T, version: S) -> Option<(Box<dyn Read>, PackageMetadata)> {
        None
    }
}

pub trait AuthorityStore {
    fn check_password<T: AsRef<str>, S: AsRef<str>>(&self, username: T, password: S) -> anyhow::Result<bool>;

    fn signup<T: AsRef<str>, S: AsRef<str>, V: AsRef<str>>(&self, username: T, password: S, email: V) -> anyhow::Result<Human>;
}

pub trait WritableStore : ReadableStore {
    fn upsert_packument<T: AsRef<str>, R: std::io::Read>(&self, package: T, body: R) -> anyhow::Result<PackageMetadata>;


    fn update_metadata<T: AsRef<str>>(&self, package: T, metadata: PackageMetadata) -> anyhow::Result<PackageMetadata>;

}

impl ReadableStore for () {
}
