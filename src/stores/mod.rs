use std::io::Read;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value;

pub struct PackageVersion {
    dist: Dist
}

pub struct Packument {
    versions: HashMap<String, PackageVersion>,
    times: HashMap<String, DateTime<Utc>>,
    tags: HashMap<String, String>,
    authors: Vec<String>,

    #[serde(flatten)]
    rest: HashMap<String, Value>
}

/*
pub enum PackumentAction {
    Create,
    PublishVersion,
    DeprecateVersion,
    UndeprecateVersion,
    UnpublishVersions,
    Unpublish,
    CreateTag,
    DeleteTag,
    AddCollaborator,
    RemoveCollaborator
}
*/

pub trait ReadableStore {
    fn get_packument<T: AsRef<str>>(&self, package: T) -> Option<Packument>;
    fn get_packument_raw<T: AsRef<str>>(&self, package: T) -> Option<(dyn Read, [u8; 32])>;
    fn get_packument_readme<T: AsRef<str>>(&self, package: T) -> Option<dyn Read>;
    fn get_tarball<T: AsRef<str>, S: AsRef<str>>(&self, package: T, version: S) -> Option<(dyn Read, [u8; 32])>;
}

pub trait WritableStore : ReadableStore {
    fn upsert_packument<T: AsRef<str>, R: std::io::Read>(&self, package: T, body: R) -> anyhow::Result<[u8; 32]>;
}
