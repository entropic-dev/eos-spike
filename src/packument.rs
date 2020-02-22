use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize)]
pub struct Dist {
    shasum: String,
    tarball: String,

    integrity: Option<String>,
    fileCount: Option<i64>,
    unpackedSize: Option<i64>,
    #[serde(rename = "npm-signature")]
    npm_signature: Option<String>,

    #[serde(flatten)]
    rest: HashMap<String, Value>
}

#[derive(Serialize, Deserialize)]
pub struct PackageVersion {
    dist: Dist,
    #[serde(rename = "_hasShrinkwrap")]
    has_shrinkwrap: Option<bool>
}

#[derive(Serialize, Deserialize)]
pub struct PackageHuman {
    name: String,
    email: String
}

#[derive(Serialize, Deserialize)]
pub struct Packument {
    author: Option<PackageHuman>,
    name: String,
    description: Option<String>,
    versions: HashMap<String, PackageVersion>,
    time: HashMap<String, DateTime<Utc>>,
    #[serde(rename = "dist-tags")]
    tags: HashMap<String, String>,
    maintainers: Vec<PackageHuman>,
    users: Option<Vec<String>>,

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


