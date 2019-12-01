use async_std::{ fs, stream::Stream };
use async_trait::async_trait;
use crate::stores::{ WritableStore };
use std::path::{ Path, PathBuf };
use sha2::Digest;
use anyhow::{ self, bail };
use std::marker::PhantomData;
use crate::object::Object;
use async_std::prelude::*;
use std::io::prelude::*;
use flate2::write::ZlibEncoder;
use flate2::Compression;

#[derive(Clone)]
pub struct LooseStore<D> {
    location: PathBuf,
    phantom: PhantomData<D>
}

impl<D> LooseStore<D> {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        LooseStore {
            location: PathBuf::from(path.as_ref()),
            phantom: PhantomData
        }
    }

    // https://stackoverflow.com/a/18732276
    pub(crate) async fn estimate_count() -> usize {
        0
    }
}

#[async_trait]
impl<D: 'static + Digest + Send + Sync> WritableStore<D> for LooseStore<D> {
    async fn add<T: AsRef<[u8]> + Send>(&self, object: Object<T>) -> anyhow::Result<()> {
        let mut digest = D::new();
        let item = object.bytes().as_ref();
        let header = format!("{} {}\0", object.to_string(), item.len());
        digest.input(&header);
        digest.input(item);
        let bytes = digest.result();
        let bytes_encoded = hex::encode(bytes);
        let mut loc = self.location.clone();
        loc.push(&bytes_encoded[0..2]);
        if let Err(e) = fs::create_dir(&loc).await {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists => {},
                _ => bail!(e)
            }
        }
        loc.push(&bytes_encoded[2..]);
        match fs::OpenOptions::new()
            .read(true)
            .create(false)
            .open(&loc)
            .await {
            Ok(_) => return Ok(()), // cache already contained the object
            Err(e) => {
                if std::io::ErrorKind::NotFound != e.kind() {
                    bail!(e);
                }
            }
        }

        let mut tmp = self.location.clone();
        tmp.push(format!("tmp-{}-{}", std::process::id(), bytes_encoded));
        // place the bytes on disk
        let mut fd = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmp).await?;


        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(header.as_ref())?;
        enc.write_all(item)?;
        fd.write_all(&enc.finish()?).await?;
        fd.sync_data().await?;
        fs::rename(&tmp, loc).await?;
        Ok(())
    }

    async fn add_stream<'a, S: Stream<Item = &'a [u8]> + Send>(&mut self, item: S, size_hint: Option<usize>) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn remove<T: Into<D> + Send>(&mut self, item: T) -> bool {
        unimplemented!()
    }

    async fn clear(&mut self) -> bool {
        unimplemented!()
    }
}
