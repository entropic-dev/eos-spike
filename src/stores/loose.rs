use async_std::{ fs, stream::Stream, prelude::* };
use async_std::io::prelude::*;
use async_trait::async_trait;
use crate::stores::{ WritableStore, ReadableStore };
use std::path::{ Path, PathBuf };
use sha2::Digest;
use anyhow::{ self, bail };
use std::marker::PhantomData;
use crate::object::Object;
use async_std::prelude::*;
use std::io::prelude::*;
use std::io::{ BufReader, BufRead };
use std::io::Write;
use flate2::write::{ ZlibEncoder };
use flate2::bufread::{ ZlibDecoder };
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

    pub async fn to_packed_store() -> anyhow::Result<()> {
        // enumerate all objects
        // fill out objects with recency/sortorderinfo
        // sort objects by type, then "sortpath" (basename/dir for blobs, semver order descending for packages)
        // walk each object type with a sliding window of comparisons. write deltas if they're >50% compression.
        // 
        Ok(())
    }
}

#[async_trait]
impl<D: 'static + Digest + Send + Sync> WritableStore<D> for LooseStore<D> {
    async fn add<T: AsRef<[u8]> + Send>(&self, object: Object<T>) -> anyhow::Result<bool> {
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
            Ok(_) => return Ok(false), // cache already contained the object
            Err(e) => {
                if std::io::ErrorKind::NotFound != e.kind() {
                    bail!(e);
                }
            }
        };

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
        Ok(true)
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

#[async_trait]
impl<D: 'static + Digest + Send + Sync> ReadableStore for LooseStore<D> {
    async fn get<T: AsRef<[u8]> + Send>(&self, item: T) -> anyhow::Result<Option<Object<Vec<u8>>>> {
        let bytes = item.as_ref();
        let bytes_encoded = hex::encode(bytes);
        let mut loc = self.location.clone();
        loc.push(&bytes_encoded[0..2]);
        loc.push(&bytes_encoded[2..]);
        let mut fd = match fs::OpenOptions::new()
            .read(true)
            .create(false)
            .open(&loc)
            .await {
            Ok(f) => f,
            Err(e) => {
                if std::io::ErrorKind::NotFound != e.kind() {
                    bail!(e);
                }
                return Ok(None)
            }
        };

        let mut data = Vec::new();
        fd.read_to_end(&mut data).await?;
        let mut reader = BufReader::new(ZlibDecoder::new(BufReader::new(&data[..])));
        let mut type_vec = Vec::new();
        let mut size_vec = Vec::new();
        let mut object = Vec::new();

        // TODO: it would be nice to do this in a thread/threadpool!
        BufRead::read_until(&mut reader, 0x20, &mut type_vec);
        BufRead::read_until(&mut reader, 0, &mut size_vec);
        std::io::copy(&mut reader, &mut object)?;

        let str_size = std::str::from_utf8(&size_vec[..])?;
        let size = str_size[..str_size.len() - 1].parse::<usize>()?;
        if object.len() != size {
            return bail!("mismatched len: got {} bytes, expected {}", object.len(), size)
        }

        return match std::str::from_utf8(&type_vec[..])? {
            "blob " => {
                Ok(Some(Object::Blob(object)))
            },
            "sign " => {
                Ok(Some(Object::Signature(object)))
            },
            "vers " => {
                Ok(Some(Object::Version(object)))
            }
            _ => {
                bail!("Could not parse object type")
            }
        }
    }

    async fn list<R: Stream<Item = Vec<u8>>>(&self) -> R {
        unimplemented!()
    }

    async fn get_stream<'a, T: AsRef<[u8]> + Send, R: Stream<Item = &'a [u8]>>(&self, item: T) -> Option<R> {
        unimplemented!()
    }
}
