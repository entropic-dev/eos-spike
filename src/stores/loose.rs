use crate::object::Object;
use crate::stores::{ReadableStore, WritableStore};
use anyhow::{self, bail};
use async_std::prelude::*;
use async_std::{fs, stream::Stream};
use async_trait::async_trait;
use flate2::bufread::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use futures::future::join_all;
use rayon::prelude::*;
use sha2::Digest;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::pin::Pin;

#[derive(Clone)]
pub struct LooseStore<D> {
    location: PathBuf,
    phantom: PhantomData<D>,
}

impl<D: 'static + Digest + Send + Sync> LooseStore<D> {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        LooseStore {
            location: PathBuf::from(path.as_ref()),
            phantom: PhantomData,
        }
    }

    // https://stackoverflow.com/a/18732276
    // pub(crate) async fn estimate_count() -> usize {
    //    unimplemented!()
    // }
    pub async fn to_packed_store(&self) -> anyhow::Result<()> {
        // faster to do the dir listing synchronously
        let entries = std::fs::read_dir(&self.location)?.filter_map(|xs| {
            let dent = xs.ok()?;
            let filename = dent.file_name();
            let name = filename.to_string_lossy();
            if name.len() != 2 {
                return None;
            }
            hex::decode(&name[..]).ok()?;
            Some(dent.path())
        });

        let mut results = Vec::new();
        for path in entries {
            results.push(async_std::task::spawn(async move {
                let mut entries = fs::read_dir(&path).await.ok()?;
                let mut items = Vec::new();
                while let Some(res) = entries.next().await {
                    let entry = res.ok()?;
                    items.push(
                        hex::decode(format!(
                            "{}{}",
                            path.file_name().unwrap().to_string_lossy(),
                            entry.file_name().to_string_lossy()
                        ))
                        .ok()?,
                    );
                }
                Some(items)
            }));
        }

        let results = join_all(results).await;
        let flattened: Vec<_> = results.iter().flatten().flatten().collect();

        // write magic ("ENTS")
        // write version (4 bytes, big-endian): 0
        // write object count (4 bytes, big-endian)
        // write objects
        //   write object type + size
        //   write object bytes
        // write crc32 code
        let mut tmp = self.location.clone();
        tmp.push("tmp");
        tmp.push(format!("tmp-{}-pack", std::process::id()));
        // place the bytes on disk
        let mut fd = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmp)
            .await?;

        let version = 0x0u32.to_be_bytes();
        fd.write_all(b"ENTS").await?;
        fd.write_all(&version[..]).await?;
        fd.write_all(&flattened.len().to_be_bytes()).await?;
        let mut offs = 16;
        let mut offsets = Vec::new();
        for hash in &flattened {
            offsets.push(offs);
            let obj = self.get(hash).await?.unwrap();
            let (typ, bytes) = match &obj {
                Object::Blob(bytes) => (0u8, bytes),
                Object::Event(bytes) => (1u8, bytes),
                Object::Version(bytes) => (2u8, bytes),
            };
            let mut size = bytes.len();
            let mut size_bytes = Vec::new();
            let first =
                (typ << 4 | (size & 0xf) as u8 | (if size > 0xf { 0x80 } else { 0x00 })) as u8;
            size = (size & !0xf) >> 4;
            size_bytes.push(first);
            while size > 0 {
                let next = (size & 0x7f) as u8;
                size = (size & !0x7f) >> 7;
                let continuation: u8 = (if size > 0 { 0x80 } else { 0 }) | next;
                size_bytes.push(continuation);
            }
            fd.write_all(&size_bytes[..]).await?;
            offs += size_bytes.len();

            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(bytes)?;
            let finished = &enc.finish()?;
            offs += finished.len();
            fd.write_all(finished).await?;
        }

        // zipper the hashes and offsets together.
        let mut sorted = flattened.iter().zip(offsets.iter()).collect::<Vec<_>>();

        sorted.par_sort_unstable_by(|lhs, rhs| lhs.0.cmp(rhs.0));

        let mut fanout = [0u32; 256];
        let mut fanout_idx: usize = 0;
        let mut object_idx: usize = 0;
        while fanout_idx < 256 && object_idx < sorted.len() {
            while sorted[object_idx].0[0] as usize != fanout_idx {
                fanout[fanout_idx] = (object_idx as u32).to_be();
                fanout_idx += 1;
                if fanout_idx == 256 {
                    break;
                }
            }

            while sorted[object_idx].0[0] as usize == fanout_idx {
                object_idx += 1;
                if object_idx >= sorted.len() {
                    break;
                }
            }

            fanout[fanout_idx] = (object_idx as u32).to_be();
            fanout_idx += 1;
        }

        while fanout_idx < 256 {
            fanout[fanout_idx] = (object_idx as u32).to_be();
            fanout_idx += 1;
        }

        let mut tmpidx = self.location.clone();
        tmpidx.push("tmp");
        tmpidx.push(format!("tmp-{}-idx", std::process::id()));
        // place the bytes on disk
        let mut fd = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmpidx)
            .await?;

        fd.write_all(b"EIDX").await?;
        fd.write_all(&version[..]).await?;
        let fanout_bytes = unsafe { std::mem::transmute::<[u32; 256], [u8; 256 * 4]>(fanout) };
        fd.write_all(&fanout_bytes[..]).await?;
        for (hash, _) in &sorted {
            fd.write_all(&hash).await?;
        }
        for (_, offset) in &sorted {
            let offs_u32 = (**offset) as u32;
            fd.write_all(&offs_u32.to_be_bytes()).await?;
        }

        let mut dest = self.location.clone();
        dest.push("pack");
        let mut packdest = dest.clone();
        let mut idxdest = dest;
        packdest.push(format!("{}.pack", std::process::id()));
        idxdest.push(format!("{}.idx", std::process::id()));
        fs::rename(&tmp, packdest).await?;
        fs::rename(&tmpidx, idxdest).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct LooseObjectStream<D> {
    location: PathBuf,
    phantom: PhantomData<D>,
}

impl<D> Stream for LooseObjectStream<D> {
    type Item = Object<Vec<u8>>;
    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut futures::task::Context,
    ) -> futures::task::Poll<Option<Self::Item>> {
        unimplemented!();
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
                std::io::ErrorKind::AlreadyExists => {}
                _ => bail!(e),
            }
        }
        loc.push(&bytes_encoded[2..]);
        match fs::OpenOptions::new()
            .read(true)
            .create(false)
            .open(&loc)
            .await
        {
            Ok(_) => return Ok(false), // cache already contained the object
            Err(e) => {
                if std::io::ErrorKind::NotFound != e.kind() {
                    bail!(e);
                }
            }
        };

        let mut tmp = self.location.clone();
        tmp.push("tmp");
        tmp.push(format!("loose-{}-{}", std::process::id(), bytes_encoded));
        // place the bytes on disk
        let mut fd = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmp)
            .await?;

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(header.as_ref())?;
        enc.write_all(item)?;
        fd.write_all(&enc.finish()?).await?;
        fd.sync_data().await?;
        fs::rename(&tmp, loc).await?;
        Ok(true)
    }

    async fn add_stream<'a, S: Stream<Item = &'a [u8]> + Send>(
        &mut self,
        _item: S,
        _size_hint: Option<usize>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn remove<T: Into<D> + Send>(&mut self, _item: T) -> bool {
        unimplemented!()
    }

    async fn clear(&mut self) -> bool {
        unimplemented!()
    }
}

#[async_trait]
impl<D: 'static + Digest + Send + Sync> ReadableStore for LooseStore<D> {
    type ObjectStream = LooseObjectStream<D>;

    async fn get<T: AsRef<[u8]> + Send + Sync>(
        &self,
        item: T,
    ) -> anyhow::Result<Option<Object<Vec<u8>>>> {
        let bytes = item.as_ref();
        let bytes_encoded = hex::encode(bytes);
        let mut loc = self.location.clone();
        loc.push(&bytes_encoded[0..2]);
        loc.push(&bytes_encoded[2..]);
        let mut fd = match fs::OpenOptions::new()
            .read(true)
            .create(false)
            .open(&loc)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                if std::io::ErrorKind::NotFound != e.kind() {
                    bail!(e);
                }
                return Ok(None);
            }
        };

        let mut data = Vec::new();
        fd.read_to_end(&mut data).await?;
        let mut reader = BufReader::new(ZlibDecoder::new(BufReader::new(&data[..])));
        let mut type_vec = Vec::new();
        let mut size_vec = Vec::new();
        let mut object = Vec::new();

        // TODO: it would be nice to do this in a thread/threadpool!
        BufRead::read_until(&mut reader, 0x20, &mut type_vec)?;
        BufRead::read_until(&mut reader, 0, &mut size_vec)?;
        std::io::copy(&mut reader, &mut object)?;

        let str_size = std::str::from_utf8(&size_vec[..])?;
        let size = str_size[..str_size.len() - 1].parse::<usize>()?;
        if object.len() != size {
            bail!(
                "mismatched len: got {} bytes, expected {}",
                object.len(),
                size
            )
        }

        match std::str::from_utf8(&type_vec[..])? {
            "blob " => Ok(Some(Object::Blob(object))),
            "sign " => Ok(Some(Object::Event(object))),
            "vers " => Ok(Some(Object::Version(object))),
            _ => bail!("Could not parse object type"),
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
