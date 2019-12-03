use async_std::{ fs, stream::Stream };
use crate::stores::ReadableStore;
use async_trait::async_trait;
use std::io::{ Cursor, Write, Seek, SeekFrom };
use memmap::{ Mmap, MmapOptions };
use std::path::{ Path, PathBuf };
use std::marker::PhantomData;
use anyhow::{ self, bail };
use std::io::Read;
use digest::Digest;
use byteorder::{ BigEndian, ReadBytesExt };
use crate::object::Object;
use flate2::bufread::ZlibDecoder;
use std::io::prelude::*;
use std;

#[derive(Clone)]
pub struct PackedObjectStream<D> {
    phantom: PhantomData<D>
}

pub struct PackedIndex<D> {
    fanout: [u32; 256],
    ids: Vec<Vec<u8>>,
    offsets: Vec<u64>,
    next_offsets_indices: Vec<usize>,
    phantom: PhantomData<D>
}

impl<D: Digest + Send + Sync> PackedIndex<D> {
    pub fn from<R: Read>(mut input: R) -> anyhow::Result<Self> {
        let mut magic = [0u8; 4];
        input.read_exact(&mut magic)?;
        let mut version = [0u8; 4];
        input.read_exact(&mut version)?;

        if (&magic != b"EIDX") {
            bail!("invalid pack index");
        }

        if (version != unsafe { std::mem::transmute::<u32, [u8; 4]>(0u32.to_be()) }) {
            bail!("unsupported pack index version");
        }

        let mut fanout = [0u32; 256];
        input.read_u32_into::<BigEndian>(&mut fanout)?;

        let object_count = fanout[255] as usize;
        let oid_size = D::new().result().len();

        let mut oid_bytes_vec = vec!(0u8; object_count * oid_size);
        input.read_exact(&mut oid_bytes_vec.as_mut_slice())?;

        let ids: Vec<Vec<u8>> = oid_bytes_vec.chunks(oid_size).map(
            |chunk| chunk.to_vec()
        ).collect();

        let mut offsets_vec = vec!(0u32; object_count);
        input.read_u32_into::<BigEndian>(&mut offsets_vec.as_mut_slice())?;

        // TODO: use this to extend to 64bit offsets
        let offsets: Vec<_> = offsets_vec.into_iter().map(|offset| {
            offset as u64
        }).collect();

        let mut offset_idx_sorted: Vec<(usize, &u64)> = offsets.iter().enumerate().collect();
        offset_idx_sorted.sort_by_key(|(_, offset)| *offset);
        let mut next_offsets_indices = vec![0; offset_idx_sorted.len()];
        let mut idx = 0;
        eprintln!("idx={}, len={}", idx,offset_idx_sorted.len() );
        while idx < offset_idx_sorted.len() - 1 {
            next_offsets_indices[offset_idx_sorted[idx].0] = offset_idx_sorted[idx + 1].0;
            idx += 1;
        }

        Ok(PackedIndex {
            fanout,
            ids,
            offsets,
            next_offsets_indices,
            phantom: PhantomData
        })
    }

    pub fn get_bounds<T: AsRef<[u8]> + Send + Sync>(&self, id: T) -> Option<(u64, u64)> {
        let as_bytes = id.as_ref();
        let mut lo = if as_bytes[0] > 0 {
            self.fanout[(as_bytes[0] - 1) as usize]
        } else {
            0
        };
        let mut hi = self.fanout[as_bytes[0] as usize];
        let mut middle: usize;
        let len = self.offsets.len();
        loop {
            middle = ((lo + hi) >> 1) as usize;
            if middle >= len {
                return None
            }

            match as_bytes.partial_cmp(&self.ids[middle][..]) {
                Some(xs) => match xs {
                    std::cmp::Ordering::Less => {
                        hi = middle as u32;
                    },
                    std::cmp::Ordering::Greater => {
                        lo = (middle + 1) as u32;
                    },
                    std::cmp::Ordering::Equal => {
                        return Some((
                            self.offsets[middle],
                            self.offsets[self.next_offsets_indices[middle]]
                        ));
                    }
                },
                None => return None
            }

            if lo >= hi {
                break
            }
        }

        None
    }

}

pub struct Reader {
    mmap: Mmap
}

impl Reader {
    pub fn new(mmap: Mmap) -> Self {
        Reader {
            mmap
        }
    }

    fn read_bounds(&self, start: u64, end: u64) -> anyhow::Result<Object<Vec<u8>>> {
        let mut cursor = Cursor::new(&self.mmap[ .. end as usize]);
        cursor.seek(SeekFrom::Start(start))?;

        let mut output = Vec::new();
        let packfile_type = packfile_read(&mut cursor, &mut output, &mut 0)?;

        Ok(match packfile_type {
            0 => Object::Blob(output),
            1 => Object::Signature(output),
            2 => Object::Version(output),
            _ => bail!("Unrecognized type")
        })
    }
}

pub fn packfile_read<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    read_bytes: &mut u64
) -> anyhow::Result<u8> {
    let mut byte = [0u8; 1];
    input.read_exact(&mut byte)?;

    let obj_type = (byte[0] & 0x70) >> 4;
    let mut size = (byte[0] & 0xf) as u64;
    let mut count = 0;
    let mut continuation = byte[0] & 0x80;
    loop {
        if continuation < 1 {
            break
        }

        input.read_exact(&mut byte)?;
        continuation = byte[0] & 0x80;

        size |= ((byte[0] & 0x7f) as u64) << (4 + 7 * count);
        count += 1;
    }

    match obj_type {
        0...4 => {
            let mut deflate_stream = ZlibDecoder::new(input);
            std::io::copy(&mut deflate_stream, output)?;
            *read_bytes = 1 + count + deflate_stream.total_in();
            return Ok(obj_type)
        },

        _ => {
            bail!("unknown object type");
        }
    }
}

pub struct PackedStore<D> {
    index: PackedIndex<D>,
    objects: Reader,
    phantom: PhantomData<D>
}

impl<D: Digest + Send + Sync> PackedStore<D> {
    pub fn new<T: AsRef<Path>>(packfile: T, index: T) -> anyhow::Result<Self> {
        let index_file = std::fs::File::open(index.as_ref())?;
        let index_mmap = unsafe { MmapOptions::new().map(&index_file)? };
        let idx = PackedIndex::from(std::io::Cursor::new(index_mmap))?;

        let file = std::fs::File::open(packfile.as_ref())?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let packfile = Reader::new(mmap);
        Ok(PackedStore {
            index: idx,
            objects: packfile,
            phantom: PhantomData
        })
    }
}

#[async_trait]
impl<D: 'static + Digest + Send + Sync> ReadableStore for PackedStore<D> {
    type ObjectStream = PackedObjectStream<D>;
    async fn get<T: AsRef<[u8]> + Send>(&self, item: T) -> anyhow::Result<Option<Object<Vec<u8>>>> {
        let bytes = item.as_ref();
        let maybe_bounds = self.index.get_bounds(bytes);
        if maybe_bounds.is_none() {
            return Ok(None)
        }

        let (start, end) = maybe_bounds.unwrap();
        match self.objects.read_bounds(start, end) {
            Ok(x) => Ok(Some(x)),
            Err(e) => bail!("failed")
        }
    }

    async fn list(&self) -> Self::ObjectStream {

        unimplemented!()
    }

    async fn get_stream<'a, T: AsRef<[u8]> + Send, R: Stream<Item = &'a [u8]>>(&self, item: T) -> Option<R> {
        unimplemented!()
    }
}
