use anyhow::bail;
use std::io::{ Write, Cursor, Read };
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use sodiumoxide::crypto::sign::ed25519::SecretKey;
use thiserror::Error;
use crate::stores::ReadableStore;
use std::ops::BitOrAssign;

fn read_varint<R: Read, O: BitOrAssign + Default + From<u8>>(r: &mut R) -> anyhow::Result<O> {
    let mut byt = [0u8; 1];
    let mut shift = 0;
    let mut accum = O::default();
    while {
        r.read_exact(&mut byt)?;
        accum |= ((byt[0] & 0x7f) << (shift * 7)).into();
        shift += 1;
        byt[0] & 0x80 != 0
    } {}
    Ok(accum)
}

pub enum Claim {
    Date(String),
    AuthorityAdd {
        public_key: String,
        name: String
    },
    AuthorityRemove {
        name: String
    },
    Yank {
        version: String,
        reason: String
    },
    Unyank {
        version: String
    },
    Tag {
        tag: String,
        version: String
    },
    Publication {
        version: String,
        id: Vec<u8>
    },
    Other {
        typeno: u32,
        data: Vec<u8>
    }
}

impl Claim {
    pub fn bitmask(&self) -> u8 {
        match self {
            Claim::AuthorityAdd { public_key: _, name: _ } => 0x01,
            Claim::AuthorityRemove { name: _ } => 0x02,
            Claim::Date(_) => 0x04,
            Claim::Yank { version: _, reason: _ } => 0x08,
            Claim::Unyank { version: _ } => 0x10,
            Claim::Tag { version: _, tag: _ } => 0x20,
            Claim::Publication { version: _, id: _ } => 0x40,
            Claim::Other { typeno: _, data: _ } => 0x80,
        }
    }

    pub fn to_bytes<W: Write>(&self, destination: &mut W) -> anyhow::Result<()> {
        bail!("oh no!")
    }

    pub fn from_bytes<T: AsRef<[u8]> + Send> (bytes: T) -> anyhow::Result<Claim> {
        bail!("aw dang");
    }
}

pub struct Event {
    claimset: u8,
    claims: Vec<Claim>,
    parents: Vec<Vec<u8>>,
    signatory: String,
    signature: Vec<u8>
}

impl Event {
    pub fn from_bytes<T: AsRef<[u8]> + Send> (input: T) -> anyhow::Result<Self> {
        // CLAIM_BITMASK(u8)
        // parent hashes(varint u32)
        // parent hashes * 32 * N
        // claims(varint u32)
        // claims * N
        //      claim type(varint u32)
        //      claim length(varint u32)
        //      claim data
        // signatory length(varint u32)
        // signatory
        // signature

        // signature type, null, payload type + len
        let bytes = input.as_ref();

        if bytes.len() < 1 {
            bail!("EOF while reading claimset mask");
        }

        let claimset = bytes[0];
        let mut cursor = Cursor::new(&bytes[1..]);
        let parent_count = read_varint(&mut cursor)?;
        let mut parents = Vec::with_capacity(parent_count);
        let mut parent_oid = [0; 32];
        while parents.len() < parent_count {
            cursor.read_exact(&mut parent_oid)?;
            parents.push(parent_oid.to_vec());
        }

        let claim_count = read_varint(&mut cursor)?;
        let mut claims = Vec::new();
        while claims.len() < claim_count {
            let claim_length = read_varint(&mut cursor)?;
            let mut claim_vec = Vec::with_capacity(claim_length);
            cursor.read_exact(&mut claim_vec)?;
            let claim = Claim::from_bytes(&claim_vec[..])?;
            claims.push(claim);
        }

        let signatory_len = read_varint(&mut cursor)?;
        let mut signatory_vec = Vec::with_capacity(signatory_len);
        cursor.read_exact(&mut signatory_vec)?;
        let signatory = String::from_utf8(signatory_vec)?;

        let mut signature = Vec::new();
        cursor.read_to_end(&mut signature)?;

        return Ok(Event {
            claims,
            signature,
            signatory,
            claimset,
            parents
        })
    }

    pub fn to_bytes_unsigned<W: Write>(&self, destination: &mut W) -> anyhow::Result<()> {

        for claim in self.claims.iter() {
            claim.to_bytes(destination)?;
        }
        Ok(())
    }

    pub fn to_bytes<W: Write, T: AsMut<W>>(&self, destination: T) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn verify<T: AsRef<[PublicKey]>>(&self, keys: T) -> bool {
        false
    }
}

#[derive(Error, Debug)]
enum EventBuilderError {
    #[error("Multiple dates")]
    RepeatedDate,
    #[error("Attempt to remove authority \"{0}\" which is not a currrent authority")]
    RemovedAuthorityDoesNotExist(String),
    #[error("Yanked version \"{0}\" does not exist")]
    YankedVersionDoesNotExist(String),
    #[error("Unyanked version \"{0}\" was not yanked")]
    UnyankedVersionNotYanked(String),
    #[error("Tagged version \"{0}\" does not exist")]
    TaggedVersionDoesNotExist(String),
    #[error("Authority name \"{0}\" is already registered with another key")]
    AuthorityNameConflict(String),
    #[error("Provided secret key is not an authority")]
    NotAuthoritative
}

pub struct EventBuilder {
    claims: Vec<Claim>,
    claimset: u8,
    error: Option<EventBuilderError>
}

impl EventBuilder {
    pub fn new() -> Self {
        EventBuilder {
            claims: Vec::new(),
            claimset: 0,
            error: None
        }
    }

    pub fn claim (mut self, c: Claim) -> Self {
        let bitmask = c.bitmask();
        let has_claim = bitmask & self.claimset;
        match &c {
            Claim::Date(_) => {
                self.error = Some(EventBuilderError::RepeatedDate)
            },
            _ => {}
        }

        self.claimset |= bitmask;
        self
    }

    pub fn sign<T, R>(self, name: T, pk: &SecretKey, store: &R) -> anyhow::Result<Event> where
        T: AsRef<str>,
        R: ReadableStore {
        if let Some(err) = self.error {
            return Err(err.into())
        }

        Err(EventBuilderError::NotAuthoritative.into())
    }
}
