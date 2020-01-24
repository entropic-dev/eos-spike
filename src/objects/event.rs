use anyhow::bail;
use std::io::{ Write, Cursor, Read };
use sodiumoxide::crypto::sign::ed25519::{ PublicKey, SecretKey, sign_detached, verify_detached, Signature };
use thiserror::Error;
use crate::stores::ReadableStore;
use std::ops::{ BitAnd, BitOrAssign };
use std::collections::HashSet;

// The varint crate let me down. This could be better/faster.
fn read_varint<R: Read>(r: &mut R) -> anyhow::Result<u64> {
    let mut byt = [0u8; 1];
    let mut shift = 0;
    let mut accum = 0u64;
    let mut mask = 0x7fu64;
    while {
        r.read_exact(&mut byt)?;

        let item = byt[0] as u64;
        accum |= (item & mask) << (shift * 7);
        shift += 1;
        item & 0x80 != 0
    } {}
    Ok(accum)
}

fn read_varint_string<R: Read>(r: &mut R) -> anyhow::Result<String> {
    let len: u64 = read_varint(r)?;
    let mut str_vec = vec![0; len as usize];
    r.read_exact(&mut str_vec);
    Ok(String::from_utf8(str_vec)?)
}

fn write_varint<W: Write, I: Into<u64>>(w: &mut W, input: I) -> anyhow::Result<usize> {
    const MSB_ALL: u64 = !0x7fu64;
    let mut input_u64: u64 = input.into();
    let mut bytes: Vec<u8> = Vec::with_capacity(8);
    while input_u64 & MSB_ALL > 0 {
        bytes.push(((input_u64 & 0xFF) as u8) | 0x80u8);
        input_u64 >>= 7;
    }
    bytes.push((input_u64 & 0x7F) as u8);
    w.write_all(&bytes[..])?;
    Ok(bytes.len())
}

fn write_varint_str<W: Write>(w: &mut W, s: &str) -> anyhow::Result<usize> {
    let bytes = s.as_bytes();
    let mut written = write_varint(w, bytes.len() as u64)?;
    w.write_all(bytes)?;
    Ok((written + bytes.len()) as usize)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    AuthorityAdd {
        public_key: String,
        name: String
    },
    AuthorityRemove {
        name: String
    },
    Date(u64),
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
        typeno: u64,
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

    pub fn to_bytes<W: Write>(&self, destination: &mut W) -> anyhow::Result<usize> {
        let mut written = 0;
        match self {
            Claim::AuthorityAdd { public_key, name } => {
                let mask = [0x01u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*public_key)?;
                written += write_varint_str(destination, &*name)?;
            },
            Claim::AuthorityRemove { name } => {
                let mask = [0x02u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*name)?;
            },
            Claim::Date(timestamp) => {
                let mask = [0x04u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint(destination, *timestamp)?;
            },
            Claim::Yank { version, reason } => {
                let mask = [0x08u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*version)?;
                written += write_varint_str(destination, &*reason)?;
            },
            Claim::Unyank { version } => {
                let mask = [0x10u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*version)?;
            },
            Claim::Tag { version, tag } => {
                let mask = [0x20u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*version)?;
                written += write_varint_str(destination, &*tag)?;
            },
            Claim::Publication { version, id } => {
                let mask = [0x40u8; 1];
                written += 1;
                destination.write_all(&mask[..])?;
                written += write_varint_str(destination, &*version)?;
                written += write_varint(destination, id.len() as u64)?;
                written += id.len();
                destination.write_all(&id[..])?;
            },
            Claim::Other { typeno, data } => {
                written += write_varint(destination, *typeno)?;
                written += data.len();
                destination.write_all(&data[..]);
            }
        }

        Ok(written)
    }

    pub fn from_bytes<T: AsRef<[u8]> + Send> (input: T) -> anyhow::Result<Claim> {
        // first byte is type encoded as varint
        // auth-add := varint publickey varint name
        // auth-rm := varint name
        // date := varint date
        // yank := varint version varint reason
        // unyank := varint version
        // tag := varint tag varint version
        // publish := varint version 32bytes id
        // other := read the rest of the bytes
        let bytes = input.as_ref();
        let mut capacity = bytes.len();
        let mut cursor = Cursor::new(bytes);
        let claim_type = read_varint(&mut cursor)?;
        capacity -= cursor.position() as usize;
        Ok(match claim_type {
            0x01 => {
                Claim::AuthorityAdd {
                    public_key: read_varint_string(&mut cursor)?,
                    name: read_varint_string(&mut cursor)?
                }
            },
            0x02 => {
                Claim::AuthorityRemove {
                    name: read_varint_string(&mut cursor)?
                }
            },
            0x04 => {
                Claim::Date(read_varint(&mut cursor)?)
            },
            0x08 => {
                Claim::Yank {
                    version: read_varint_string(&mut cursor)?,
                    reason: read_varint_string(&mut cursor)?
                }
            },
            0x10 => {
                Claim::Unyank {
                    version: read_varint_string(&mut cursor)?
                }
            },
            0x20 => {
                Claim::Tag {
                    tag: read_varint_string(&mut cursor)?,
                    version: read_varint_string(&mut cursor)?
                }
            },
            0x40 => {
                let version = read_varint_string(&mut cursor)?;
                let mut id = [0u8; 32];
                cursor.read_exact(&mut id)?;
                Claim::Publication {
                    version,
                    id: id.to_vec()
                }
            },
            typeno => {
                let mut rest = Vec::with_capacity(capacity);
                cursor.read_to_end(&mut rest)?;
                Claim::Other {
                    typeno,
                    data: rest
                }
            }
        })
    }
}

#[derive(PartialEq, Debug)]
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
        // TODO(chrisdickinson): note the lack of a signature algo string. We
        // should add that.

        // signature type, null, payload type + len
        let bytes = input.as_ref();

        if bytes.len() < 1 {
            bail!("EOF while reading claimset mask");
        }

        let claimset = bytes[0];
        let mut cursor = Cursor::new(&bytes[1..]);
        let parent_count = read_varint(&mut cursor)? as usize;
        let mut parents = Vec::with_capacity(parent_count);
        let mut parent_oid = [0; 32];
        while parents.len() < parent_count {
            cursor.read_exact(&mut parent_oid)?;
            parents.push(parent_oid.to_vec());
        }

        let claim_count = read_varint(&mut cursor)? as usize;
        let mut claims = Vec::new();
        while claims.len() < claim_count {
            let claim_length = read_varint(&mut cursor)? as usize;
            let mut claim_vec = vec![0; claim_length];
            cursor.read_exact(&mut claim_vec)?;
            let claim = Claim::from_bytes(&claim_vec[..])?;
            claims.push(claim);
        }

        let signatory_len = read_varint(&mut cursor)? as usize;
        let mut signatory_vec = vec![0; signatory_len];
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

    pub fn to_bytes_unsigned<W: Write>(&self, destination: &mut W) -> anyhow::Result<usize> {

        let claimset_buf = [self.claimset; 1];
        let mut written = 1 as usize;
        destination.write_all(&claimset_buf)?;

        written += write_varint(destination, self.parents.len() as u64)?;
        for parent in self.parents.iter() {
            written += parent.len();
            destination.write_all(&parent[..])?;
        }

        written += write_varint(destination, self.claims.len() as u64)?;
        for claim in self.claims.iter() {
            written += claim.to_bytes(destination)?;
        }

        let signatory_slice = self.signatory.as_bytes();
        written += write_varint(destination, signatory_slice.len() as u64)?;
        written += signatory_slice.len();
        destination.write_all(signatory_slice)?;

        Ok(written)
    }

    pub fn to_bytes<W: Write>(&self, destination: &mut W) -> anyhow::Result<usize> {
        let mut written = self.to_bytes_unsigned(destination)?;
        written += self.signature.len();
        destination.write_all(&self.signature[..])?;
        Ok(written)
    }

    pub fn verify(&self, pk: &PublicKey) -> anyhow::Result<bool> {
        let mut buf = Vec::new();
        self.to_bytes_unsigned(&mut buf)?;

        let mut signature_bytes = [0; 64];
        signature_bytes.copy_from_slice(&self.signature[0..64]);
        let sig = Signature(signature_bytes);
        Ok(verify_detached(&sig, &buf[..], pk))
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
    parents: HashSet<Vec<u8>>,
    claimset: u8,
    error: Option<EventBuilderError>
}

impl EventBuilder {
    pub fn new() -> Self {
        EventBuilder {
            claims: Vec::new(),
            parents: HashSet::new(),
            claimset: 0,
            error: None
        }
    }

    pub fn parent<T: AsRef<[u8]>> (mut self, p: T) -> Self {
        let bytes = p.as_ref();
        self.parents.insert(bytes.to_vec());
        self
    }

    pub fn claim (mut self, c: Claim) -> Self {
        let bitmask = c.bitmask();
        let has_claim = bitmask & self.claimset > 0;
        if has_claim {
            match &c {
                Claim::Date(_) => {
                    self.error = Some(EventBuilderError::RepeatedDate)
                },
                _ => {}
            }
        }
        self.claims.push(c);
        self.claimset |= bitmask;
        self
    }

    pub fn sign<T, R>(self, signatory: T, sk: &SecretKey, store: &R) -> anyhow::Result<Event> where
        T: AsRef<str>,
        R: ReadableStore {
        if let Some(err) = self.error {
            return Err(err.into())
        }

        let mut event = Event {
            claimset: self.claimset,
            claims: self.claims,
            parents: self.parents.into_iter().collect(),
            signatory: String::from(signatory.as_ref()),
            signature: Vec::new()
        };

        let mut unsigned_event_bytes = Vec::new();
        let written = event.to_bytes_unsigned(&mut unsigned_event_bytes)?;
        let sig = sign_detached(&unsigned_event_bytes[..], sk);
        event.signature = sig.0.to_vec();

        // TODO: validation of the new signed event: are we an authority?
        // are our claims valid? etc.
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    #[test]
    fn varint_roundtrip_works() {
        let mut v = Vec::new();
        let expect = 0x80808080u64;
        write_varint(&mut v, expect).expect("failed to write_varint");
        let mut cursor = Cursor::new(&v[..]);
        let result = read_varint(&mut cursor).expect("failed to read_varint");
        assert!(expect == result);
    }

    #[test]
    fn eventbuilder_no_parents_test() {
        let (pk, sk) = sign::gen_keypair();
        let ev = EventBuilder::new()
            .claim(Claim::Date(1579825624495u64))
            .sign("Chris Dickinson <chris@neversaw.us>", &sk, &()).expect("failed to sign");

        println!("signed={:?}", ev);

        let mut buf = Vec::new();
        ev.to_bytes(&mut buf);
        println!("to_bytes={:?}", String::from_utf8_lossy(&buf[..]));

        let ev2 = Event::from_bytes(&buf[..]).expect("failed to marshal from bytes");
        println!("resurrected={:?}", ev2);

        assert!(ev.verify(&pk).expect("Failed to serialize 'ev' in order to verify"));
        assert!(ev2.verify(&pk).expect("Failed to serialize 'ev2' in order to verify"));
    }
}
