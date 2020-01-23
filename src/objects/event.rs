use anyhow::bail;
use std::io::Write;
use sodiumoxide::crypto::sign::ed25519::{ PublicKey, PrivateKey };
use thiserror::Error;
use crate::stores::ReadableStore;

pub enum Claim {
    Date(String),
    Authority {
        action: enum { Add, Remove },
        public_key: String,
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
    Parent {
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
            Claim::Date(_) => 0x01,
            Claim::Authority(_) => 0x02,
            Claim::Yank(_) => 0x04,
            Claim::Unyank(_) => 0x08,
            Claim::Tag(_) => 0x10,
            Claim::Publication(_) => 0x20,
            Claim::Parent(_) => 0x40,
            Claim::Other(_) => 0x80,
        }
    }

    pub fn from_bytes<T: AsRef<[u8]> + Send> (bytes: T) -> anyhow::Result<Claim> {
        bail!("aw dang");
    }
}

pub struct Event {
    claims: Vec<Claim>,
    undersigned: String,
    signature: Vec<u8>
}

impl Event {
    pub fn from_bytes<T: AsRef<[u8]> + Send> (input: T) -> anyhow::Result<Self> {
        // signature type, null, payload type + len
        let bytes = input.as_ref();

        if bytes.len() < 1 {
            bail!("EOF while reading claimset mask");
        }

        let claimset = bytes[0];
        let mut idx = 1;
        let mut claims = Vec::new();
        while idx < bytes.len() {
            if bytes[idx] == 0 {
                // signature!
                idx += 1;
                break;
            }

            let mut expected_length = 0 as usize;
            let base = idx;
            // read while the high bit is set...
            while idx < bytes.len() && bytes[idx] & 0x80 > 0 {
                expected_length |= ((bytes[idx] & 0x7f) as usize) << ((idx - base) * 7);
                idx += 1;
            }
            if idx >= bytes.len() - 1 {
                bail!("unexpected eof while reading claim length");
            }

            // NB: there can be (at most) 128 different claim types. Anything over 128
            // runs into the expected_length varint.
            let claim = Claim::from_bytes(&bytes[idx..idx + expected_length])?;
            idx += expected_length;
            claims.push(claim);
        }
        let signature = Vec::from(&bytes[idx + 1..]);
        return Ok(Event {
            claims,
            signature
        })
    }

    pub fn to_bytes_unsigned<W: Write, T: AsMut<W>>(&self, destination: T) -> anyhow::Result<()> {
        let w = destination.as_mut();
        for claim in self.claims {
            claim.to_bytes(w);
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

#[derive(Error)]
enum EventBuilderError {
    RepeatedDate,
    AuthorityDoesNotExist,
    YankedVersionDoesNotExist,
    UnyankedVersionNotYanked,
    TaggedVersionDoesNotExist,
    ParentNotFound,
    AuthorityNameConflict
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

    pub fn claim (c: Claim) -> Self {
        
    }

    pub fn sign<T: AsRef<str>, R: AsRef<ReadableStore>>(name: T, private_key: &PrivateKey, store: R) -> Result<Event> {

    }
}
