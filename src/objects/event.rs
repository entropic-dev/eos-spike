use anyhow::bail;
use std::io::Write;

pub enum Attestation {
    Date(String),
    OriginSet {
        hostname: String,
        public_key: String
    },
    AuthorityAdd {
        public_key: String
    },
    AuthorityRemove {
        public_key: String,
    },
    Yank {
        version: String,
        reason: String
    },
    Unyank {
        version: String
    },
    TagSet {
        tag: String,
        version: String
    },
    TagRemove {
        tag: String
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

impl Attestation {
    pub fn from_bytes<T: AsRef<[u8]> + Send> (bytes: T) -> anyhow::Result<Attestation> {
        bail!("aw dang");
    }
}

pub struct Event {
    attestations: Vec<Attestation>,
    signature: Vec<u8>
}

impl Event {
    pub fn from_bytes<T: AsRef<[u8]> + Send> (input: T) -> anyhow::Result<Self> {
        // signature type, null, payload type + len
        let bytes = input.as_ref();
        let mut idx = 0;
        let mut attestations = Vec::new();
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
                bail!("unexpected eof while reading attestation length");
            }

            // NB: there can be (at most) 128 different attestation types. Anything over 128
            // runs into the expected_length varint.
            let attestation = Attestation::from_bytes(&bytes[idx..idx + expected_length])?;
            idx += expected_length;
            attestations.push(attestation);
        }
        let signature = Vec::from(&bytes[idx + 1..]);
        return Ok(Event {
            attestations,
            signature
        })
    }

    pub fn to_bytes_unsigned<W: Write, T: AsMut<W>>(&self, destination: T) -> anyhow::Result<()> {
        let w = destination.as_mut();
        for attestation in self.attestations {
            attestation.to_bytes(w);
        }
        Ok(())
    }

    pub fn to_bytes<W: Write, T: AsMut<W>>(&self, destination: T) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn verify<T: AsRef<[sodiumoxide::crypto::sign::ed25519::PublicKey]>>(&self, keys: T) -> bool {
        false
    }
}

// Turn a list of attestations into a signed event
// impl From<Vec<Attestation>> for Event {
//
// }
