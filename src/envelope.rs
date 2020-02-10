use sha2::Digest;
use std::fmt::{Display, Formatter, Result as FmtResult};
#[derive(Debug)]
pub enum Envelope<T: AsRef<[u8]> + Send> {
    Blob(T),
    Version(T),
    Event(T),
}

impl<T: AsRef<[u8]> + Send> Display for Envelope<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self {
            Envelope::Blob(_) => write!(f, "blob"),
            Envelope::Version(_) => write!(f, "vers"),
            Envelope::Event(_) => write!(f, "sign"),
        }
    }
}

impl<T: AsRef<[u8]> + Send> Envelope<T> {
    pub fn payload_bytes(&self) -> &T {
        match &self {
            Envelope::Blob(x) => x,
            Envelope::Version(x) => x,
            Envelope::Event(x) => x,
        }
    }

    // TODO: rip out all the "generic digest" stuff. It's kudzu.
    pub fn content_address<D: 'static + Digest + Send + Sync>(&self) -> ([u8; 32], String) {
        let mut digest = D::new();
        let item = self.payload_bytes().as_ref();
        let header = format!("{} {}\0", self.to_string(), item.len());
        digest.input(&header);
        digest.input(item);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest.result()[..]);
        (bytes, header)
    }
}
