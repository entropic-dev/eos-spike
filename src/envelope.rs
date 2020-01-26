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
}
