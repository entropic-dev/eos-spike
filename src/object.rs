use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum Object<T: AsRef<[u8]> + Send> {
    Blob(T),
    Version(T),
    Event(T),
}

// impl<T: AsRef<[u8]>> FromStr for Object<T> {
//     type Err = ObjectStoreError;
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "blob" =>
//         }
//     }
// }

impl<T: AsRef<[u8]> + Send> Display for Object<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self {
            Object::Blob(_) => write!(f, "blob"),
            Object::Version(_) => write!(f, "vers"),
            Object::Event(_) => write!(f, "sign"),
        }
    }
}

impl<T: AsRef<[u8]> + Send> Object<T> {
    pub fn bytes(&self) -> &T {
        match &self {
            Object::Blob(x) => x,
            Object::Version(x) => x,
            Object::Event(x) => x,
        }
    }
}
