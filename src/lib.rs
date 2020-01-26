pub mod envelope;
pub mod errors;
pub mod objects;
pub mod stores;

pub trait PackageArg {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasArg<T: PackageArg + Clone + std::fmt::Debug + Eq + PartialEq> {
    name: String,
    package: T,
}
impl<T: PackageArg + Clone + std::fmt::Debug + Eq + PartialEq> PackageArg for AliasArg<T> {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
