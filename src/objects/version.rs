use crate::stores::ReadableStore;

pub struct Version {
    // NB: Why not a HashMap? We want to store these with a particular
    // order. We know that the paths will be sorted so lookup will be
    // log(N). BTreeMaps are also sorted with log(N) lookup, but
    // according to the docs have some pathological interactions with
    // cache misses.
    //
    // THAT SAID. If you are interested in speeding this up, please
    // prove me wrong! <3
    paths: Vec<(String, [u8; 32]>
}


impl Version {

    pub fn unpack_sync<P: AsRef<Path>, R: ReadableStore>(&self, destination: P, store: &R) -> Result<()> {
        // best version: paths -> unique dirnames -> reduced to those that don't start with the others
    }
}
