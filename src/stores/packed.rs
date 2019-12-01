#[derive(Clone)]
pub struct PackedStore<D> {
    index: PackedIndex<D>,
    store: Objects<D>,
    phantom: PhantomData<D>
}
