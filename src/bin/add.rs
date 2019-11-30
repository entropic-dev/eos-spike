use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::WritableStore;
use entropic_object_store::object::Object;
use sha2::Sha256;
use digest::Digest;
use anyhow;

#[async_std::main]
async fn main () -> anyhow::Result<()> {
    let mut loose = LooseStore::<Sha256>::new("/Users/cdickinson/lol");
    let result = loose.add(Object::Blob("hello world")).await;
    println!("result={:?}", result);
    Ok(())
}
