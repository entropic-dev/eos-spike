use entropic_object_store::keys::{ load_public_key, load_secret_key };
use sodiumoxide::crypto::sign;
use std::io::{Read, Write};

fn main() -> anyhow::Result<()> {
    let mut data = Vec::new();
    let mut base = dirs::home_dir().unwrap();
    base.push(".ssh");
    let mut secret_key_src = base.clone();
    secret_key_src.push("id_ed25519");
    let mut public_key_src = base;
    public_key_src.push("id_ed25519.pub");

    let (pk, sk) = (
        load_public_key(public_key_src)?,
        load_secret_key(secret_key_src)?
    );

    std::io::stdin().read_to_end(&mut data)?;

    let signed_data = sign::sign(&data[..], &sk);
    std::io::stdout().write_all(&signed_data[..]);
    let verified_data = sign::verify(&signed_data, &pk).unwrap();
    println!("roundtrip={:?}", String::from_utf8_lossy(&verified_data[..]));
    Ok(())
}
