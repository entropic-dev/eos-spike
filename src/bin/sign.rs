use sodiumoxide::crypto::sign;
use std::io::{ Read, Write };

fn main() -> anyhow::Result<()> {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    let (pk, sk) = sign::gen_keypair();
    let signed_data = sign::sign(&data[..], &sk);
    std::io::stdout().write_all(&signed_data[..]);
    // let verified_data = sign::verify(&signed_data, &pk).unwrap();
    Ok(())
}
