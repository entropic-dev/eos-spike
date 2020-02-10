use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{ PublicKey, SecretKey, SECRETKEYBYTES, PUBLICKEYBYTES };
use std::io::{Read, Write, Cursor, BufRead};
use anyhow::bail;
use std::fs;
use std::path::{ Path, PathBuf };

// machinery:
// we need host + username + pk/sk location per host
// can use defaults for pk/sk location (~/.ssh/id_ed25519{,pub})
// can use default for username (whoami)
// cannot use host default (maybe.)

fn load_public_key<T: AsRef<Path>>(src: T) -> anyhow::Result<PublicKey> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .create(false)
        .open(src.as_ref())?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    drop(file);

    match &data[0..12] {
        b"ssh-ed25519 " => {
            let sp = data[12..].iter().position(|&r| r == b' ');
            let decoded = base64::decode(&data[12..12 + sp.unwrap_or_else(|| data.len() - 12)])?;

            // 4 bytes typename length, typename, 4 bytes key length, key
            let mut dword_bytes = [0u8; 4];
            dword_bytes.copy_from_slice(&decoded[0..4]);
            let typename_len = u32::from_be_bytes(dword_bytes) as usize;
            if typename_len > decoded.len() - 4 {
                bail!("unexpected eof reading ssh key typename")
            }

            if &decoded[4..typename_len + 4] != b"ssh-ed25519" {
                bail!("unexpected type")
            }

            dword_bytes.copy_from_slice(&decoded[4 + typename_len..8 + typename_len]);
            let key_len = u32::from_be_bytes(dword_bytes) as usize;
            if key_len > decoded.len() - (8 + typename_len) {
                bail!("unexpected eof reading ssh key value")
            }

            match PublicKey::from_slice(&decoded[8 + typename_len..]) {
                Some(xs) => Ok(xs),
                None => bail!("failed to read public key bytes")
            }
        },
        _ => {
            bail!("unexpected leading text");
        }
    }
}

fn read_u32<R: Read>(cursor: &mut R) -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_bytestr<R: Read>(cursor: &mut R) -> anyhow::Result<Vec<u8>> {
    let size = read_u32(cursor)? as usize;
    let mut data = vec![0u8; size];
    cursor.read_exact(&mut data)?;
    Ok(data)
}

fn load_secret_key<T: AsRef<Path>>(src: T) -> anyhow::Result<SecretKey> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .create(false)
        .open(src.as_ref())?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    drop(file);

    let pemfile = pem::parse(&data[..])?;

    // auth-magic := "openssh-key-v1\00"
    // count := 4 byte LE len
    // string := count + (byte * count)
    // body := 
    //      auth-magic +
    //      string +            // cipher name
    //      string +            // kdfname
    //      string +            // kdfoptions
    //      count +             // int number of keys (1)
    //      (string * count) +  // publickey 1
    //      payload
    //
    // payload := (may be ciphered)
    //      uint * 2 +          // checksum (repeated)
    //      string +            // privatekey 1 pubkey algo
    //      string +            // privatekey 1 pubkey (again)
    //      string +            // privatekey 1 private key
    //      string +            // privatekey comment 1
    //      padding
    //
    // kdfoptions :=
    //      string +    // salt
    //      u32         // rounds
    let mut cursor = Cursor::new(&pemfile.contents[..]);

    const AUTHMAGIC: &[u8] = b"openssh-key-v1\0";
    let mut checkmagic = [0u8; AUTHMAGIC.len()];

    cursor.read_exact(&mut checkmagic)?;
    if checkmagic != AUTHMAGIC {
        bail!("unknown format");
    }

    let cipher = read_bytestr(&mut cursor)?;
    let kdfname = read_bytestr(&mut cursor)?;
    let kdfoptions = read_bytestr(&mut cursor)?;
    let count = read_u32(&mut cursor)?;
    if count != 1 {
        bail!("We can only handle a single key at a time.")
    }
    let pubkey = read_bytestr(&mut cursor)?;
    let rest = read_bytestr(&mut cursor)?;

    if cipher != b"none" {
        bail!("We do not support encrypted keys at this time. (Saw cipher={})", String::from_utf8_lossy(&cipher[..]))
    }

    if kdfname != b"none" {
        bail!("We do not support encrypted keys at this time. (Saw kdfname={})", String::from_utf8_lossy(&kdfname[..]))
    }


    let mut cursor = Cursor::new(&rest[..]);
    let cksum0 = read_u32(&mut cursor)?;
    let cksum1 = read_u32(&mut cursor)?;

    if cksum0 != cksum1 {
        bail!("Checksums did not match each other.")
    }

    let secret_key_algo = read_bytestr(&mut cursor)?;
    let secret_key_pub = read_bytestr(&mut cursor)?;
    let secret_key = read_bytestr(&mut cursor)?;
    let comment = read_bytestr(&mut cursor)?;

    match SecretKey::from_slice(&secret_key[..]) {
        Some(xs) => Ok(xs),
        None => bail!("failed to read secret key bytes")
    }
}

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
