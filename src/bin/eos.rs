#![feature(async_closure)]
use anyhow::{self, bail};
use async_std::io::prelude::*;
use async_std::{fs, io};
use colored::Colorize;
use digest::Digest;
use entropic_object_store::objects::event::{ EventBuilder, Claim };
use entropic_object_store::envelope::Envelope;
use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::packed::PackedStore;
use entropic_object_store::stores::{ReadableStore, WritableStore};
use entropic_object_store::keys::{ load_public_key, load_secret_key };
use futures::future::FutureExt;
use futures::future::{join_all, select_all};
use sha2::Sha256;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

enum Backends {
    Loose,
    Packed,
}

impl FromStr for Backends {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "loose" => Ok(Backends::Loose),
            "packed" => Ok(Backends::Packed),
            s => bail!("not a recognized backed: \"{}\"", s),
        }
    }
}

impl Eos {
    fn log<T: AsRef<str>>(&self, s: T) -> anyhow::Result<()> {
        if !self.quiet {
            println!("{}", s.as_ref());
        }
        Ok(())
    }

    fn error<T: AsRef<str>>(&self, s: T) -> anyhow::Result<()> {
        if !self.quiet {
            eprintln!("{}", s.as_ref());
        }
        Ok(())
    }
}

#[derive(StructOpt)]
enum Command {
    Add {
        #[structopt(parse(from_os_str))]
        files: Vec<PathBuf>,
    },
    Get {
        hashes: Vec<String>,
        #[structopt(short, long, default_value = "loose")]
        backend: Backends,
    },
    GetAll {
        hashfile: PathBuf,
        #[structopt(short, long, default_value = "loose")]
        backend: Backends,
    },
    Pack {},
    Snapshot {
        #[structopt(short, long)]
        comment: Option<String>,
        parent: Option<String>
    }
}

#[derive(StructOpt)]
#[structopt(about = "entropic object store: a testbed")]
struct Eos {
    #[structopt(short, parse(from_os_str))]
    dir: Option<PathBuf>,
    #[structopt(short)]
    parent: Option<String>,
    #[structopt(subcommand)]
    command: Command,
    #[structopt(short, long)]
    quiet: bool,
}

async fn load_file<D: Digest + Send + Sync, S: WritableStore<D> + Send + Sync>(
    store: &S,
    file: PathBuf,
) -> anyhow::Result<String> {
    match fs::read(&file).await {
        Err(_) => Ok(format!(
            "{} failed to read {:?}",
            "ERR:".black().on_red(),
            file
        )),
        Ok(data) => {
            let blob = Envelope::Blob(data);
            let (content_address, _) = blob.content_address::<Sha256>();
            let result = match store.add(blob).await {
                Err(_e) => {
                    return Ok(format!(
                        "{} failed to write {:?}",
                        "ERR:".black().on_red(),
                        file
                    ))
                }
                Ok(f) => f,
            };

            if result {
                Ok(format!("{}", hex::encode(content_address).white().on_green()))
            } else {
                Ok(format!("{}", hex::encode(content_address).white().on_purple()))
            }
        }
    }
}

async fn cmd_add<D: Digest + Send + Sync, S: WritableStore<D> + Send + Sync>(
    eos: &Eos,
    store: S,
    files: &[PathBuf],
) -> anyhow::Result<()> {
    let mut pending = Vec::new();
    for file in files.iter().filter_map(|file| file.canonicalize().ok()) {
        pending.push(load_file(&store, file).boxed());
    }

    let mut concurrent = pending.split_off(if pending.len() >= 1024 {
        pending.len() - 1024
    } else {
        0
    });

    while concurrent.len() > 0 {
        let (result, _idx, rest) = select_all(concurrent).await;
        eos.log(format!("{}", result?));
        concurrent = rest;
        if let Some(popped) = pending.pop() {
            concurrent.push(popped);
        }
    }

    Ok(())
}

async fn cmd_get<S: ReadableStore, T: AsRef<str>>(eos: &Eos, store: S, hashes: &[T]) -> anyhow::Result<()> {
    let cksize = Sha256::new().result().len();
    let valid_hashes: Vec<_> = hashes
        .iter()
        .filter_map(|xs| {
            let decoded = hex::decode(xs.as_ref()).ok()?;
            if decoded.len() != cksize {
                return None;
            }
            Some(decoded)
        })
        .collect();
    let cleaned_hashes: Vec<_> = valid_hashes.iter().map(hex::encode).collect();

    let mut pending = Vec::new();
    for hash in valid_hashes {
        pending.push(store.get(hash));
    }

    let mut results = Vec::with_capacity(pending.len());
    let mut concurrent = pending.split_off(if pending.len() >= 1024 {
        pending.len() - 1024
    } else {
        0
    });

    while pending.len() > 0 {
        let (result, _idx, rest) = select_all(concurrent).await;
        results.push(result);
        concurrent = rest;
        if let Some(popped) = pending.pop() {
            concurrent.push(popped);
        }
    }

    let last_chunk = join_all(concurrent).await;
    results.extend(last_chunk);

    for (idx, object) in results.iter().enumerate() {
        match object {
            Ok(opt) => {
                match opt {
                    Some(obj) => {
                        eos.log(format!("{} got {}", "OK: ".white().on_green(), obj.to_string()));
                        // ::std::io::Write::write_all(&mut ::std::io::stdout(), obj.bytes());
                    }
                    None => {
                        eos.error(format!(
                            "{} could not find that hash ({})",
                            "MU: ".white().on_purple(),
                            cleaned_hashes[idx]
                        ));
                    }
                }
            }
            Err(_e) => {
                eos.error(format!("{} error reading hash {}", "ERR:".white().on_red(), idx));
            }
        }
    }

    Ok(())
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let eos = Eos::from_args();
    let destination = eos.dir.clone().unwrap_or_else(|| {
        let mut pb = dirs::home_dir().unwrap();
        pb.push(".eos");
        pb
    });

    let packfiles = PackedStore::<Sha256>::load_all(&destination)?;
    let loose = LooseStore::<Sha256>::new(destination);

    match &eos.command {
        Command::Add { files } => {
            let processed_files;
            if files.len() == 1 && files[0].to_string_lossy() == "-" {
                let mut data = Vec::new();
                io::stdin().read_to_end(&mut data).await?;
                processed_files = std::str::from_utf8(&data)?
                    .trim()
                    .split("\n")
                    .map(|xs| PathBuf::from(xs))
                    .collect()
            } else {
                processed_files = files.clone();
            }
            cmd_add(&eos, loose, &processed_files).await?
        }
        Command::Get { hashes, backend } => match backend {
            Backends::Loose => cmd_get(&eos, loose, &hashes[..]).await?,
            Backends::Packed => cmd_get(&eos, packfiles, &hashes[..]).await?,
        },
        Command::GetAll { hashfile, backend } => {
            let data = fs::read(&hashfile).await?;
            let hashes: Vec<_> = std::str::from_utf8(&data)?.trim().split("\n").collect();
            match backend {
                Backends::Loose => cmd_get(&eos, loose, &hashes[..]).await?,
                Backends::Packed => cmd_get(&eos, packfiles, &hashes[..]).await?,
            }
        }
        Command::Pack {} => loose.to_packed_store().await?,
        Command::Snapshot { comment, parent } => {
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

            let comment = comment.clone().unwrap_or_else(|| "".to_string());
            let comment_bytes: Vec<_> = comment.bytes().collect();
            let mut ev = EventBuilder::new()
                .claim(Claim::Other {
                    typeno: 0x80,
                    data: comment_bytes
                });

            if let Some(p) = parent {
                let decoded = hex::decode(p)?;
                if decoded.len() != 32 {
                    bail!("Please pass a 64-byte hex parent value");
                }
                ev = ev.parent(decoded)
            }
            let signed = ev.sign("Chris Dickinson <chris@neversaw.us>", &sk, &())?;
            let mut buf = Vec::new();
            signed.to_bytes(&mut buf);
            let envelope = Envelope::Event(buf);
            let (content_address, _) = envelope.content_address::<Sha256>();
            loose.add(envelope).await?;
            println!("{}", hex::encode(content_address));
        }
    };
    Ok(())
}
