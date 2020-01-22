#![feature(async_closure)]
use anyhow::{self, bail};
use async_std::{ fs, io };
use colored::Colorize;
use digest::Digest;
use entropic_object_store::object::Object;
use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::packed::PackedStore;
use entropic_object_store::stores::{ReadableStore, WritableStore};
use futures::future::{ select_all, join_all };
use sha2::Sha256;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;
use async_std::io::prelude::*;
use futures::future::FutureExt;

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
}

#[derive(StructOpt)]
#[structopt(about = "entropic object store: a testbed")]
struct Eos {
    #[structopt(short, parse(from_os_str))]
    dir: Option<PathBuf>,
    #[structopt(subcommand)]
    command: Command,
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
            let result = match store.add(Object::Blob(data)).await {
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
                Ok(format!("{} wrote {:?}", "OK: ".white().on_green(), file))
            } else {
                Ok(format!(
                    "{} already had {:?}",
                    "MU: ".white().on_purple(),
                    file
                ))
            }
        }
    }
}

async fn cmd_add<D: Digest + Send + Sync, S: WritableStore<D> + Send + Sync>(
    store: S,
    files: &[PathBuf],
) -> anyhow::Result<()> {

    let mut pending = Vec::new();
    for file in files.iter().filter_map(|file| file.canonicalize().ok()) {
        pending.push(load_file(&store, file).boxed());
    }

    let mut concurrent = pending.split_off(if pending.len() >= 1024 { pending.len() - 1024 } else { 0 });

    while concurrent.len() > 0 {
        let (result, _idx, rest) = select_all(concurrent).await;
        println!("{}", result?);
        concurrent = rest;
        if let Some(popped) = pending.pop() {
            concurrent.push(popped);
        }
    }

    Ok(())
}

async fn cmd_get<S: ReadableStore, T: AsRef<str>>(store: S, hashes: &[T]) -> anyhow::Result<()> {
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
    let mut concurrent = pending.split_off(if pending.len() >= 1024 { pending.len() - 1024 } else { 0 });

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
                        println!("{} got {}", "OK: ".white().on_green(), obj.to_string());
                        //::std::io::Write::write_all(&mut ::std::io::stdout(), obj.bytes());
                    }
                    None => {
                        println!(
                            "{} could not find that hash ({})",
                            "MU: ".white().on_purple(),
                            cleaned_hashes[idx]
                        );
                    }
                }
            }
            Err(_e) => {
                dbg!(_e);
                println!("{} error reading hash {}", "ERR:".white().on_red(), idx);
            }
        }
    }

    Ok(())
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let eos = Eos::from_args();
    let destination = eos.dir.unwrap_or_else(|| {
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
                processed_files = std::str::from_utf8(&data)?.trim().split("\n").map(|xs| PathBuf::from(xs)).collect()
            } else {
                processed_files = files.clone();
            }
            cmd_add(loose, &processed_files).await?
        },
        Command::Get { hashes, backend } => match backend {
            Backends::Loose => cmd_get(loose, &hashes[..]).await?,
            Backends::Packed => cmd_get(packfiles, &hashes[..]).await?,
        },
        Command::GetAll { hashfile, backend } => {
            let data = fs::read(&hashfile).await?;
            let hashes: Vec<_> = std::str::from_utf8(&data)?.trim().split("\n").collect();
            match backend {
                Backends::Loose => cmd_get(loose, &hashes[..]).await?,
                Backends::Packed => cmd_get(packfiles, &hashes[..]).await?,
            }
        },
        Command::Pack {} => loose.to_packed_store().await?,
    };
    Ok(())
}
