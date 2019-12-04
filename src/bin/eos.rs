#![feature(async_closure)]
use anyhow::{self, bail};
use async_std::fs;
use async_std::prelude::*;
use colored::Colorize;
use digest::Digest;
use entropic_object_store::object::Object;
use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::packed::PackedStore;
use entropic_object_store::stores::{ReadableStore, WritableStore};
use futures::future::join_all;
use futures::prelude::*;
use sha2::Sha256;
use std::path::{Path, PathBuf};
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

async fn load_file<D: Digest + Send + Sync, S: WritableStore<D>>(
    store: &S,
    file: PathBuf,
) -> anyhow::Result<String> {
    match fs::read(&file).await {
        Err(e) => Ok(format!(
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

async fn cmd_add<D: Digest + Send + Sync, S: WritableStore<D>>(
    store: S,
    files: &Vec<PathBuf>,
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for file in files.iter().filter_map(|file| file.canonicalize().ok()) {
        results.push(load_file(&store, file));
    }

    for output in join_all(results).await {
        println!("{}", output?);
    }
    Ok(())
}

async fn cmd_get<S: ReadableStore>(store: S, hashes: &Vec<String>) -> anyhow::Result<()> {
    let cksize = Sha256::new().result().len();
    let valid_hashes: Vec<_> = hashes
        .iter()
        .filter_map(|xs| {
            let decoded = hex::decode(xs).ok()?;
            if decoded.len() != cksize {
                return None;
            }
            Some(decoded)
        })
        .collect();
    let cleaned_hashes: Vec<_> = valid_hashes.iter().map(|xs| hex::encode(xs)).collect();

    let mut results = Vec::new();
    for hash in valid_hashes {
        results.push(store.get(hash));
    }

    let results = join_all(results).await;
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
                println!("{} error reading hash", "ERR:".white().on_red());
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

    let mut packfile = destination.clone();
    let mut packindex = destination.clone();
    packfile.push("tmp");
    packfile.push("tmp-4700-pack");
    packindex.push("tmp");
    packindex.push("tmp-4700-idx");

    let packed = PackedStore::<Sha256>::new(packfile, packindex)?;

    let loose = LooseStore::<Sha256>::new(destination);
    match &eos.command {
        Command::Add { files } => cmd_add(loose, files).await?,
        Command::Get { hashes, backend } => match backend {
            Backends::Loose => cmd_get(loose, hashes).await?,
            Backends::Packed => cmd_get(packed, hashes).await?,
        },
        Command::Pack {} => loose.to_packed_store().await?,
    };
    Ok(())
}
