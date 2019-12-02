#![feature(async_closure)]
use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::{ReadableStore, WritableStore};
use entropic_object_store::object::Object;
use sha2::Sha256;
use digest::Digest;
use anyhow;
use structopt::{ StructOpt };
use std::path::{ Path, PathBuf };
use colored::Colorize;
use async_std::fs;
use async_std::prelude::*;
use futures::prelude::*;
use futures::future::{join_all};

#[derive(StructOpt)]
enum Command {
    Add {
        #[structopt(parse(from_os_str))]
        files: Vec<PathBuf>
    },
    Get {
        hashes: Vec<String>
    },
    Pack {
    }
}

#[derive(StructOpt)]
#[structopt(about = "entropic object store: a testbed")]
struct Eos {
    #[structopt(short, parse(from_os_str))]
    dir: Option<PathBuf>,
    #[structopt(subcommand)]
    command: Command
}

async fn load_file(store: &LooseStore<Sha256>, file: PathBuf) -> anyhow::Result<String> {
    match fs::read(&file).await {
        Err(e) => {
            Ok(format!("{} failed to read {:?}", "ERR:".black().on_red(), file))
        },
        Ok(data) => {
            let result = match store.add(Object::Blob(data)).await {
                Err(_e) => return Ok(format!("{} failed to write {:?}", "ERR:".black().on_red(), file)),
                Ok(f) => f
            };

            if result {
                Ok(format!("{} wrote {:?}", "OK: ".white().on_green(), file))
            } else {
                Ok(format!("{} already had {:?}", "MU: ".white().on_purple(), file))
            }
        }
    }
}

async fn cmd_add(store: LooseStore<Sha256>, files: &Vec<PathBuf>) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for file in files.iter().filter_map(|file| {
        file.canonicalize().ok()
    }) {
        results.push(load_file(&store, file));
    }

    for output in join_all(results).await {
        println!("{}", output?);
    }
    Ok(())
}

async fn cmd_get(store: LooseStore<Sha256>, hashes: &Vec<String>) -> anyhow::Result<()> {
    let cksize = Sha256::new().result().len();
    let valid_hashes: Vec<_> = hashes.iter().filter_map(|xs| {
        let decoded = hex::decode(xs).ok()?;
        if decoded.len() != cksize {
            return None
        }
        Some(decoded)
    }).collect();

    let mut results = Vec::new();
    for hash in valid_hashes {
        results.push(store.get(hash));
    }

    let results = join_all(results).await;
    for object in results {
        match object {
            Ok(opt) => {
                match opt {
                    Some(obj) => {
                        println!("{} got {}", "OK: ".white().on_green(), obj.to_string());
                    },
                    None => {
                        println!("{} could not find that hash", "MU: ".white().on_purple());

                    }
                }
            },
            Err(_e) => {
                dbg!(_e);
                println!("{} error reading hash", "ERR:".white().on_red());
            }
        }
    }

    Ok(())
}

#[async_std::main]
async fn main () -> anyhow::Result<()> {
    let eos = Eos::from_args();
    let destination = eos.dir.unwrap_or_else(|| {
        let mut pb = dirs::home_dir().unwrap();
        pb.push(".eos");
        pb
    });

    let loose = LooseStore::<Sha256>::new(destination);
    match &eos.command {
        Command::Add { files } => cmd_add(loose, files).await?,
        Command::Get { hashes } => cmd_get(loose, hashes).await?,
        Command::Pack { } => loose.to_packed_store().await?
    };
    Ok(())
}
