#![feature(async_closure)]
use entropic_object_store::stores::loose::LooseStore;
use entropic_object_store::stores::WritableStore;
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

async fn load_file(store: &LooseStore<Sha256>, file: PathBuf) -> anyhow::Result<()> {
    match fs::read(&file).await {
        Err(e) => {
            println!("{} failed to write {:?}", "ERR:".black().on_red(), file);
        },
        Ok(data) => {
            println!("{} wrote {:?}", "OK:".white().on_green(), file);
            store.add(Object::Blob(data)).await;
        }
    };
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
        Command::Add { files } => {
            let mut results = Vec::new();

            for file in files.iter().filter_map(|file| {
                file.canonicalize().ok()
            }) {
                results.push(load_file(&loose, file));
            }

            join_all(results).await
        }
    };
    Ok(())
}
