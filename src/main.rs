use anyhow::Result;
use clap::Parser;

mod backup;
mod check;
mod cli;
mod config;
mod notification;
mod restic;
mod stats;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await
}
