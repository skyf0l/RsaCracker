use clap::{command, Parser, Subcommand};
use main_error::MainError;

use rsacracker::attack;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[clap(flatten)]
    options: Options,
    /// Subcommands.
    #[command(subcommand)]
    subcommand: SubCommand,
}

/// Options.
#[derive(Parser, Debug, Clone)]
struct Options {}

/// Subcommands.
#[derive(Subcommand, Debug, Clone)]
enum SubCommand {}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), MainError> {
    let _args = Args::parse();

    attack();

    Ok(())
}
