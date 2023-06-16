#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod attack;
mod utils;

pub use attack::*;

/// Attack!
pub fn run_attacks(params: &Parameters) -> AttackResult {
    for attack in ATTACKS.iter() {
        println!("Running attack: {}", attack.name());
        match attack.run(params) {
            Ok((priv_key, m)) => {
                return Ok((priv_key, m));
            }
            Err(e) => {
                println!("=> Attack failed: {e}");
            }
        }
    }
    Err(Error::NotFound)
}
