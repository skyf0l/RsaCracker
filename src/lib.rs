#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod attack;
mod ntheory;
mod utils;

pub use attack::*;

/// Attack!
pub fn run_attacks(params: &Parameters) -> AttackResult {
    for attack in ATTACKS.iter() {
        println!("Running attack: {}", attack.name());
        match attack.run(params) {
            Ok((private_key, m)) => {
                println!("=> Attack successful!");

                // If we have a private key and a cipher message, decrypt it
                let m = if let (Some(private_key), Some(c), None) = (&private_key, &params.c, &m) {
                    Some(private_key.decrypt(c))
                } else {
                    m
                };
                return Ok((private_key, m));
            }
            Err(e) => {
                println!("=> Attack failed: {e}");
            }
        }
    }
    Err(Error::NotFound)
}
