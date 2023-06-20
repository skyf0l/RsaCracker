#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use rug::Integer;

mod attack;
mod ntheory;
mod utils;

pub use attack::*;

/// Convert a `rug::Integer` to a byte vector.
pub fn integer_to_bytes(i: &Integer) -> Vec<u8> {
    base_x::decode("0123456789", &i.to_string()).unwrap()
}

/// Convert a `rug::Integer` to a string.
pub fn integer_to_string(i: &Integer) -> Option<String> {
    String::from_utf8(integer_to_bytes(i)).ok()
}

/// Attack!
pub fn run_attacks(params: &Parameters) -> Option<SolvedRsa> {
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
                return Some((private_key, m));
            }
            Err(e) => {
                println!("=> Attack failed: {e}");
            }
        }
    }
    None
}
