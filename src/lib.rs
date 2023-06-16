#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod attack;
pub use attack::*;

/// Attack!
pub fn run_attacks(params: &Parameters) -> AttackResult {
    for attack in ATTACKS.iter() {
        println!("Running attack: {}", attack.name());
        match attack.run(params) {
            Ok((priv_key, m)) => {
                if let Some(priv_key) = &priv_key {
                    println!("=> Found private key: {priv_key:?}");
                }
                if let Some(m) = &m {
                    println!("=> Found message: {m:?}");
                }
                return Ok((priv_key, m));
            }
            Err(e) => {
                println!("=> Attack failed: {e}");
            }
        }
    }
    Err(Error::NotFound)
}
