#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod attack;
pub use attack::*;

/// Attack!
pub fn run_attacks(params: &Parameters) -> AttackResult {
    // SmallPrimeAttack::run(params)
    CubeRootAttack::run(params)
}
