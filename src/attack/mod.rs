use indicatif::ProgressBar;
use lazy_static::lazy_static;

mod brent;
mod cipolla;
mod comfact_cn;
mod cube_root;
mod cunningham_chain;
mod ecm;
mod fermat;
mod gaa;
mod hart;
mod known_d;
mod known_factors;
mod known_phi;
mod kraitchik;
mod leaked_crt_coefficient;
mod leaked_crt_exponent;
mod leaked_crt_exponents;
mod leaked_pq;
mod londahl;
mod mersenne_prime;
mod pollard_pm1;
mod pollard_rho;
mod power;
mod sequence;
mod small_e;
mod small_prime;
mod sparse;
mod squfof;
mod sum_pq;
mod twin_prime;
mod wiener;

use crate::{Parameters, Solution};

pub use self::ecm::EcmAttack;
pub use brent::BrentAttack;
pub use cipolla::CipollaAttack;
pub use comfact_cn::ComfactCnAttack;
pub use cube_root::CubeRootAttack;
pub use cunningham_chain::CunninghamChainAttack;
pub use fermat::FermatAttack;
pub use gaa::GaaAttack;
pub use hart::HartAttack;
pub use known_d::KnownDAttack;
pub use known_factors::KnownFactorsAttack;
pub use known_phi::KnownPhiAttack;
pub use kraitchik::KraitchikAttack;
pub use leaked_crt_coefficient::LeakedCrtCoefficientAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use leaked_crt_exponents::LeakedCrtExponentsAttack;
pub use leaked_pq::LeakedPQAttack;
pub use londahl::LondahlAttack;
pub use mersenne_prime::MersennePrimeAttack;
pub use pollard_pm1::PollardPM1Attack;
pub use pollard_rho::PollardRhoAttack;
pub use power::PowerAttack;
pub use sequence::FibonacciGcdAttack;
pub use sequence::LucasGcdAttack;
pub use small_e::SmallEAttack;
pub use small_prime::SmallPrimeAttack;
pub use sparse::SparseAttack;
pub use squfof::SqufofAttack;
pub use sum_pq::SumPQAttack;
pub use twin_prime::TwinPrimeAttack;
pub use wiener::WienerAttack;

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Missing parameters
    #[error("missing parameters")]
    MissingParameters,
    /// Unsuccessful attack
    #[error("unsuccessful attack")]
    NotFound,
    /// Key error
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
}

/// Attack speed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackSpeed {
    /// Fast attack (less than 1s)
    Fast,
    /// Medium attack (few seconds)
    Medium,
    /// Slow attack (more than 30 seconds)
    Slow,
}

impl PartialOrd for AttackSpeed {
    fn partial_cmp(&self, other: &AttackSpeed) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AttackSpeed {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use crate::AttackSpeed::{Fast, Medium, Slow};
        use std::cmp::Ordering::*;

        match (self, other) {
            (Fast, Fast) | (Medium, Medium) | (Slow, Slow) => Equal,
            (Fast, _) => Less,
            (_, Fast) => Greater,
            (Medium, _) => Less,
            (_, Medium) => Greater,
        }
    }
}

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name(&self) -> &'static str;

    /// Get the attack speed
    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    /// Run the attack
    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error>;
}

lazy_static! {
    /// List of attacks
    pub static ref ATTACKS: Vec<Box<dyn Attack + Sync>> = vec![
        Box::new(BrentAttack),
        Box::new(CipollaAttack),
        Box::new(ComfactCnAttack),
        Box::new(CubeRootAttack),
        Box::new(CunninghamChainAttack),
        Box::new(EcmAttack),
        Box::new(FermatAttack),
        Box::new(GaaAttack),
        Box::new(HartAttack),
        Box::new(KnownDAttack),
        Box::new(KnownFactorsAttack),
        Box::new(KnownPhiAttack),
        Box::new(KraitchikAttack),
        Box::new(LeakedCrtCoefficientAttack),
        Box::new(LeakedCrtExponentAttack),
        Box::new(LeakedCrtExponentsAttack),
        Box::new(LeakedPQAttack),
        Box::new(LondahlAttack),
        Box::new(MersennePrimeAttack),
        Box::new(PollardPM1Attack),
        Box::new(PollardRhoAttack),
        Box::new(PowerAttack),
        Box::new(sequence::FactorialGcdAttack),
        Box::new(sequence::FermatGcdAttack),
        Box::new(sequence::FibonacciGcdAttack),
        Box::new(sequence::JacobsthalGcdAttack),
        Box::new(sequence::LucasGcdAttack),
        Box::new(sequence::MersenneGcdAttack),
        Box::new(sequence::PrimorialGcdAttack),
        Box::new(sequence::XYGcdAttack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(SparseAttack),
        Box::new(SqufofAttack),
        Box::new(SumPQAttack),
        Box::new(TwinPrimeAttack),
        Box::new(WienerAttack),
    ];
}
