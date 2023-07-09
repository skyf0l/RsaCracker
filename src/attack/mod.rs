use indicatif::ProgressBar;
use lazy_static::lazy_static;

mod brent;
mod cipolla;
mod cube_root;
mod ecm;
mod fermat;
mod known_d;
mod known_factors;
mod known_phi;
mod leaked_crt_coefficient;
mod leaked_crt_exponent;
mod leaked_pq;
mod pollard_p_1;
mod pollard_rho;
mod small_e;
mod small_prime;
mod sum_pq;
mod wiener;

use crate::{Parameters, Solution};

pub use self::ecm::EcmAttack;
pub use brent::BrentAttack;
pub use cipolla::CipollaAttack;
pub use cube_root::CubeRootAttack;
pub use fermat::FermatAttack;
pub use known_d::KnownDAttack;
pub use known_factors::KnownFactorsAttack;
pub use known_phi::KnownPhiAttack;
pub use leaked_crt_coefficient::LeakedCrtCoefficientAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use leaked_pq::LeakedPQAttack;
pub use pollard_p_1::PollardP1Attack;
pub use pollard_rho::PollardRhoAttack;
pub use small_e::SmallEAttack;
pub use small_prime::SmallPrimeAttack;
pub use sum_pq::SumPQAttack;
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

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name(&self) -> &'static str;

    /// Run the attack
    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error>;
}

lazy_static! {
    /// List of attacks
    pub static ref ATTACKS: Vec<Box<dyn Attack + Sync>> = vec![
        Box::new(CipollaAttack),
        Box::new(CubeRootAttack),
        Box::new(FermatAttack),
        Box::new(KnownDAttack),
        Box::new(KnownFactorsAttack),
        Box::new(KnownPhiAttack),
        Box::new(LeakedCrtCoefficientAttack),
        Box::new(LeakedCrtExponentAttack),
        Box::new(LeakedPQAttack),
        Box::new(PollardP1Attack),
        Box::new(PollardRhoAttack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(SumPQAttack),
        Box::new(WienerAttack),
        Box::new(EcmAttack),
        Box::new(BrentAttack),
    ];
}
