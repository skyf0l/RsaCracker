use lazy_static::lazy_static;
use rug::Integer;

mod cube_root;
mod ecm;
mod fermat;
mod known_d;
mod known_factors;
mod known_phi;
mod leaked_crt_exponent;
mod pollard_p_1;
mod small_e;
mod small_prime;
mod sum_pq;
mod wiener;

use crate::key::PrivateKey;
use crate::Parameters;

pub use self::ecm::EcmAttack;
pub use cube_root::CubeRootAttack;
pub use fermat::FermatAttack;
pub use known_d::KnownDAttack;
pub use known_factors::KnownFactorsAttack;
pub use known_phi::KnownPhiAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use pollard_p_1::PollardP1Attack;
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
    /// Ket error
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
}

/// Solved RSA (private key, decrypted message)
pub type SolvedRsa = (Option<PrivateKey>, Option<Integer>);

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name(&self) -> &'static str;

    /// Run the attack
    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error>;
}

lazy_static! {
    /// List of attacks
    pub static ref ATTACKS: Vec<Box<dyn Attack + Sync>> = vec![
        Box::new(CubeRootAttack),
        Box::new(FermatAttack),
        Box::new(KnownDAttack),
        Box::new(KnownFactorsAttack),
        Box::new(KnownPhiAttack),
        Box::new(LeakedCrtExponentAttack),
        Box::new(PollardP1Attack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(SumPQAttack),
        Box::new(WienerAttack),
        Box::new(EcmAttack),
    ];
}
