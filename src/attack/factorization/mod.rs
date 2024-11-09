use std::sync::Arc;

use lazy_static::lazy_static;

mod brent;
mod cunningham_chain;
mod ecm;
mod factordb;
mod fermat;
mod hart;
mod known_factors;
mod kraitchik;
mod londahl;
mod mersenne_prime;
mod pollard_pm1;
mod pollard_rho;
mod power;
mod sequence;
mod small_prime;
mod sparse;
mod squfof;
mod twin_prime;

pub use self::ecm::EcmAttack;
pub use brent::BrentAttack;
pub use cunningham_chain::CunninghamChainAttack;
pub use factordb::FactorDbAttack;
pub use fermat::FermatAttack;
pub use hart::HartAttack;
pub use known_factors::KnownFactorsAttack;
pub use kraitchik::KraitchikAttack;
pub use londahl::LondahlAttack;
pub use mersenne_prime::MersennePrimeAttack;
pub use pollard_pm1::PollardPM1Attack;
pub use pollard_rho::PollardRhoAttack;
pub use power::PowerAttack;
pub use sequence::*;
pub use small_prime::SmallPrimeAttack;
pub use sparse::SparseAttack;
pub use squfof::SqufofAttack;
pub use twin_prime::TwinPrimeAttack;

use crate::Attack;

lazy_static! {
    static ref _ATTACKS: Vec<Arc<dyn Attack + Sync + Send>> = vec![
        Arc::new(BrentAttack),
        Arc::new(CunninghamChainAttack),
        Arc::new(EcmAttack),
        Arc::new(FactorDbAttack),
        Arc::new(FermatAttack),
        Arc::new(HartAttack),
        Arc::new(KnownFactorsAttack),
        Arc::new(KraitchikAttack),
        Arc::new(LondahlAttack),
        Arc::new(MersennePrimeAttack),
        Arc::new(PollardPM1Attack),
        Arc::new(PollardRhoAttack),
        Arc::new(PowerAttack),
        Arc::new(SmallPrimeAttack),
        Arc::new(SparseAttack),
        Arc::new(SqufofAttack),
        Arc::new(TwinPrimeAttack),
    ];

    /// List of attacks
    pub static ref FACTORIZATION_ATTACKS: Vec<Arc<dyn Attack + Sync + Send>> = {
        let mut attacks = _ATTACKS.to_vec();
        attacks.extend_from_slice(&SEQUENCE_ATTACKS);
        attacks
    };
}
