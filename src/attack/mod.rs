use indicatif::ProgressBar;
use lazy_static::lazy_static;
use std::sync::Arc;

mod cipolla;
mod comfact_cn;
mod cube_root;
mod factorization;
mod gaa;
mod known_d;
mod known_phi;
mod leaked_crt_coefficient;
mod leaked_crt_exponent;
mod leaked_crt_exponents;
mod leaked_pq;
mod non_coprime_exp;
mod partial_d;
mod prime_modulus;
mod small_e;
mod sum_pq;
mod wiener;

use crate::Factors;
use crate::{Parameters, Solution};

pub use cipolla::CipollaAttack;
pub use comfact_cn::ComfactCnAttack;
pub use cube_root::CubeRootAttack;
pub use factorization::*;
pub use gaa::GaaAttack;
pub use known_d::KnownDAttack;
pub use known_phi::KnownPhiAttack;
pub use leaked_crt_coefficient::LeakedCrtCoefficientAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use leaked_crt_exponents::LeakedCrtExponentsAttack;
pub use leaked_pq::LeakedPQAttack;
pub use non_coprime_exp::NonCoprimeExpAttack;
pub use partial_d::PartialDAttack;
pub use prime_modulus::PrimeModulusAttack;
pub use small_e::SmallEAttack;
pub use sum_pq::SumPQAttack;
pub use wiener::WienerAttack;

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Missing parameters
    #[error("Missing parameters")]
    MissingParameters,
    /// Unsuccessful attack
    #[error("Unsuccessful attack")]
    NotFound,
    /// Key error
    #[error(transparent)]
    Key(crate::key::KeyError),
    /// Partial factorization
    #[error("Partial factorization: {0:?}")]
    PartialFactorization(Factors),
}

impl From<crate::key::KeyError> for Error {
    fn from(e: crate::key::KeyError) -> Self {
        match e {
            crate::key::KeyError::FactorsAreNotPrimeNumbers(factors) => {
                Error::PartialFactorization(factors)
            }
            _ => Error::Key(e),
        }
    }
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

/// Attack kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackKind {
    /// Factorization attack requiring only n
    Factorization,
    /// Attack depending on knowing extra information (e.g. d, phi, p, q, etc.)
    KnownExtraInformation,
}

impl PartialOrd for AttackKind {
    fn partial_cmp(&self, other: &AttackKind) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AttackKind {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use crate::AttackKind::{Factorization, KnownExtraInformation};
        use std::cmp::Ordering::*;

        match (self, other) {
            (Factorization, Factorization) | (KnownExtraInformation, KnownExtraInformation) => {
                Equal
            }
            (KnownExtraInformation, _) => Less,
            (_, KnownExtraInformation) => Greater,
        }
    }
}

/// Abstract attack trait
pub trait Attack: std::fmt::Debug {
    /// Returns the attack name
    fn name(&self) -> &'static str;

    /// Returns the attack speed
    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    /// Returns the attack kind
    fn kind(&self) -> AttackKind {
        AttackKind::Factorization
    }

    /// Runs the attack
    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error>;
}

lazy_static! {
    static ref _ATTACKS: Vec<Arc<dyn Attack + Sync + Send>> = vec![
        Arc::new(CipollaAttack),
        Arc::new(ComfactCnAttack),
        Arc::new(CubeRootAttack),
        Arc::new(GaaAttack),
        Arc::new(KnownDAttack),
        Arc::new(KnownPhiAttack),
        Arc::new(LeakedCrtCoefficientAttack),
        Arc::new(LeakedCrtExponentAttack),
        Arc::new(LeakedCrtExponentsAttack),
        Arc::new(LeakedPQAttack),
        Arc::new(NonCoprimeExpAttack),
        Arc::new(PartialDAttack),
        Arc::new(PrimeModulusAttack),
        Arc::new(SmallEAttack),
        Arc::new(SumPQAttack),
        Arc::new(WienerAttack),
    ];

    /// List of attacks
    pub static ref ATTACKS: Vec<Arc<dyn Attack + Sync + Send>> = {
        let mut attacks = _ATTACKS.to_vec();
        attacks.extend_from_slice(&FACTORIZATION_ATTACKS);
        attacks
    };
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn unique_attacks() {
        // Check if all attacks have unique names (no duplicates)
        let mut attacks = ATTACKS.to_vec();
        attacks.sort_by(|a, b| a.name().cmp(b.name()));

        for (i, attack) in attacks.iter().enumerate() {
            if i > 0 {
                assert!(
                    attack.name() != attacks[i - 1].name(),
                    "Duplicated attack: {}",
                    attack.name()
                );
            }
        }
    }
}
