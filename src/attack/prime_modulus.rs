use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{Attack, AttackKind, AttackSpeed, Error, KeyError, Parameters, Solution};

/// N is a prime modulus attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeModulusAttack;

impl Attack for PrimeModulusAttack {
    fn name(&self) -> &'static str {
        "prime_modulus"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        if let (Some(n), Some(c)) = (&params.n, &params.c) {
            if n.is_probably_prime(100) == IsPrime::No {
                return Err(Error::NotFound);
            }

            let d = params
                .e
                .clone()
                .invert(&(n - Integer::from(1)))
                .or(Err(KeyError::PrivateExponentComputationFailed))?;
            let m = c.clone().pow_mod(&d, n).unwrap();

            return Ok(Solution::new_m(self.name(), m));
        }

        Err(Error::MissingParameters)
    }
}
