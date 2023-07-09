use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, Error, Parameters, Solution};

/// Mersenne prime factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MersennePrimeAttack;

const MERSENNE_PRIMES: [u32; 51] = [
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
    9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433,
    1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20336011, 24036583, 25964951, 30402457,
    32582657, 37156667, 42643801, 43112609, 57885161, 74207281, 77232917, 82589933,
];

impl Attack for MersennePrimeAttack {
    fn name(&self) -> &'static str {
        "mersenne_prime"
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        for m in MERSENNE_PRIMES.iter() {
            let p: Integer = (Integer::from(1) << m) - 1;
            if p > *n {
                break;
            }
            if n.is_divisible(&p) {
                let q = n.clone() / &p;
                return Ok(Solution::new_pk(PrivateKey::from_factors(
                    &[p, q],
                    e.clone(),
                )?));
            }
        }
        Err(Error::NotFound)
    }
}
