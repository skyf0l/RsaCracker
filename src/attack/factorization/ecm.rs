use std::collections::HashMap;

use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

const MAX_DEEP: usize = 4;

const OPTIMAL_B1: [usize; 12] = [
    2000,       // 15 digits
    11000,      // 20 digits
    50000,      // 25 digits
    250000,     // 30 digits
    1000000,    // 35 digits
    3000000,    // 40 digits
    11000000,   // 45 digits
    44000000,   // 50 digits
    110000000,  // 55 digits
    260000000,  // 60 digits
    850000000,  // 65 digits
    2900000000, // 70 digits
];

fn ecm(
    n: &Integer,
    pb: Option<&ProgressBar>,
    seed: usize,
    deep: usize,
) -> Result<HashMap<Integer, usize>, Error> {
    if deep == MAX_DEEP {
        return Ok(HashMap::from([(n.clone(), 1)]));
    }

    if let Some(pb) = pb {
        pb.set_prefix(format!("ecm ({}/{})", deep + 1, MAX_DEEP));
    }

    let mut factors = HashMap::new();
    for (factor, count) in ecm::ecm_with_params(n, OPTIMAL_B1[deep], 100_000, 100, seed, pb)
        .or(Err(Error::NotFound))?
    {
        if factor.is_probably_prime(100) != IsPrime::No {
            factors.insert(factor, count);
        } else {
            // Try with larger bounds
            let sub_factors = ecm(&factor, pb, seed * 17, deep + 1)?;

            for (sub_factor, sub_count) in sub_factors {
                *factors.entry(sub_factor).or_insert(0) += sub_count * count;
            }
        }
    }

    Ok(factors)
}

/// Lenstra's ECM factorization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcmAttack;

impl Attack for EcmAttack {
    fn name(&self) -> &'static str {
        "ecm"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let factors = ecm(n, pb, 1234, 0)
            .or(Err(Error::NotFound))?
            .iter()
            .flat_map(|(p, e)| std::iter::repeat(p).take(*e))
            .cloned()
            .collect::<Vec<_>>();

        if factors.len() < 2 {
            return Err(Error::NotFound);
        }

        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_factors(factors, e)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from(1779681653);
        let q = Integer::from(1903643191);

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };
        let solution = EcmAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
