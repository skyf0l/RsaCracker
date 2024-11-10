use std::collections::HashMap;

use indicatif::ProgressBar;
use rug::Integer;

use crate::{
    key::PrivateKey, utils::log_base_ceil, Attack, AttackSpeed, Error, Parameters, Solution,
};

/// Factorize n when n = p^k
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerAttack;

impl Attack for PowerAttack {
    fn name(&self) -> &'static str {
        "power"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        for power in (2..log_base_ceil(n, 2) as u32).rev() {
            let (root, rem) = n.root_rem_ref(power).into();

            if rem != Integer::ZERO {
                continue;
            }

            let factors = HashMap::from([(root, power as usize)]);
            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_factors(factors, e)?,
            ));
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack_1() {
        let p = Integer::from_str("2291993061073575758193465505232279130309044473989611727024268917236359456245089131405543871839300931").unwrap();
        let factors = Factors::from(HashMap::from([(p, 19)]));

        let params = Parameters {
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            ..Default::default()
        };

        let solution = PowerAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }

    #[test]
    fn attack_2() {
        let p = Integer::from_str("2291993061073575758193465505232279130309044473989611727024268917236359456245089131405543871839300931").unwrap();
        let factors = Factors::from(HashMap::from([(p, 16)]));

        let params = Parameters {
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            ..Default::default()
        };

        let solution = PowerAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
