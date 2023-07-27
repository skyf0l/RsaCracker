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
        for power in 2..log_base_ceil(n, 2) as u32 {
            let (root, rem) = n.root_rem_ref(power).into();

            if rem != Integer::ZERO {
                continue;
            }

            let factors = (0..power).map(|_| root.clone()).collect::<Vec<_>>();
            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_factors(&factors, e.clone())?,
            ));
        }

        Err(Error::NotFound)
    }
}
