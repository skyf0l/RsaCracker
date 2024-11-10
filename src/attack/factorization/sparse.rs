use indicatif::ProgressBar;
use itertools::Itertools;
use rug::Integer;

use crate::{
    key::PrivateKey,
    utils::{log_base_ceil, solve_quadratic},
    Attack, Error, Parameters, Solution,
};

const MAX_DIFFER_BITS: usize = 2; // Bigger than 2 is way too slow

/// P and q differ by only a few bits
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseAttack;

impl Attack for SparseAttack {
    fn name(&self) -> &'static str {
        "sparse"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let one = Integer::from(1);
        let max_bits = log_base_ceil(n, 2) >> 1;
        let c = -n.clone();
        if let Some(pb) = pb {
            pb.set_length(MAX_DIFFER_BITS as u64);
        }

        // Precalculate powers of 2
        let calculated_powers = (3..=max_bits).map(|p| Integer::from(2) << p).collect_vec();

        for diff_bits in 1..=MAX_DIFFER_BITS {
            for powers in (3..=max_bits).combinations(diff_bits) {
                let difference = powers
                    .iter()
                    .map(|p| &calculated_powers[*p - 3])
                    .sum::<Integer>();

                // Solve: n == x * (x - 2^p1 - 2^p2 - ... - 2^ pn)
                for root in solve_quadratic(&one, &difference, &c) {
                    if root > 0 {
                        let q = Integer::from(n / &root);
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(root, q, e)?,
                        ));
                    }
                }
            }
            if let Some(pb) = pb {
                pb.inc(1);
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::integer::IsPrime;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from_str("7729848568775352075615583091837654172059095741143868092188926149647651947207100509260263762608517411743825830918928309404832038536720454350643554760215479").unwrap();
        let q = p.clone() ^ (Integer::from(1) << 42u32);
        assert!(q.is_probably_prime(100) == IsPrime::Probably);

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = SparseAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
