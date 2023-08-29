use std::collections::hash_map::Entry;

use indicatif::ProgressBar;
use rug::Integer;

use crate::{
    key::PrivateKey, utils::solve_quadratic, Attack, AttackSpeed, Error, Parameters, Solution,
};

const LONDAHL_B: u64 = 10_000_000;

fn close_factor(n: &Integer, b: u64, pb: Option<&ProgressBar>) -> Option<(Integer, Integer)> {
    let tick_size: u64 = b / 100;
    if let Some(pb) = pb {
        pb.set_length(b * 2);
    }

    // Approximate phi
    let phi_approx = n - 2 * n.clone().sqrt() + 1;

    // Create a look-up table
    let mut look_up = std::collections::HashMap::new();
    look_up.reserve(b as usize);

    let mut z = Integer::from(1);
    for i in 0..=b {
        match look_up.entry(z.clone()) {
            Entry::Occupied(_) => {
                // Key already exists, so key generation is looping
                if let Some(pb) = pb {
                    pb.set_position(b);
                }
                break;
            }
            Entry::Vacant(e) => {
                e.insert(i);
            }
        }
        z = (z * 2) % n;

        if i % tick_size == 0 {
            if let Some(pb) = pb {
                pb.inc(tick_size);
            }
        }
    }

    // Check the table
    let mut mu = Integer::from(2)
        .pow_mod(&phi_approx, n)
        .unwrap()
        .invert(n)
        .ok()?;
    let fac = Integer::from(2).pow_mod(&b.into(), n).unwrap();

    for j in 1..=b {
        mu = (mu * &fac) % n;

        if j % tick_size == 0 {
            if let Some(pb) = pb {
                pb.inc(tick_size);
            }
        }

        if let Some(i) = look_up.get(&mu) {
            let phi = &phi_approx + (i - Integer::from(j) * b);
            let b = -(n - phi + 1u64);
            let roots = solve_quadratic(&Integer::from(1), &b, n);

            if roots.len() != 2 || roots.iter().any(|r| *r == 1) {
                continue;
            }

            return Some((roots[0].clone(), roots[1].clone()));
        }
    }

    None
}

/// Londahl close-prime factorization attack
///
/// See <https://web.archive.org/web/20201031000312/https://grocid.net/2017/09/16/finding-close-prime-factorizations/>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LondahlAttack;

impl Attack for LondahlAttack {
    fn name(&self) -> &'static str {
        "londahl"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        self.run_with_b(params, pb, LONDAHL_B)
    }
}

impl LondahlAttack {
    fn run_with_b(
        &self,
        params: &Parameters,
        pb: Option<&ProgressBar>,
        b: u64,
    ) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let (p, q) = close_factor(n, b, pb).ok_or(Error::NotFound)?;
        Ok(Solution::new_pk(
            self.name(),
            PrivateKey::from_p_q(p, q, e.clone())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::Parameters;

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from_str("1658948984989849391").unwrap();
        let q = Integer::from_str("1658948984989849393").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            ..Default::default()
        };

        let solution = LondahlAttack.run_with_b(&params, None, 1_000).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
