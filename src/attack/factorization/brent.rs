use indicatif::ProgressBar;
use rug::{rand::RandState, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

fn brent(n: &Integer, pb: Option<&ProgressBar>) -> Option<Integer> {
    if let Some(pb) = pb {
        pb.set_length(23)
    }

    // Implementation inspired by https://gist.github.com/ssanin82/18582bf4a1849dfb8afd
    let mut rgen = RandState::new();
    let two = Integer::from(2);

    let mut y: Integer = Integer::from(n - 1).random_below(&mut rgen) + 1;
    let c = Integer::from(n - 1).random_below(&mut rgen) + 1;
    let m: Integer = Integer::from(n - 1).random_below(&mut rgen) + 1;

    let mut g = Integer::from(1);
    let mut r = 1u64;
    let mut q = Integer::from(1);

    let mut ys = Integer::from(1);

    let mut x;
    loop {
        x = y.clone();

        for _ in 0..=r {
            y = (Integer::from(y.pow_mod_ref(&two, n).unwrap()) + &c) % n;
        }

        let mut k = Integer::ZERO;
        while k < r && g == 1 {
            ys = y.clone();

            let mut i = 0;
            while i <= m && r - i > k {
                y = (Integer::from(y.pow_mod_ref(&two, n).unwrap()) + &c) % n;
                q = q * (x.clone() - &y).abs() % n;
                i += 1;
            }
            g = Integer::from(q.gcd_ref(n));
            k += &m;
            if n > &g && g > 1 {
                break;
            }
        }

        r <<= 1;
        if let Some(pb) = pb {
            pb.inc(1);
        }
        // Limit to 22 iterations
        if r > 1 << 22 {
            return None;
        }

        if g != 1 {
            break;
        }
    }

    if &g == n {
        let start_ys = Integer::from(&ys);
        loop {
            ys = (Integer::from(ys.pow_mod_ref(&two, n).unwrap()) + &c) % n;
            g = Integer::from((x.clone() - &ys).abs().gcd_ref(n));
            if n > &g && g > 1 {
                break;
            }

            // If looped back to start, n might be prime
            if start_ys == ys {
                return None;
            }
        }
    }

    Some(g)
}

/// Pollard rho with brent's optimization attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrentAttack;

impl Attack for BrentAttack {
    fn name(&self) -> &'static str {
        "brent"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Slow
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(p) = brent(n, pb) {
            let q = Integer::from(n / &p);
            Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ))
        } else {
            Err(Error::NotFound)
        }
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
        let solution = BrentAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
