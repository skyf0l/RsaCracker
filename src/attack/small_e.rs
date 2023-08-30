use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Small e attack (m^e = c + k * n, with k small)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallEAttack;

impl Attack for SmallEAttack {
    fn name(&self) -> &'static str {
        "small_e"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }
        for i in 1..MAX_ITERATIONS {
            let enc = Integer::from(n) * Integer::from(i) + c.clone();
            let (root, rem) = enc.root_rem_ref(e).into();

            // If the root is perfect, we found the plaintext
            if rem == Integer::ZERO {
                return Ok(Solution::new_m(self.name(), root));
            }

            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::ops::Pow;

    use crate::{bytes_to_integer, Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let m = bytes_to_integer(b"Skyf0l!");
        let e = Integer::from(19);
        let p = Integer::from_str("10516567718118716602791930727855199494190478912727182354857606776715779027196209315905790350010119220287035355327718513394492773485069389806205568352533083").unwrap();
        let q = Integer::from_str("12869992910655119669765280088337996038516113996953468433685852659331554429285128301221602991903893809659317109932793836235757301811226355874891889915573169").unwrap();
        let n = p.clone() * &q;
        let c = m.clone().pow(e.to_u32().unwrap());
        assert!(c > n);
        assert!(c.clone() / &n < MAX_ITERATIONS);
        let c = c % &n;

        let params = Parameters {
            e,
            n: Some(n),
            c: Some(c),
            ..Default::default()
        };

        let solution = SmallEAttack.run(&params, None).unwrap();
        assert_eq!(solution.m.unwrap(), m);
    }
}
