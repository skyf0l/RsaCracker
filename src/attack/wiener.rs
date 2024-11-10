use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{
    key::PrivateKey,
    ntheory::{contfrac_to_rational, rational_to_contfrac, trivial_factorization_with_n_phi},
    Attack, AttackKind, Error, Parameters, Solution,
};

/// Wiener's attack (too small d)
///
/// See <https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/wiener_attack.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WienerAttack;

impl Attack for WienerAttack {
    fn name(&self) -> &'static str {
        "wiener"
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;

        let frac = rational_to_contfrac(e, n);
        if let Some(pb) = pb {
            pb.set_length(frac.len() as u64);
        }
        let mut convergents = Vec::new();
        for i in 0..frac.len() {
            convergents.push(contfrac_to_rational(&frac[0..i]));
            if let Some(pb) = pb {
                pb.inc(1);
            }
        }
        for (k, d) in convergents {
            if k != 0 {
                let (phi, q) = (e.clone() * &d - Integer::from(1)).div_rem_floor(k);
                if phi.is_even() && q == 0 {
                    let s = Integer::from(1) + n - &phi;
                    let discr = s.clone().pow(2) - n * Integer::from(4);
                    let t = if discr > 0 && discr.is_perfect_square() {
                        discr.sqrt()
                    } else {
                        Integer::ZERO
                    };

                    if (s + t).is_even() {
                        if let Some((p, q)) = trivial_factorization_with_n_phi(n, &phi) {
                            return Ok(Solution::new_pk(
                                self.name(),
                                PrivateKey::from_p_q(p, q, e)?,
                            ));
                        }
                    }
                }
            }
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
    fn attack() {
        let p = Integer::from_str("6933923262781683366316472659407081840385285455077122235753449057801539822308174027541202209776857105782337372767555342676749125109168114988291773001406719").unwrap();
        let q = Integer::from_str("9216552630349497248854461148903581877939724838581072236002328187229938158716983013925360355301876965491548210304574562739493228847611293721830637308804193").unwrap();
        let d = Integer::from_str(
            "82656209786119546586793013314401325784594131342654070912205833037942868600641",
        )
        .unwrap();
        let factors = Factors::from([p, q]);
        let phi = factors.phi();
        let e = d.invert(&phi).unwrap();

        let params = Parameters {
            e,
            n: Some(factors.product()),
            ..Default::default()
        };

        let solution = WienerAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
