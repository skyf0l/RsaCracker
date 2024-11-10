use indicatif::ProgressBar;
use rug::Integer;

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Common factor shared in plaintext / ciphertext attack
///
/// See <https://crypto.stackexchange.com/a/99221>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfactCnAttack;

impl Attack for ComfactCnAttack {
    fn name(&self) -> &'static str {
        "comfact_cn"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        let p = Integer::from(c.gcd_ref(n));

        if p != 1 {
            let q = n.clone() / &p;

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
    use std::str::FromStr;

    use rug::Integer;

    use crate::{factors::Factors, Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let e = Integer::from(65537);
        let p = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let m = p.clone() * 2u64 * 3u64 * 19u64;
        let factors = Factors::from([p, q]);
        let c = m.pow_mod(&e, &factors.product()).unwrap();

        let params = Parameters {
            e,
            n: Some(factors.product()),
            c: Some(c),
            ..Default::default()
        };
        let solution = ComfactCnAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }
}
