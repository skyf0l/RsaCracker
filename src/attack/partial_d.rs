use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackKind, AttackSpeed, Error, KnownDAttack, Parameters, Solution};

/// Partial d leaked attack (more that half of the bits of d are known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDAttack;

impl Attack for PartialDAttack {
    fn name(&self) -> &'static str {
        "partial_d"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let e_u32 = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let d_lsb = params.d.as_ref().ok_or(Error::MissingParameters)?;

        let known_bits = d_lsb.significant_bits();

        for k in 1..e_u32 {
            let d_candidate = (n.clone() * k + 1u64) / e;
            let d_msb = (d_candidate >> known_bits) << known_bits;
            let d = d_msb | d_lsb;

            // Check congruence
            if Integer::from(e * &d) % k == 1 {
                // Try to encrypt and decrypt 2 to check if d is correct
                if Integer::from(2)
                    .pow_mod(e, n)
                    .unwrap()
                    .pow_mod(&d, n)
                    .unwrap()
                    == 2
                {
                    // Compute p and q
                    return KnownDAttack
                        .run(
                            &(Parameters {
                                d: Some(d),
                                ..Default::default()
                            } + params),
                            _pb,
                        )
                        .map(|mut s| {
                            s.attack = self.name();
                            s
                        });
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

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let p = Integer::from_str("619725990001524703456465713279465625846752832414168572011466066232082436863841189586501588353354943054775532335900016320501197905886582011529076059068049302722289071314361386097002051734252322740808308805710458547662135247973085180484778717957169307399128511564888941495042113300382369335995877815563").unwrap();
        let q = Integer::from_str("961141430710150744852888885216606265327700813871292735032123072541546834239236573911369525935582156732540361058711390750890531374856612832113164217347913046140103022163728329963032320241017138138876928547833993486588456012463816930437584873444942767568476855020374256145222297933467290778138867303179").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();
        let partial_d = d.clone() % Integer::from(2).pow(d.significant_bits() / 2 + 2);

        let params = Parameters {
            n: Some(factors.product()),
            d: Some(partial_d),
            ..Default::default()
        };

        let solution = PartialDAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
