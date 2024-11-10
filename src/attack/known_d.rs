use indicatif::ProgressBar;
use rug::{ops::Pow, rand::RandState, Integer};

use crate::{
    key::PrivateKey, utils::log_base_ceil, Attack, AttackKind, AttackSpeed, Error, Parameters,
    Solution,
};

/// Known phi attack
///
/// See <https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/known_d.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDAttack;

impl Attack for KnownDAttack {
    fn name(&self) -> &'static str {
        "known_d"
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
        let d = params.d.as_ref().ok_or(Error::MissingParameters)?;

        let k = e * d - Integer::from(1);
        let bits = log_base_ceil(&k, 2);

        let mut rgen = RandState::new();
        loop {
            let g = (n.clone() - Integer::from(1)).random_below(&mut rgen) + Integer::from(1);
            for s in 1..=bits as u32 {
                let x = Integer::from(g.pow_mod_ref(&(&k / Integer::from(2).pow(s)), n).unwrap());
                let p = Integer::from(n.gcd_ref(&(x - Integer::from(1))));
                if p > 1 && p < *n && n.is_divisible(&p) {
                    let q = Integer::from(n / &p);
                    return Ok(Solution::new_pk(
                        self.name(),
                        PrivateKey::from_p_q(p, q, e)?,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Factors, Parameters};

    use super::*;

    #[test]
    fn attack_1() {
        let p = Integer::from_str("619725990001524703456465713279465625846752832414168572011466066232082436863841189586501588353354943054775532335900016320501197905886582011529076059068049302722289071314361386097002051734252322740808308805710458547662135247973085180484778717957169307399128511564888941495042113300382369335995877815563").unwrap();
        let q = Integer::from_str("961141430710150744852888885216606265327700813871292735032123072541546834239236573911369525935582156732540361058711390750890531374856612832113164217347913046140103022163728329963032320241017138138876928547833993486588456012463816930437584873444942767568476855020374256145222297933467290778138867303179").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();

        let params = Parameters {
            n: Some(factors.product()),
            d: Some(d),
            ..Default::default()
        };

        let solution = KnownDAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn attack_2() {
        let p = Integer::from_str("10999882285407021659159843781080979389814097626452668846482424135627220062700466847567575264657287989126943263999867722090759547565297969535143544253926071").unwrap();
        let q = Integer::from_str("12894820825544912052042889653649757120734073367261758361676140208842841153775542379620171049124260330205408767340830801133280422958906941622318918402459837").unwrap();
        let factors = Factors::from([p.clone(), q.clone()]);
        let d = Integer::from(65537).invert(&factors.phi()).unwrap();

        let params = Parameters {
            n: Some(factors.product()),
            d: Some(d),
            ..Default::default()
        };

        let solution = KnownDAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
