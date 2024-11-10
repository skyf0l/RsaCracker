use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{
    key::PrivateKey, utils::solve_quadratic, Attack, AttackKind, Error, Parameters, Solution,
};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Ghafar-Ariffin-Asbullah key recovery attack (lsb of p and q are known)
///
/// Implementation of <https://www.mdpi.com/2073-8994/12/5/838>
/// See <https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/gaa.py>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaaAttack;

impl Attack for GaaAttack {
    fn name(&self) -> &'static str {
        "gaa"
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let rp = params.p.as_ref().ok_or(Error::MissingParameters)?;
        let rq = params.q.as_ref().ok_or(Error::MissingParameters)?;
        let one = Integer::from(1);

        if let Some(pb) = pb {
            pb.set_length(MAX_ITERATIONS);
        }

        // k = ceil(sqrt(rp * rq))
        let mut k = match Integer::from(rp * rq).sqrt_rem(Integer::ZERO) {
            (root, rem) if rem == Integer::ZERO => root,
            (root, _) => root + 1,
        };
        let n_sqrt = Integer::from(n.sqrt_ref());

        for i in 0..MAX_ITERATIONS {
            let sigma = (n_sqrt.clone() - &k).pow(2);
            let z = (n - Integer::from(rp * rq)) % &sigma;

            // Solve: x^2 - z * x + sigma * rp * rq = 0
            for root in solve_quadratic(&one, &(-z), &(sigma * rp * rq)) {
                if root < 0 {
                    continue;
                }

                if Integer::from(&root % rp) == 0 {
                    let p = Integer::from(&root / rp) + rq;
                    let q = Integer::from(n / &p);
                    if p.clone() * &q == *n {
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(p, q, e)?,
                        ));
                    }
                }
                if Integer::from(&root % rq) == 0 {
                    let q = (root / rq) + rp;
                    let p = Integer::from(n / &q);
                    if p.clone() * &q == *n {
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(p, q, e)?,
                        ));
                    }
                }
            }

            if i % TICK_SIZE == 0 {
                if let Some(pb) = pb {
                    pb.inc(TICK_SIZE);
                }
            }

            k += 1;
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn attack_1() {
        let p = Integer::from_str("122539608741316849829261726098688957114502463272691906657106165887494465656483627796660671278978213477051915433597161268345944097932917669169852614268434890176706523882967335716979529907163623313323845921267400475000574500531377847942396759927437400904034577111052905698000623411296101838403579267392100002539").unwrap();
        let q = Integer::from_str("207632566695348090325106198564354306872362493463538154841386314580707220972445801440409737589803024013035554181699335224061662229162879643933792870833231736875142501533422110427899095351781206012327937258761409973123340262144886588093314114536052456895922041585909651666335476791456709509341751911472100003017").unwrap();
        let rp = 2539.into();
        let rq = 3017.into();

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(rp),
            q: Some(rq),
            ..Default::default()
        };

        let solution = GaaAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn attack_2() {
        let p = Integer::from_str("90298295824650311663818894095620747783372649281213396245855149883068750544736749865742151003212745876322858711152862555726263459709030033799784069102281145447897017439265777617772466042518218409294380111768917907088743454681904160308248752114524063081088402900608673706746438458236567547010845749956723115239").unwrap();
        let q = Integer::from_str("95071251890492896215829359101175428907421221364386877469905182082459875177459986258243302560246216190552021119341405678279166840212587310541906674474311515240972185868939740063531859593844606048709104560925568301977927216150294427162519810608935523631249827019496037479563371324790366397060798445963209377357").unwrap();
        let rp = 34023.into();
        let rq = 34381.into();
        assert_eq!(rp, p.clone() & 0b1111111111111111);
        assert_eq!(rq, q.clone() & 0b1111111111111111);

        let params = Parameters {
            n: Some(p.clone() * &q),
            p: Some(rp),
            q: Some(rq),
            ..Default::default()
        };

        let solution = GaaAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }
}
