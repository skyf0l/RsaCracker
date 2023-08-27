use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, utils::solve_quadratic, Attack, Error, Parameters, Solution};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Ghafar-Ariffin-Asbullah key recovery attack (lsb of p and q are known)
///
/// Implementation of <https://www.mdpi.com/2073-8994/12/5/838>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaaAttack;

impl Attack for GaaAttack {
    fn name(&self) -> &'static str {
        "gaa"
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
                            PrivateKey::from_p_q(p, q, e.clone()).unwrap(),
                        ));
                    }
                }
                if Integer::from(&root % rq) == 0 {
                    let q = (root / rq) + rp;
                    let p = Integer::from(n / &q);
                    if p.clone() * &q == *n {
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(p, q, e.clone()).unwrap(),
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
    fn attack() {
        let params = Parameters {
            n: Some(Integer::from_str("25443213484803330676546636060506767271319211956273880351374351825462561580132551177398365004567302649029372469108528581383182366032879612606427513826234802141122998206193459531773833796480172789254233470084592231117946043667803816674367149523326731127008733355361824250743661733271951270041603994991855260193100644339351409446036601574046698036751560570936645802773832960804417075002671744354815841155246667831512956948961180313537576080810878904128457697494633264997808381810844117016959712493847383233300377347818990874284472761519902676254694772586325941589525740707826852095908188649384624121217162949627607660163").unwrap()),
            p: Some(0b101111001001.into()),
            q: Some(0b100111101011.into()),
            ..Default::default()
        };

        let solution = GaaAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), Integer::from_str("122539608741316849829261726098688957114502463272691906657106165887494465656483627796660671278978213477051915433597161268345944097932917669169852614268434890176706523882967335716979529907163623313323845921267400475000574500531377847942396759927437400904034577111052905698000623411296101838403579267392100002539").unwrap());
        assert_eq!(pk.q(), Integer::from_str("207632566695348090325106198564354306872362493463538154841386314580707220972445801440409737589803024013035554181699335224061662229162879643933792870833231736875142501533422110427899095351781206012327937258761409973123340262144886588093314114536052456895922041585909651666335476791456709509341751911472100003017").unwrap());
    }
}
