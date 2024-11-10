use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, rand::RandState, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// See https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/known_phi.py
pub fn factorize(n: &Integer, phi: &Integer) -> Option<(Integer, Integer)> {
    let s = Integer::from(1) + n - phi;
    let d = s.clone().pow(2) - n * Integer::from(4);
    let sqrt_d = if d > 0 && d.is_perfect_square() {
        d.sqrt()
    } else {
        return None;
    };
    let p: Integer = (s.clone() - &sqrt_d) >> 1;
    let q: Integer = (s + sqrt_d) >> 1;

    // Check if p and q are factors of n
    if p.clone() * q.clone() != *n {
        return None;
    }

    // Check if p and q are prime
    if p.is_probably_prime(100) == IsPrime::No || q.is_probably_prime(100) == IsPrime::No {
        return None;
    }

    Some((p, q))
}

/// See https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/known_phi.py
fn factorize_multi_factors(n: &Integer, phi: &Integer) -> Option<Vec<Integer>> {
    let mut rgen = RandState::new();
    let mut prime_factors = std::collections::HashSet::new();
    let mut factors = vec![n.clone()];

    while let Some(n) = &factors.pop() {
        let w = (n - Integer::from(3)).random_below(&mut rgen) + Integer::from(2);
        let mut i = 1;

        while phi % (Integer::from(2).pow(i)) == 0 {
            let sqrt_1 = Integer::from(
                w.clone()
                    .pow_mod_ref(&(phi.clone() / Integer::from(2).pow(i)), n)
                    .unwrap(),
            );
            if sqrt_1 > 1 && sqrt_1 != Integer::from(1) - n {
                let p = Integer::from(n.gcd_ref(&(sqrt_1 + 1)));
                let q = n.clone() / &p;

                if p.is_probably_prime(100) != IsPrime::No {
                    prime_factors.insert(p);
                } else if p > 1 {
                    factors.push(p);
                }

                if q.is_probably_prime(100) != IsPrime::No {
                    prime_factors.insert(q);
                } else if q > 1 {
                    factors.push(q);
                }

                break;
            }

            i += 1;
        }
    }

    Some(prime_factors.into_iter().collect())
}

/// Known phi attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPhiAttack;

impl Attack for KnownPhiAttack {
    fn name(&self) -> &'static str {
        "known_phi"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = params.e.clone();
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let phi = params.phi.as_ref().ok_or(Error::MissingParameters)?;

        if let Some((p, q)) = factorize(n, phi) {
            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_p_q(p, q, e)?,
            ));
        }
        if let Some(factors) = factorize_multi_factors(n, phi) {
            return Ok(Solution::new_pk(
                self.name(),
                PrivateKey::from_factors(factors, e)?,
            ));
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
    fn two_factors_1() {
        let p = Integer::from_str("119569912348019973808690648749233130234147905846600013235049261329629970511527761524945847616965313961538713539339797361044473682137188967689436399275622598823807683697187768076793066267578400065793399498609464820787702834758072187460388248841109767616650659184902691855492090063216897253934411433653188209273").unwrap();
        let q = Integer::from_str("163878850764915422483981859745444212722239786863013177512288243925115067928584457671822966318511433648800054833973100107499888490740673843681679946017109383206395115582461040491817953385276745680081596226714070613457018921708592656990254385150774779681262565789230098265299312143978832885242439190257255425823").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            phi: Some((p.clone() - 1) * (q.clone() - 1)),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn two_factors_2() {
        let p = Integer::from_str("11106026672819778415395265319351312104517763207376765038636473714941732117831488482730793398782365364840624898218935983446211558033147834146885518313145941").unwrap();
        let q = Integer::from_str("12793494802119353329493630005275969260540058187994460635179617401018719587481122947567147790680079651999077966705114757935833094909655872125005398075725409").unwrap();

        let params = Parameters {
            n: Some(p.clone() * &q),
            phi: Some((p.clone() - 1) * (q.clone() - 1)),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p(), p);
        assert_eq!(pk.q(), q);
    }

    #[test]
    fn many_factors() {
        let factors = Factors::from([
            Integer::from_str("10193015828669388212171268316396616412166866643440710733674534917491644123135436050477232002188857603479321547506131679866357093667445348339711929671105733").unwrap(),
            Integer::from_str("8826244874397589965592244959402585690675974843434609869757034692220480232437419549416634170391846191239385439228177059214900435042874545573920364227747261").unwrap(),
            Integer::from_str("7352042777909126576764043061995108196815011736073183321111078742728938275060552442022686305342309076279692633229512445674423158310200668776459828180575601").unwrap(),
            Integer::from_str("9118676262959556930818956921827413198986277995127667203870694452397233225961924996910197904901037135372560207618442015208042298428698343225720163505153059").unwrap(),
        ]);

        let params = Parameters {
            n: Some(factors.product()),
            phi: Some(factors.phi()),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, factors);
    }

    #[test]
    fn lot_of_factors() {
        let params = Parameters {
            n: Some(Integer::from_str("101944608207205828373234136985536127422758789188321061203233970866512105752389494532109758175073247548389686570704851101289141025209074305203459165089172207956558339993794255871893298918197670129098361534364062718759980887842594439938816962085529619977722435671024746830146652610211084398772129518078361766394000325505666361018996382168237814399").unwrap()),
            phi: Some(Integer::from_str("101944607938544789583331239048519959294698102607886324393128120389399874129497315153018585963284614983040398803726604034782757560581739754229841910703215832926475159513862093763187745099680421838752895446425172704303481984530969498702763652186288580132507738455103266082927816136366288633207465666651081767959552975436188098172823697096704000000").unwrap()),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(
            pk.factors,
            Factors::from([
                8973591997u64,
                9448712249u64,
                9548549893u64,
                10714663247u64,
                10899303251u64,
                11149917179u64,
                11183413321u64,
                11309828183u64,
                11314251569u64,
                11347803821u64,
                12155568713u64,
                12343587833u64,
                12356265853u64,
                12828934241u64,
                12934972423u64,
                12998526157u64,
                13179420827u64,
                13458671999u64,
                13713656219u64,
                14052991763u64,
                14238968797u64,
                15181937833u64,
                15458492117u64,
                15624167453u64,
                15891284197u64,
                15955507489u64,
                16138658707u64,
                16725941473u64,
                16818501409u64,
                17008632517u64,
                17142507589u64,
            ])
        );
    }
}
