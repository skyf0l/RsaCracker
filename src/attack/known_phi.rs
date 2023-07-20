use indicatif::ProgressBar;
use rug::{integer::IsPrime, ops::Pow, rand::RandState, Integer};

use crate::{key::PrivateKey, Attack, AttackSpeed, Error, Parameters, Solution};

/// See https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/known_phi.py
fn factorize(n: &Integer, phi: &Integer) -> Option<(Integer, Integer)> {
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
    if p.is_probably_prime(30) == IsPrime::No || q.is_probably_prime(30) == IsPrime::No {
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

                if p.is_probably_prime(30) == IsPrime::Yes {
                    prime_factors.insert(p);
                } else if p > 1 {
                    factors.push(p);
                }

                if q.is_probably_prime(30) == IsPrime::Yes {
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
                PrivateKey::from_factors(&factors, e)?,
            ));
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
    fn two_factors() {
        let params = Parameters {
            n: Some(Integer::from_str("19594979821655183104856721200876279688744199212596318791410700925214020940999368124753876379046101491755637328180352524777390418669210709696131801135729820817964419360433309338628094186567119917735965630612618443318361476838501333469511238156792898753876667912964148133223421606462036819614830830346046983259407147596111671725522875516790826213635619398696281968888325882416381776971733880221909903860599888903194248107358128483103962534467323374352040906477803568664482713174891860915973023918444553550090873773281086421418960484839799410173913761912529789181262819973734812402783319741028408456027454148088452256679").unwrap()),
            phi: Some(Integer::from_str("19594979821655183104856721200876279688744199212596318791410700925214020940999368124753876379046101491755637328180352524777390418669210709696131801135729820817964419360433309338628094186567119917735965630612618443318361476838501333469511238156792898753876667912964148133223421606462036819614830830346046983259123698832998736329230203008296148870679231705986668778140988377161636738531621661025141089925123141292855479734045231014559600361589460562980924561185071586634279913895243052347362004265589407804215878047957550987174238728373134565723271127920645241883349594999602022281991917533832678316850603524178008621584").unwrap()),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p, Integer::from_str("119569912348019973808690648749233130234147905846600013235049261329629970511527761524945847616965313961538713539339797361044473682137188967689436399275622598823807683697187768076793066267578400065793399498609464820787702834758072187460388248841109767616650659184902691855492090063216897253934411433653188209273").unwrap());
        assert_eq!(pk.q, Integer::from_str("163878850764915422483981859745444212722239786863013177512288243925115067928584457671822966318511433648800054833973100107499888490740673843681679946017109383206395115582461040491817953385276745680081596226714070613457018921708592656990254385150774779681262565789230098265299312143978832885242439190257255425823").unwrap());
    }

    #[test]
    fn multi_factors() {
        let params = Parameters {
            n: Some(Integer::from_str("101944608207205828373234136985536127422758789188321061203233970866512105752389494532109758175073247548389686570704851101289141025209074305203459165089172207956558339993794255871893298918197670129098361534364062718759980887842594439938816962085529619977722435671024746830146652610211084398772129518078361766394000325505666361018996382168237814399").unwrap()),
            phi: Some(Integer::from_str("101944607938544789583331239048519959294698102607886324393128120389399874129497315153018585963284614983040398803726604034782757560581739754229841910703215832926475159513862093763187745099680421838752895446425172704303481984530969498702763652186288580132507738455103266082927816136366288633207465666651081767959552975436188098172823697096704000000").unwrap()),
            ..Default::default()
        };

        let solution = KnownPhiAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.p, Integer::from(8973591997u64));
        assert_eq!(pk.q, Integer::from(9448712249u64));
        assert_eq!(
            pk.other_factors,
            vec![
                9548549893u64.into(),
                10714663247u64.into(),
                10899303251u64.into(),
                11149917179u64.into(),
                11183413321u64.into(),
                11309828183u64.into(),
                11314251569u64.into(),
                11347803821u64.into(),
                12155568713u64.into(),
                12343587833u64.into(),
                12356265853u64.into(),
                12828934241u64.into(),
                12934972423u64.into(),
                12998526157u64.into(),
                13179420827u64.into(),
                13458671999u64.into(),
                13713656219u64.into(),
                14052991763u64.into(),
                14238968797u64.into(),
                15181937833u64.into(),
                15458492117u64.into(),
                15624167453u64.into(),
                15891284197u64.into(),
                15955507489u64.into(),
                16138658707u64.into(),
                16725941473u64.into(),
                16818501409u64.into(),
                17008632517u64.into(),
                17142507589u64.into(),
            ] as Vec<Integer>
        );
    }
}
