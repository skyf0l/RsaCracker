use rug::{Complete, Integer};

use crate::{Attack, AttackResult, Error, Parameters, PrivateKey};

/// Leaked CRT attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedCrtAttack;

impl Attack for LeakedCrtAttack {
    fn name(&self) -> &'static str {
        "leaked_crt"
    }

    fn run(&self, params: &Parameters) -> AttackResult {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let dp = params
            .dp
            .as_ref()
            .or_else(|| params.dq.as_ref())
            .ok_or(Error::MissingParameters)?;

        let p = (Integer::from(2).pow_mod(&(e.clone() * dp), n).unwrap() - Integer::from(2)).gcd(n);
        let q = match n.div_rem_ref(&p).complete() {
            (q, rem) if (rem) == Integer::ZERO => q,
            _ => return Err(Error::NotFound),
        };

        Ok((Some(PrivateKey::from_p_q(p, q, e.clone())), None))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn picoctf_2017_weirderrsa() {
        // From picoCTF 2017 / weirderRSA
        // https://ctftime.org/task/3910

        let params = Parameters {
            n: Some(Integer::from_str("499607129142614016115845569972309954865466642986629586633467546172800056547903083303297314393486719922392114168964815069281475244480336720618108262665997707387594045170650286331094075335771255196970298123339129317833157961011527832876727076344754954725939644758068479530394261225267979368085014589570504346427").unwrap()),
            dp: Some(Integer::from_str("10223330953817363123811922583649696214606550602104286204220891355717604605964870127334598738896285490397615099445491494493968669242516576783690807635432479").unwrap()),
            ..Default::default()
        };

        let (priv_key, m) = LeakedCrtAttack.run(&params).unwrap();
        let priv_key = priv_key.unwrap();

        assert_eq!(priv_key.factors[0], Integer::from_str("21100368704141636765855256286221434048709743518984068751384002972320635654735828125061083146556203496016954264151493285718542969434118526065399759241883701").unwrap());
        assert_eq!(priv_key.factors[1], Integer::from_str("23677649246221455526920237847285936347198272142280404458636058832373207515323875094007407059089156524867954227386619644296258425845383217043246438138436527").unwrap());
        assert!(m.is_none());
    }
}
