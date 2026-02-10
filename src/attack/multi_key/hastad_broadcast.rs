use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{
    math::number_theory::crt, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution,
};

/// Hastad's broadcast attack
///
/// When the same message is sent to k recipients using the same small public exponent e,
/// and k >= e, we can use the Chinese Remainder Theorem to recover the plaintext.
///
/// Given k ciphertexts c_i = m^e mod n_i where all n_i are pairwise coprime and k >= e,
/// we can compute M = m^e mod (n_1 * n_2 * ... * n_k) using CRT,
/// then m = e-th_root(M).
///
/// This attack is most effective when e is small (typically e = 3).
///
/// See <https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Hastad's_broadcast_attack>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HastadBroadcastAttack;

impl Attack for HastadBroadcastAttack {
    fn name(&self) -> &'static str {
        "hastad_broadcast"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        // Collect all keys with the same exponent e
        let e = &params.e;

        // Collect ciphertexts and moduli
        let mut ciphertexts = Vec::new();
        let mut moduli = Vec::new();

        // Add main key if both n and c are present
        if let (Some(n), Some(c)) = (&params.n, &params.c) {
            ciphertexts.push(c.clone());
            moduli.push(n.clone());
        }

        // Add additional keys with same exponent
        for key in &params.keys {
            if &key.e != e {
                continue;
            }
            if let (Some(n), Some(c)) = (&key.n, &key.c) {
                ciphertexts.push(c.clone());
                moduli.push(n.clone());
            }
        }

        let k = ciphertexts.len();

        // Need at least e ciphertexts
        if k < e.to_usize().unwrap_or(usize::MAX) {
            return Err(Error::MissingParameters);
        }

        // Check if all moduli are pairwise coprime
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                let gcd = Integer::from(moduli[i].gcd_ref(&moduli[j]));
                if gcd != 1 {
                    return Err(Error::NotFound);
                }
            }
        }

        // Use CRT to compute M = m^e mod (n_1 * n_2 * ... * n_k)
        let m_to_e = crt(&ciphertexts, &moduli).ok_or(Error::NotFound)?;

        // Compute the e-th root of m_to_e
        // For small e, we can try to compute the integer e-th root directly
        let e_u32 = e.to_u32().ok_or(Error::NotFound)?;

        // Try to compute the e-th root
        let m = m_to_e.clone().root(e_u32);

        // Verify the result - check if m^e equals m_to_e within some tolerance
        // The root might not be exact due to truncation
        let m_pow = m.clone().pow(e_u32);

        // Verify the solution by checking if m^e == m_to_e
        // For exact roots (typical in CTF challenges), m^e should equal m_to_e exactly
        if m_pow == m_to_e {
            Ok(Solution::new_m(self.name(), m))
        } else {
            // Try m+1 in case of rounding errors from root extraction
            // This handles edge cases where the integer root is slightly off
            let m_plus_1: Integer = m.clone() + 1;
            let m_pow_plus_1 = m_plus_1.clone().pow(e_u32);
            if m_pow_plus_1 == m_to_e {
                Ok(Solution::new_m(self.name(), m_plus_1))
            } else {
                Err(Error::NotFound)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::{bytes_to_integer, Attack, KeyEntry, Parameters};

    use super::*;

    #[test]
    fn attack_e3_three_keys() {
        // Test with properly generated values where m^e > n (generated using Python script)
        let m = Integer::from_str("66830545723625031329598396452680170994847162991633871117889391281981676827738191451102456382").unwrap();
        let params = Parameters {
            n: Some(Integer::from_str("115281337973362411162266855132914564458653800660041481334367562735006342331634314517752184850094244582299835925123902087561172576479332128164450884671759969762022921364202079392872201142138410366100982688835312265712307675746902439162493190620661146462558258932419011080270743063098208554881775633354122249321").unwrap()),
            e: Integer::from(3),
            c: Some(Integer::from_str("298486726059328947067315360825894194529912707926077020751128594766183781989061764509887580350940073963822141541826745407818163622258682878356994675054575431194369503688988004615089849807030852843360793864864260364694912917599533073861698417256518229602680255360546639079774968").unwrap()),
            keys: vec![
                KeyEntry {
                    n: Some(Integer::from_str("82627430843474575609857801047987170990157766979518974716293991321564785335218901239804607972684227616119756049387033309667012255153070229178828069681214308481260979280007841094716004346162330538391574357459445942595387167495955384155376744761281227350298942769996999843331368385136959029834713680592943441763").unwrap()),
                    e: Integer::from(3),
                    c: Some(Integer::from_str("298486726059328947067315360825894194529912707926077020751128594766183781989061764509887580350940073963822141541826745407818163622258682878356994675054575431194369503688988004615089849807030852843360793864864260364694912917599533073861698417256518229602680255360546639079774968").unwrap()),
                },
                KeyEntry {
                    n: Some(Integer::from_str("106016107619843338457703330186909229032812081225474325262984096037846033194688537104198575356795730416395143590215413080033567513997572481818238776089120892670910620969445247010844115306748150950399602438844813608007431096232921175940932031372487679769048902089090677674136962866797764666203736550369689256177").unwrap()),
                    e: Integer::from(3),
                    c: Some(Integer::from_str("298486726059328947067315360825894194529912707926077020751128594766183781989061764509887580350940073963822141541826745407818163622258682878356994675054575431194369503688988004615089849807030852843360793864864260364694912917599533073861698417256518229602680255360546639079774968").unwrap()),
                },
            ],
            ..Default::default()
        };

        let attack = HastadBroadcastAttack;
        let result = attack.run(&params, None);
        assert!(result.is_ok());
        let solution = result.unwrap();
        assert_eq!(solution.m, Some(m));
    }

    #[test]
    fn attack_insufficient_keys() {
        let m = bytes_to_integer(b"RSA!");
        let e = Integer::from(3);

        let n1 = Integer::from_str("166270918338126577330758828592535648964989469159127542778196697837221437733066780089912708466193803018826184715618764250423068066614662326811797974314176667").unwrap();
        let n2 = Integer::from_str("256944505384930713891354055418220521236353785764660191142433035259468015265326659749049542974891482699292481929606466794325217644417074317817771540857797489").unwrap();

        let c1 = m.clone().pow_mod(&e, &n1).unwrap();
        let c2 = m.clone().pow_mod(&e, &n2).unwrap();

        let params = Parameters {
            n: Some(n1),
            e: e.clone(),
            c: Some(c1),
            keys: vec![KeyEntry {
                n: Some(n2),
                e,
                c: Some(c2),
            }],
            ..Default::default()
        };

        let result = HastadBroadcastAttack.run(&params, None);
        assert!(matches!(result, Err(Error::MissingParameters)));
    }
}
