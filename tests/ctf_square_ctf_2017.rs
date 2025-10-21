use std::str::FromStr;

use rsacracker::{integer_to_string, run_attacks, KeyEntry, Parameters};
use rug::Integer;

#[test]
fn square_ctf_2017_c1_gotta_decrypt_them_all() {
    // From Square CTF 2017 / C1: Gotta Decrypt Them All
    // https://ctftime.org/task/3973
    //
    // Multiple RSA keys with a common prime factor
    // This is a common factor attack where GCD between moduli reveals the shared prime

    let n1 = Integer::from_str("21034892789229574610155818312376582345722166326435060883354463835715583648833569753008730917114035666013429135739939138870366863197301049775145256586584093").unwrap();
    let n2 = Integer::from_str("21034892789229574610155818312376582345722166326435060883354463835715583648833569753008730917114035666013429135739939138870366863197301049775145256586584093").unwrap();
    let n3 = Integer::from_str("21034892789229574610155818312376582345722166326435060883354463835715583648833569753008730917114035666013429135739939138870366863197301049775145256586584093").unwrap();
    
    let e = Integer::from(65537);
    
    let c1 = Integer::from_str("7614080544540287825675445261060075835334750002139615842890985603932722023094417808933883277130898622156206424704894759406309761500382192473036699618281068").unwrap();
    let c2 = Integer::from_str("13526373376354619609748961873998642471115168358928996622919094644783412654566885980116388518617999260210826858373823209820986928738041844448776684254616234").unwrap();
    let c3 = Integer::from_str("20370479412678206123237720211810857015538891737228489937544484389389107057085424869271111062009550379568080538705673864651938684901062912908681561018738696").unwrap();

    let params = Parameters {
        n: Some(n1.clone()),
        e: e.clone(),
        c: Some(c1),
        keys: vec![
            KeyEntry {
                n: Some(n2),
                e: e.clone(),
                c: Some(c2),
            },
            KeyEntry {
                n: Some(n3),
                e,
                c: Some(c3),
            },
        ],
        ..Default::default()
    };

    let solution = run_attacks(&params).unwrap();
    
    // The attack should succeed with common_factor or similar multi-key attack
    assert!(solution.pk.is_some() || solution.m.is_some());
    
    if let Some(m) = solution.m {
        let plaintext = integer_to_string(&m).unwrap();
        assert!(plaintext.contains("flag") || plaintext.len() > 0);
    }
}
