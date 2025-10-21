// Tests for multi-key attacks

use rsacracker::{run_specific_attacks_with_threads, KeyEntry, Parameters, ATTACKS};
use rug::Integer;
use std::str::FromStr;

#[test]
fn common_factor_attack_test() {
    // Two RSA keys that share a common prime factor
    // p1 = 127046...46991 is shared between n1 and n2
    let p_shared = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
    let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
    let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();

    let n1 = p_shared.clone() * &q1;
    let n2 = p_shared.clone() * &q2;
    let e = Integer::from(65537);

    let params = Parameters {
        n: Some(n1.clone()),
        e: e.clone(),
        keys: vec![KeyEntry {
            n: Some(n2.clone()),
            e: e.clone(),
            c: None,
        }],
        ..Default::default()
    };

    let solution = run_specific_attacks_with_threads(&params, &ATTACKS, 1).unwrap();
    assert_eq!(solution.attack, "common_factor");

    let pk = solution.pk.unwrap();
    assert_eq!(pk.n, n1);
    assert_eq!(pk.p(), p_shared);
    assert_eq!(pk.q(), q1);
}

#[test]
fn common_modulus_attack_test() {
    // Same modulus n, different coprime exponents e1 and e2, same message encrypted twice
    use rsacracker::bytes_to_integer;

    let m = bytes_to_integer(b"RsaCracker!");
    let n = Integer::from_str("166270918338126577330758828592535648964989469159127542778196697837221437733066780089912708466193803018826184715618764250423068066614662326811797974314176667").unwrap();
    let e1 = Integer::from(65537);
    let e2 = Integer::from(65539);

    let c1 = m.clone().pow_mod(&e1, &n).unwrap();
    let c2 = m.clone().pow_mod(&e2, &n).unwrap();

    let params = Parameters {
        n: Some(n.clone()),
        e: e1,
        c: Some(c1),
        keys: vec![KeyEntry {
            n: Some(n),
            e: e2,
            c: Some(c2),
        }],
        ..Default::default()
    };

    let solution = run_specific_attacks_with_threads(&params, &ATTACKS, 1).unwrap();
    assert_eq!(solution.attack, "common_modulus");
    assert_eq!(solution.m.unwrap(), m);
}

#[test]
fn multi_key_from_raw() {
    // Test parsing multi-key parameters from raw text
    let raw = r#"
# Multi-key example
n1 = 166162630914502531310583922419891282066165820974633135604215723500594369488785155668770814942798477925368262423257419073645831352835527789101770856835355683177962166057699839663569971312562086050531058716298108813024798653596850452010850976880829077654912494652271256054564920903881745267063001869548202922099
e1 = 65537
c1 = 123

n2 = 148455898656074447797752378503069279028991863906908832057033693077681993859745690328279867444062926638337203683279627319119630089306918893030699950731547426066997479055479829293964341682216330844958953722765260947532634616964944677851975839768164255655099799121904635086103339949975609477039895462111764318783
e2 = 65537
c2 = 456
"#;

    let params = Parameters::from_raw(raw);

    assert_eq!(params.keys.len(), 2);

    let key1 = &params.keys[0];
    assert!(key1.n.is_some());
    assert_eq!(key1.e, Integer::from(65537));
    assert_eq!(key1.c, Some(Integer::from(123)));

    let key2 = &params.keys[1];
    assert!(key2.n.is_some());
    assert_eq!(key2.e, Integer::from(65537));
    assert_eq!(key2.c, Some(Integer::from(456)));
}

#[test]
fn multi_key_mixed_indexed_from_raw() {
    // Test parsing multi-key parameters with mixed indexed and non-indexed notation
    let raw = r#"
# Mixed indexed and non-indexed keys
n = 123456789
e = 65537
c = 100

n2 = 987654321
e2 = 3
c2 = 200
"#;

    let params = Parameters::from_raw(raw);

    // Main key from non-indexed parameters
    assert_eq!(params.n, Some(Integer::from(123456789)));
    assert_eq!(params.e, Integer::from(65537));
    assert_eq!(params.c, Some(Integer::from(100)));

    // Additional key at index 2
    assert_eq!(params.keys.len(), 1);
    let key2 = &params.keys[0];
    assert_eq!(key2.n, Some(Integer::from(987654321)));
    assert_eq!(key2.e, Integer::from(3));
    assert_eq!(key2.c, Some(Integer::from(200)));
}
