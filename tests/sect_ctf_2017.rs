use std::{str::FromStr, sync::Arc};

use rsacracker::{integer_to_string, run_specific_attacks, LondahlAttack, Parameters};
use rug::Integer;

#[test]
fn sect_ctf_2017_qproximity() {
    // From SEC-T CTF 2017 / qproximity
    // https://ctftime.org/task/4611

    let params = Parameters {
        c: Some(Integer::from_str("136693955701526219361177143240361857452695512699295758960798998881326125388134176724670266426837335604857949750275181457411794799230868032860940345876713105851002345543552367990479812123656312974840567388822426291834335319932929790713807521900477689775575240804227499316680526933994834929316987597679933119").unwrap()),
        ..Default::default()
    } + Parameters::from_public_key(
        b"-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAOBxiQviVpL4G5d0TmVmjDn51zu
iravDlD4vUlVk9XK79/fwptVzYsjimO42+ZW5VmHF2AUXaPhDC3jBaoNIoa78CXO
ft030bR1S0hGcffcDFMm/tZxwu2/AAXCHoLdjHSwL7gxtXulFxbWoWOdSq+qxtak
zBSZ7R1QlDmbnpwdAgMDEzc=
-----END PUBLIC KEY-----",
    )
    .unwrap();

    let solution = run_specific_attacks(&params, &[Arc::new(LondahlAttack)]).unwrap();
    assert!(solution.pk.is_some());
    assert_eq!(
        integer_to_string(&solution.m.unwrap()).unwrap().trim(),
        "SECT{w3ll_th4t_wasnt_2_h4rd?}"
    );
}
