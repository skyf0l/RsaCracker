use std::str::FromStr;

use rsacracker::{integer_to_string, run_attacks, Parameters};
use rug::Integer;

#[test]
fn hxp_ctf_2018_daring() {
    // From hxp CTF 2018 / daring
    // https://ctftime.org/task/7215

    let params = Parameters {
        c : Some(Integer::from_str("2780321436921227845269766067805604547641764672251687438825498122989499386967784164108893743279610287605669769995594639683212592165536863280639528420328182048065518360606262307313806591343147104009274770408926901136562839153074067955850912830877064811031354484452546219065027914838811744269912371819665118277221").unwrap()),
        ..Default::default()

    } + Parameters::from_public_key(
        b"-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC7LPIneSm9M962IJh4Op5Dwr9k
aud5nAOXZZvafTrbkfAMmFUv7u/VmNzvPiTWhuaHgKEhyzVFp9XXdp4u+KoQ41wd
H4LS7SJq5eWGaEU9riDcP1MF2orO+OWDgbzx9hgdz5k3LyEHTrmsUgUQNsHCVsZi
FQr8/gZPzYYTRWMYcwIBAw==
-----END PUBLIC KEY-----",
    )
    .unwrap();

    let solution = run_attacks(&params).unwrap();
    assert!(solution.pk.is_none());
    assert_eq!(
        integer_to_string(&solution.m.unwrap()).unwrap(),
        "dsc{t0-m355-w1th-m4th-t4k35-4-l0t-0f-sp1n3}"
    );
}
