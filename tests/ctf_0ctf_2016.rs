use std::str::FromStr;

use rsacracker::{run_attacks, Parameters};
use rug::Integer;

#[test]
fn _0ctf_2016_quals_equation() {
    // From 0CTF 2016 Quals / equation
    // https://ctftime.org/task/2127

    /* // TODO: Recover exponent from partial private key as in the challenge
    ```
    Os9mhOQRdqW2cwVrnNI72DLcAXpXUJ1HGwJBANWiJcDUGxZpnERxVw7s0913WXNt
    V4GqdxCzG0pG5EHThtoTRbyX0aqRP4U/hQ9tRoSoDmBn+3HPITsnbCy67VkCQBM4
    xZPTtUKM6Xi+16VTUnFVs9E4rqwIQCDAxn9UuVMBXlX2Cl0xOGUF4C5hItrX2woF
    7LVS5EizR63CyRcPovMCQQDVyNbcWD7N88MhZjujKuSrHJot7WcCaRmTGEIJ6TkU
    8NWt9BVjR4jVkZ2EqNd0KZWdQPukeynPcLlDEkIXyaQx
    ```
     */

    let params = Parameters {
        dp : Some(Integer::from_str("11188888442779478492506783674852186314949555636014740182307607993518479864690065244102864238986781155531033697982611187514703037389481147794554444962262361").unwrap()),
        dq : Some(Integer::from_str("1006725509429627901220283238134032802363853505667837273574181077068133214344166038422298631614477333564791953596600001816371928482096290600710984197710579").unwrap()),
        qinv : Some(Integer::from_str("11196804284042107547423407831525890933636414684075355664222816007929037065463409676450144484947842399975707117057331864113464711778199061912128258484839473").unwrap()),
        ..Default::default()

    };

    let solution = run_attacks(&params).unwrap();
    assert!(solution.pk.is_some());
    // The challenge's ciphertext was lost in the Internet
    // assert_eq!(
    //     integer_to_string(&solution.m.unwrap()).unwrap(),
    //     "0ctf{Keep_ca1m_and_s01ve_the_RSA_Eeeequati0n!!!}"
    // );
}
