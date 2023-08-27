use std::{str::FromStr, sync::Arc};

use rsacracker::{
    integer_to_string, run_attacks, run_specific_attacks, EcmAttack, FermatAttack, Parameters,
    PollardPM1Attack,
};
use rug::Integer;

#[test]
fn tjctf_2022_rsa_apprentice() {
    // From TJCTF 2022 / rsa-apprentice
    // https://ctftime.org/task/21330

    let params_1 = Parameters {
        n: Some(Integer::from_str("1216177716507739302616478655910148392804849").unwrap()),
        c: Some(Integer::from_str("257733734393970582988408159581244878149116").unwrap()),
        ..Default::default()
    };

    let solution_1 = run_specific_attacks(&params_1, &[Arc::new(PollardPM1Attack)]).unwrap();
    let pk = solution_1.pk.unwrap();

    let params_2 = Parameters {
        p: Some(pk.factors()[0].clone()),
        q: Some(pk.factors()[1].clone()),
        c: Some(Integer::from_str("843105902970788695411197846605744081831851").unwrap()),
        ..Default::default()
    };

    let solution_2 = run_attacks(&params_2).unwrap();
    assert!(solution_2.pk.is_some());

    assert_eq!(
        integer_to_string(&solution_1.m.unwrap()).unwrap()
            + &integer_to_string(&solution_2.m.unwrap()).unwrap(),
        "tjctf{n0t_s0_S3cur3_Cryp70}"
    );
}

#[test]
fn tjctf_2022_factor_master_stage1() {
    // From TJCTF 2022 / Factor Master - Stage 1
    // https://ctftime.org/task/21337

    let params = Parameters {
        n : Some(Integer::from_str("3078022440801373210337104721383788945269841345540381786461869466047167774292910507898271854415088423387441878003635925671242403990130707600286208825860598185366502783389401946255254009805550183195848597802674713816105514808690440034054131157345378931099830908251595958813150564857519044414566388971863597746025212116903383").unwrap()),
        ..Default::default()

    };

    let solution = run_specific_attacks(&params, &[Arc::new(EcmAttack)]).unwrap();
    assert!(solution.pk.is_some());
}

#[test]
fn tjctf_2022_factor_master_stage2() {
    // From TJCTF 2022 / Factor Master - Stage 2
    // https://ctftime.org/task/21337

    let params = Parameters {
        n : Some(Integer::from_str("12523075107893791979670086707623506471576547212425605718643256089034062921399670612867694943757055085178349600784468258775145279570350968588029532994484280605541161840043110768095556920359586801820737108058642407027816389045132065321568733220795809976422394948165878992741595084450271085800087160926998447040235530905682615573443593633635200340671667136194543093004548023552293122118621043983922325072588081963997257093699835276232119055313001936359282917797012144687265278587815357965203828734724403209938137378759948258101691362201357271541579478013729291487873561103240859749343463562093825705218044527322177571787").unwrap()),
        ..Default::default()

    };

    let solution = run_specific_attacks(&params, &[Arc::new(FermatAttack)]).unwrap();
    assert!(solution.pk.is_some());
}

#[test]
fn tjctf_2022_factor_master_stage3() {
    // From TJCTF 2022 / Factor Master - Stage 3
    // https://ctftime.org/task/21337

    let params = Parameters {
        n : Some(Integer::from_str("16775456867805984728872686858263669312523071985853423544832928914931466217497916500304025842334595069035893304826620713035067403632775326650638807721909986534273067175278036732714548718290260916614452578629041971960641973778516135495150910189458704151718760604252770859136939228039374420738485738280093347995422837742415700003539840808831343305209121350268278898733608200955655642536521306373413919713006708021680593130914807322718252140665334149540148154741946451629086971070985334632116582612652704935888565314234428659775099169962107057045209761211583044825424787313273960727038228937171903535958015936788395270469").unwrap()),
        ..Default::default()

    };

    let solution = run_specific_attacks(&params, &[Arc::new(PollardPM1Attack)]).unwrap();
    assert!(solution.pk.is_some());
}
