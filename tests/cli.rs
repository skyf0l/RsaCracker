fn run_bin(args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rsacracker"));
    cmd.args(args)
        .env("RSACRACKER_DISABLE_UPDATE", "1")
        .output()
        .expect("failed to run rsacracker binary")
}

// picoCTF 2019 b00tl3gRSA2 parameters (Wiener attack)
const N: &str = "93596195645610503452177719837666902345047461004926714393186384188598288812343005592124086521572864457489909063543756427769917131437307447863586528928496194559057760628385975297585140789577911616474493538014622500120560643072265673362843715324209056486085041020831625385434745566998218712055519575753745124619";
const E: &str = "1595235523996321655798747471789583440185208568327862733680046250799766370193739982702940394656406146131440688831932739213253542820322450207724280220533900355744553772981019201731036379810734890063829650829319133004906034534031330743611288482822751674556919861911431941749713177767003275664528498846275096193";
const C: &str = "78394077185972242522366494812194999029111007804513916081388100744678077142246684573709463174914072230588766938274935729449697899122556506361108922139286130431073819269477944903949010409297739704373353086560177410340042335176831160010922826152074048460889509110907225759217407138633733239524781798190577093673";
const FLAG: &str = "picoCTF{bad_1d3a5_2152720}";

// Cipher present via --raw file -> decrypt, no factor output
#[test]
fn raw_file_with_cipher_decrypts() {
    let output = run_bin(&[
        "--raw",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/raw/picoctf_2019_b00tl3grsa2.txt"
        ),
        "--attack=wiener",
    ]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FLAG),
        "expected decrypted flag in stdout, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Factors of n:"),
        "must not print factors when cipher is present in raw file, got:\n{stdout}"
    );
}

// No cipher in --raw file -> show factors by default, no decryption output
#[test]
fn raw_file_without_cipher_shows_factors() {
    let output = run_bin(&[
        "--raw",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/raw/no_cipher_wiener.txt"
        ),
        "--attack=wiener",
    ]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Factors of n:"),
        "expected factor output when no cipher is present in raw file, got:\n{stdout}"
    );
    assert!(
        stdout.contains("p =") && stdout.contains("q ="),
        "expected p and q in factor output, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("m ="),
        "must not print decryption output when no cipher is present, got:\n{stdout}"
    );
}

// Cipher present via -c flag -> decrypt, no factor output
#[test]
fn cli_flags_with_cipher_decrypts() {
    let output = run_bin(&["-n", N, "-e", E, "-c", C, "--attack=wiener"]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FLAG),
        "expected decrypted flag in stdout, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Factors of n:"),
        "must not print factors when -c flag is provided, got:\n{stdout}"
    );
}

// --factors flag forces factor output even when cipher is present, no decryption output
#[test]
fn cli_flags_with_cipher_and_factors_flag_shows_factors() {
    let output = run_bin(&["-n", N, "-e", E, "-c", C, "--attack=wiener", "--factors"]);

    assert!(
        output.status.success(),
        "process failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Factors of n:"),
        "expected factor output when --factors is passed, got:\n{stdout}"
    );
    assert!(
        !stdout.contains(FLAG),
        "must not print decryption output when --factors is passed, got:\n{stdout}"
    );
}
