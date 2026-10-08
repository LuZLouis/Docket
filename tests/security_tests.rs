use curve25519_dalek::scalar::Scalar;
use docket_rs::{
    crypto::{predicate_prove, predicate_verify, signed, Bases, Profile},
    protocol::Config,
};

fn config() -> Config {
    Config {
        round: "threshold-test".into(),
        n: 4,
        m: 4,
        t: 3,
        f_r: 1,
        f_c: 1,
        unavailable: 0,
        dim: 2,
        profile: Profile::Native,
        bound: 7,
        norm: None,
        receipt_cutoff: 5,
        appeal_cutoff: 10,
    }
}

#[test]
fn threshold_and_progress_requirements_fail_closed() {
    let mut c = config();
    assert!(c.validate().is_ok());
    c.t = 2;
    assert!(c.validate().is_err()); // 2t <= m + f_R
    c.t = 3;
    c.f_r = 3;
    assert!(c.validate().is_err()); // f_R >= t
    c.f_r = 1;
    c.unavailable = 2;
    assert!(c.validate().is_err()); // t > m - f_R - d_R
}

#[test]
fn actual_bulletproofs_enforces_both_signed_endpoints() {
    let g = Bases::new(2);
    let values = [-7, 7];
    let blind = [Scalar::from(11u64), Scalar::from(13u64)];
    let cs = values
        .iter()
        .zip(blind)
        .map(|(x, b)| g.g * signed(*x) + g.h * b)
        .collect::<Vec<_>>();
    let proof = predicate_prove([9; 32], 0, &values, &blind, &cs, 7, None, &g).unwrap();
    predicate_verify([9; 32], 0, &cs, &proof, 7, None, &g).unwrap();
    assert!(predicate_verify([8; 32], 0, &cs, &proof, 7, None, &g).is_err());
    assert!(predicate_prove([9; 32], 0, &[-8, 7], &blind, &cs, 7, None, &g).is_err());
    assert!(predicate_prove([9; 32], 0, &[-7, 8], &blind, &cs, 7, None, &g).is_err());
}
