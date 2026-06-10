use avsa_rs::params::{AvsaParams, ROUND1_HOST_NO_WRAP_Q_HALF};

#[test]
fn params_reject_invalid_no_wraparound() {
    let invalid_b2 = AvsaParams {
        dim: 4,
        n_selected: 3,
        n_max_admitted: 3,
        b_inf: 10,
        b2_sq: ROUND1_HOST_NO_WRAP_Q_HALF,
    };
    assert!(invalid_b2.validate().is_err());

    let invalid_coordinate_sum = AvsaParams {
        dim: 4,
        n_selected: usize::MAX,
        n_max_admitted: usize::MAX,
        b_inf: i64::MAX,
        b2_sq: 16,
    };
    assert!(invalid_coordinate_sum.validate().is_err());
}
