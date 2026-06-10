use avsa_rs::commit::{Generators, PointVector};
use avsa_rs::proof::range::{
    shift_commitments, shift_signed_values, signed_range_prove, signed_range_verify,
    MockRangeProof, MockRangeProofBackend, RangeProofBackend, RangeProofContext,
};
use avsa_rs::vector::{encode_signed_vector, random_scalar_vector, ScalarVector};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn committed_signed_values(values: &[i64]) -> (Generators, ScalarVector, PointVector) {
    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    let encoded = encode_signed_vector(values);
    let blindings = random_scalar_vector(values.len(), &mut rng);
    let commitments = generators
        .commit_vector(&encoded, &blindings)
        .expect("commitments");
    (generators, blindings, commitments)
}

#[test]
fn mock_range_backend_accepts_valid_shifted_commitments() {
    let signed_values = vec![-2, 0, 3];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let shifted_values = shift_signed_values(&signed_values, 3).expect("shifted values");
    let shifted_commitments =
        shift_commitments(&commitments, 3, &generators).expect("shifted commitments");
    let context =
        RangeProofContext::new("rid-range", 7, 3, 3, &shifted_commitments).expect("range context");

    let proof = MockRangeProofBackend::prove_range(
        &context,
        &shifted_commitments,
        &shifted_values,
        &blindings,
        3,
        &generators,
    )
    .expect("mock prove");

    MockRangeProofBackend::verify_range(&context, &shifted_commitments, &proof, 3, &generators)
        .expect("mock verify");
}

#[test]
fn mock_range_backend_rejects_value_out_of_unsigned_range() {
    let generators = Generators::default();
    let blindings = vec![Scalar::from(9_u64)];
    let shifted_values = vec![4_u64];
    let shifted_commitments = vec![generators.commit_scalar(Scalar::from(4_u64), blindings[0])];
    let context =
        RangeProofContext::new("rid-range", 7, 1, 2, &shifted_commitments).expect("range context");
    let proof = MockRangeProof {
        context_digest: context.digest(),
        shifted_values,
        blindings,
    };

    assert!(MockRangeProofBackend::verify_range(
        &context,
        &shifted_commitments,
        &proof,
        2,
        &generators,
    )
    .is_err());
}

#[test]
fn mock_range_backend_rejects_tampered_blinding() {
    let signed_values = vec![-2, 0, 3];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let shifted_values = shift_signed_values(&signed_values, 3).expect("shifted values");
    let shifted_commitments =
        shift_commitments(&commitments, 3, &generators).expect("shifted commitments");
    let context =
        RangeProofContext::new("rid-range", 7, 3, 3, &shifted_commitments).expect("range context");
    let mut proof = MockRangeProofBackend::prove_range(
        &context,
        &shifted_commitments,
        &shifted_values,
        &blindings,
        3,
        &generators,
    )
    .expect("mock prove");
    proof.blindings[0] = proof.blindings[0] + Scalar::from(1_u64);

    assert!(MockRangeProofBackend::verify_range(
        &context,
        &shifted_commitments,
        &proof,
        3,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_proof_accepts_honest_vector() {
    let signed_values = vec![-3, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        3,
        &generators,
    )
    .expect("signed range proof");

    signed_range_verify::<MockRangeProofBackend>("rid-range", 7, &commitments, &proof, &generators)
        .expect("signed range verify");
}

#[test]
fn signed_range_prove_rejects_value_above_bound() {
    let signed_values = vec![4];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);

    assert!(signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        3,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_prove_rejects_value_below_bound() {
    let signed_values = vec![-4];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);

    assert!(signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        3,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_tampered_commitment() {
    let signed_values = vec![-3, 0, 2];
    let (generators, blindings, mut commitments) = committed_signed_values(&signed_values);
    let proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");
    commitments[0] = commitments[0] + generators.g;

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_tampered_shifted_commitment() {
    let signed_values = vec![-3, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let mut proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");
    proof.shifted_commitments[0] = proof.shifted_commitments[0] + generators.g;

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_wrong_round_id() {
    let signed_values = vec![-3, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-other",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_wrong_client_id() {
    let signed_values = vec![-3, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-range",
        8,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_wrong_bound() {
    let signed_values = vec![-2, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let mut proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");
    proof.b_inf = 2;

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_verify_rejects_wrong_bit_size() {
    let signed_values = vec![-2, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let mut proof = signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        4,
        &generators,
    )
    .expect("signed range proof");
    proof.bit_size = 5;

    assert!(signed_range_verify::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn signed_range_dimension_mismatch_rejects() {
    let signed_values = vec![-2, 0, 2];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);

    assert!(signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values[..2],
        &blindings,
        3,
        4,
        &generators,
    )
    .is_err());
}

#[test]
fn bit_size_too_small_for_bound_rejects() {
    let signed_values = vec![0];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);

    assert!(signed_range_prove::<MockRangeProofBackend>(
        "rid-range",
        7,
        &commitments,
        &signed_values,
        &blindings,
        8,
        4,
        &generators,
    )
    .is_err());
}
