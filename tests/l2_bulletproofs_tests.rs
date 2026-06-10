#![cfg(feature = "bulletproofs-backend")]

use avsa_rs::commit::{Generators, PointVector};
use avsa_rs::proof::l2::{l2_prove, l2_verify, L2Proof, L2Statement, L2Witness};
use avsa_rs::proof::range::{BulletproofsRangeBackend, BulletproofsRangeProof};
use avsa_rs::vector::{encode_signed_vector, random_scalar_vector, ScalarVector};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn committed_signed_values(values: &[i64]) -> (Generators, ScalarVector, PointVector) {
    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(401);
    let encoded = encode_signed_vector(values);
    let blindings = random_scalar_vector(values.len(), &mut rng);
    let commitments = generators
        .commit_vector(&encoded, &blindings)
        .expect("commitments");
    (generators, blindings, commitments)
}

fn bulletproofs_l2_proof(
    values: &[i64],
) -> (
    Generators,
    ScalarVector,
    PointVector,
    L2Proof<BulletproofsRangeProof>,
) {
    let (generators, blindings, commitments) = committed_signed_values(values);
    let statement = L2Statement {
        rid: "rid-l2-bulletproofs",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 8,
    };
    let witness = L2Witness {
        values,
        blindings: &blindings,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(403);
    let proof =
        l2_prove::<BulletproofsRangeBackend, _>(&statement, &witness, &generators, &mut rng)
            .expect("Bulletproofs-backed L2 proof");
    (generators, blindings, commitments, proof)
}

#[test]
fn l2_proof_with_bulletproofs_backend_accepts_honest_vector() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = bulletproofs_l2_proof(&values);
    let statement = L2Statement {
        rid: "rid-l2-bulletproofs",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 8,
    };

    l2_verify::<BulletproofsRangeBackend>(&statement, &proof, &generators)
        .expect("Bulletproofs-backed L2 verifies");
}

#[test]
fn l2_proof_object_has_no_witness_values_with_bulletproofs_backend() {
    let values = vec![1, -2, 2];
    let (_generators, _blindings, _commitments, proof) = bulletproofs_l2_proof(&values);
    let proof_debug = format!("{:?}", proof);
    let backend_debug = format!("{:?}", proof.range_proof);

    assert!(!backend_debug.contains("shifted_values"));
    assert!(!backend_debug.contains("blindings"));
    assert!(!proof_debug.contains("values:"));
    assert!(!proof_debug.contains("blindings:"));
}
