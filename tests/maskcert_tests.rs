use avsa_rs::audit::decision::PublicAuditContext;
use avsa_rs::audit::maskcert::{
    verify_mask_certificate, AdmittedSet, MaskCertificate, PairMaskOpening, SelfMaskOpening,
};
use avsa_rs::commit::Generators;
use avsa_rs::mask::required_boundary_pairs;
use avsa_rs::record::ClientRecord;
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3, 4];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);
    signed_updates.insert(4, vec![2, 0, 1, -2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(71);
    let round = build_honest_round(
        "rid-maskcert",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");
    (generators, round)
}

fn honest_mask_certificate(round: &HonestRound, admitted: &[u64]) -> MaskCertificate {
    let self_openings = admitted
        .iter()
        .map(|client| SelfMaskOpening {
            client_id: *client,
            mask: round.graph.self_mask(*client).expect("self mask").clone(),
        })
        .collect();
    let pair_openings = required_boundary_pairs(&round.selected, admitted)
        .expect("boundary pairs")
        .into_iter()
        .map(|(admitted_client, other_client)| PairMaskOpening {
            admitted_client,
            other_client,
            mask: round
                .graph
                .pair_mask(admitted_client, other_client)
                .expect("pair mask")
                .clone(),
        })
        .collect();

    MaskCertificate {
        round_id: round.round_id.clone(),
        selected_clients: round.selected.clone(),
        admitted_set: AdmittedSet::new(admitted.to_vec()).expect("admitted set"),
        aggregate_mask: round
            .graph
            .aggregate_mask(admitted)
            .expect("aggregate mask"),
        self_openings,
        pair_openings,
    }
}

fn records_by_client(round: &HonestRound) -> BTreeMap<u64, ClientRecord> {
    round.records.clone()
}

#[test]
fn verify_mask_certificate_accepts_honest_certificate() {
    let (generators, round) = sample_round();
    let cert = honest_mask_certificate(&round, &[1, 3]);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    verify_mask_certificate(&cert, &records_by_client(&round), &context)
        .expect("honest mask certificate");
}

#[test]
fn missing_self_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.self_openings.pop();
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn extra_self_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.self_openings.push(SelfMaskOpening {
        client_id: 2,
        mask: round.graph.self_mask(2).expect("self mask").clone(),
    });
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn wrong_self_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.self_openings[0].mask[0] = cert.self_openings[0].mask[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn missing_boundary_pair_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings.pop();
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn extra_boundary_pair_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings.push(PairMaskOpening {
        admitted_client: 1,
        other_client: 3,
        mask: round.graph.pair_mask(1, 3).expect("pair mask").clone(),
    });
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn wrong_boundary_pair_opening_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings[0].mask[0] = cert.pair_openings[0].mask[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn wrong_pair_orientation_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    let first = &mut cert.pair_openings[0];
    let admitted_client = first.admitted_client;
    first.admitted_client = first.other_client;
    first.other_client = admitted_client;
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn wrong_aggregate_mask_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.aggregate_mask[0] = cert.aggregate_mask[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn aggregate_tag_relation_mismatch_rejects() {
    let (generators, round) = sample_round();
    let cert = honest_mask_certificate(&round, &[1, 3]);
    let mut records = records_by_client(&round);
    let record = records.get_mut(&1).expect("record");
    record.submitted_tag += generators.k;
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records, &context).is_err());
}

#[test]
fn admitted_set_with_duplicate_client_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.admitted_set = AdmittedSet {
        clients: vec![1, 1],
    };
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}

#[test]
fn admitted_set_not_subset_of_selected_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.admitted_set = AdmittedSet {
        clients: vec![1, 5],
    };
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_mask_certificate(&cert, &records_by_client(&round), &context).is_err());
}
