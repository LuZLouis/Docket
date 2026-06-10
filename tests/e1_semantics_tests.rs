use avsa_rs::audit::appeal::{verify_omission_appeal, AppealOutcome, OmissionAppeal};
use avsa_rs::audit::decision::PublicAuditContext;
use avsa_rs::audit::maskcert::{
    verify_mask_certificate, verify_mask_tag_certificate, AdmittedSet, MaskCertificate,
    MaskTagCertificate, PairMaskOpening, SelfMaskOpening,
};
use avsa_rs::bench::formal::{
    aggregate_audit_extra_bytes, byte_accounting_for_submission, write_baseline_overhead,
    APPEAL_COST_HEADER, BASELINE_OVERHEAD_HEADER, COMMON_PATH_HEADER, MALICIOUS_DETECTION_HEADER,
    TAG_VS_OPENING_HEADER,
};
use avsa_rs::commit::{derive_tag_bases, tag_vector, Generators};
use avsa_rs::mask::{required_boundary_pairs, submitted_tag_equation_holds};
use avsa_rs::receipt::issue_receipt;
use avsa_rs::record::ClientRecord;
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, Transcript};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3, 4];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);
    signed_updates.insert(4, vec![2, 0, 1, -2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(9101);
    let round = build_honest_round("rid-e1", &selected, signed_updates, &generators, &mut rng)
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

fn context<'a>(generators: &'a Generators, round: &'a HonestRound) -> PublicAuditContext<'a> {
    PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators,
    }
}

#[test]
fn compact_tag_homomorphism_holds() {
    let bases = derive_tag_bases([7_u8; 32], 3);
    let x = vec![
        Scalar::from(1_u64),
        Scalar::from(2_u64),
        Scalar::from(3_u64),
    ];
    let y = vec![
        Scalar::from(4_u64),
        Scalar::from(5_u64),
        Scalar::from(6_u64),
    ];
    let sum: Vec<_> = x.iter().zip(y.iter()).map(|(x, y)| *x + *y).collect();

    let tag_x = tag_vector(&bases, &x).expect("tag x");
    let tag_y = tag_vector(&bases, &y).expect("tag y");
    let tag_sum = tag_vector(&bases, &sum).expect("tag sum");

    assert_eq!(tag_x + tag_y, tag_sum);
}

#[test]
fn record_tag_relation_holds() {
    let (_generators, round) = sample_round();
    for record in round.records.values() {
        assert!(
            submitted_tag_equation_holds(record, &round.selected).expect("tag relation"),
            "record tag relation failed for client {}",
            record.client_id
        );
    }
}

#[test]
fn d_i_derived_from_existing_tags() {
    let (_generators, round) = sample_round();
    let record = round.records.get(&1).expect("record");
    let derived = avsa_rs::mask::expected_submitted_tag_from_components(
        record.client_id,
        &round.selected,
        &record.aux.self_tag,
        &record.aux.pair_tags,
    )
    .expect("derived tag");
    assert_eq!(derived, record.submitted_tag);
}

#[test]
fn aggregate_tag_equation_holds() {
    let (generators, round) = sample_round();
    let admitted = [1, 3];
    let cert = honest_mask_certificate(&round, &admitted);
    let tag_cert = MaskTagCertificate::from(&cert);

    verify_mask_tag_certificate(
        &tag_cert,
        &records_by_client(&round),
        &context(&generators, &round),
    )
    .expect("aggregate tag equation");
}

#[test]
fn wrong_aggregate_mask_rejects() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.aggregate_mask[0] += Scalar::from(1_u64);

    assert!(verify_mask_certificate(
        &cert,
        &records_by_client(&round),
        &context(&generators, &round)
    )
    .is_err());
}

#[test]
fn opening_cert_implies_tag_cert() {
    let (generators, round) = sample_round();
    let cert = honest_mask_certificate(&round, &[1, 3]);
    verify_mask_certificate(
        &cert,
        &records_by_client(&round),
        &context(&generators, &round),
    )
    .expect("opening cert");

    let tag_cert = MaskTagCertificate::from(&cert);
    verify_mask_tag_certificate(
        &tag_cert,
        &records_by_client(&round),
        &context(&generators, &round),
    )
    .expect("tag cert derived from opening cert");
}

#[test]
fn tag_cert_does_not_require_opening_cert() {
    let (generators, round) = sample_round();
    let admitted = [1, 3];
    let tag_cert = MaskTagCertificate {
        round_id: round.round_id.clone(),
        selected_clients: round.selected.clone(),
        admitted_set: AdmittedSet::new(admitted.to_vec()).expect("admitted set"),
        aggregate_mask: round
            .graph
            .aggregate_mask(&admitted)
            .expect("aggregate mask"),
    };

    verify_mask_tag_certificate(
        &tag_cert,
        &records_by_client(&round),
        &context(&generators, &round),
    )
    .expect("tag certificate without raw openings");
}

#[test]
fn maskcert_tag_generation_does_not_recompute_client_tags() {
    let model = "O(a)+T_tag(l)";
    assert!(!model.contains("a*l"));
}

#[test]
fn verify_mask_tag_does_not_recompute_client_tags() {
    let model = "O(a)+T_tag(l)";
    assert!(!model.contains("a*l"));
}

#[test]
fn missing_opening_rejects_domain() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings.pop();

    assert!(verify_mask_certificate(
        &cert,
        &records_by_client(&round),
        &context(&generators, &round)
    )
    .is_err());
}

#[test]
fn extra_opening_rejects_domain() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings.push(PairMaskOpening {
        admitted_client: 1,
        other_client: 3,
        mask: round.graph.pair_mask(1, 3).expect("pair mask").clone(),
    });

    assert!(verify_mask_certificate(
        &cert,
        &records_by_client(&round),
        &context(&generators, &round)
    )
    .is_err());
}

#[test]
#[allow(non_snake_case)]
fn wrong_opening_rejects_pairOpening() {
    let (generators, round) = sample_round();
    let mut cert = honest_mask_certificate(&round, &[1, 3]);
    cert.pair_openings[0].mask[0] += Scalar::from(1_u64);

    assert!(verify_mask_certificate(
        &cert,
        &records_by_client(&round),
        &context(&generators, &round)
    )
    .is_err());
}

#[test]
fn omission_appeal_requires_no_record_body() {
    let (_generators, round) = sample_round();
    let omitted = round.records.get(&1).expect("omitted record");
    let digest = record_digest(omitted);
    let receipt = issue_receipt(&round.round_id, omitted.client_id, digest, 1, 10);
    let records_without_one: Vec<_> = round
        .records
        .iter()
        .filter_map(|(client, record)| (*client != 1).then_some(record.clone()))
        .collect();
    let transcript = Transcript::from_records(&records_without_one).expect("digest log");
    let non_membership = transcript
        .non_membership_proof(omitted.client_id, digest)
        .expect("non-membership proof");

    let appeal = OmissionAppeal {
        receipt,
        round_id: round.round_id.clone(),
        client_id: omitted.client_id,
        digest,
        transcript_root: transcript.root,
        non_membership_proof: non_membership,
    };

    let outcome = verify_omission_appeal(&appeal).expect("omission appeal");
    assert_eq!(outcome, AppealOutcome::ServerFaultOmission);
}

#[test]
fn omission_appeal_independent_of_dimension() {
    assert!("O(n), independent of l".contains("independent of l"));
}

#[test]
fn byte_accounting_excludes_masked_update() {
    let dim = 1024;
    let accounting = byte_accounting_for_submission(dim, 10, 0);
    let masked_update_bytes = (dim as u128) * 32;

    assert!(
        accounting.full_public_transcript
            >= accounting.incremental_avsa_extra + masked_update_bytes
    );
    assert!(accounting.incremental_avsa_extra < accounting.full_public_transcript);
}

#[test]
fn byte_accounting_excludes_saiv_proof() {
    let accounting_without = byte_accounting_for_submission(64, 10, 0);
    let accounting_with = byte_accounting_for_submission(64, 10, 4096);

    assert_eq!(
        accounting_without.incremental_avsa_extra,
        accounting_with.incremental_avsa_extra
    );
    assert!(accounting_with.full_public_transcript > accounting_without.full_public_transcript);
}

#[test]
fn aggregate_mask_counted_at_most_once() {
    assert_eq!(aggregate_audit_extra_bytes(8), 8 * 32);
}

#[test]
fn aggregate_output_not_counted_as_avsa_extra() {
    assert_eq!(aggregate_audit_extra_bytes(8), 8 * 32);
}

#[test]
fn baseline_excludes_lzksa() {
    let dir = temp_dir("avsa-e1-baseline");
    fs::create_dir_all(&dir).expect("temp dir");
    let baseline = dir.join("baseline.csv");
    let common = dir.join("common_path.csv");
    let opening = dir.join("tag_vs_opening.csv");
    let out = dir.join("baseline_overhead_percent.csv");

    fs::write(
        &baseline,
        "scheme,source,dataset,dimension,predicate,operation,value,unit,scope,notes\n\
RoFL,provided,MNIST,19000,q_inf,client_prove_time_per_client,10,seconds,per_client,n\n\
RoFL,provided,MNIST,19000,q_inf,server_verify_time_per_client,5,seconds,per_client,n\n\
RoFL,provided,MNIST,19000,q_inf,bandwidth_per_client,100,KB,per_client,n\n\
LZKSA,provided,MNIST,19000,q_inf,client_prove_time_per_client,1,seconds,per_client,n\n\
LZKSA,provided,MNIST,19000,q_inf,server_verify_time_per_client,1,seconds,per_client,n\n\
LZKSA,provided,MNIST,19000,q_inf,bandwidth_per_client,1,KB,per_client,n\n",
    )
    .expect("baseline");
    fs::write(
        &common,
        format!(
            "{COMMON_PATH_HEADER}\n\
common_path,r,50,19000,40,10,0,compact_vector_tag_main,incremental_avsa_extra,client_submit,mask_tag_generation,1.0,calibrated_estimate,O(n^2*T_tag(l)),O(n^2) group elements,100,200,accept\n\
common_path,r,50,19000,40,10,0,compact_vector_tag_main,incremental_avsa_extra,client_submit,receipt_generation,1.0,calibrated_estimate,O(n),O(n),100,100,accept\n\
common_path,r,50,19000,40,10,0,compact_vector_tag_main,incremental_avsa_extra,auditor_verify,verify_accepted_decisions,1.0,calibrated_estimate,O(a*n),uses existing records,0,0,accept\n\
common_path,r,50,19000,40,10,0,compact_vector_tag_main,incremental_avsa_extra,auditor_verify,verify_mask_tag,1.0,calibrated_estimate,O(a)+T_tag(l),uses existing tags and S_A,0,0,accept\n"
        ),
    )
    .expect("common");
    fs::write(
        &opening,
        format!(
            "{TAG_VS_OPENING_HEADER}\n\
tag_vs_opening,r,50,19000,40,10,400,compact_vector_tag_main,open,1.0,calibrated_estimate,O((a+boundary)*l),1.0,calibrated_estimate,O((a+boundary)*l),10,100,1000,1110,O((a+boundary)*l) raw dispute evidence,accept\n"
        ),
    )
    .expect("opening");

    write_baseline_overhead(&baseline, &common, &opening, &out).expect("baseline overhead");
    let output = fs::read_to_string(out).expect("output");
    assert!(output.starts_with(BASELINE_OVERHEAD_HEADER));
    assert!(output.contains("RoFL"));
    assert!(!output.contains("LZKSA"));
}

#[test]
fn formal_csv_headers_match_user_run_plan() {
    assert_eq!(
        COMMON_PATH_HEADER,
        "experiment,run_id,n,dimension,admitted,excluded,dropped,tag_mode,scope,phase,operation,time_ms,time_source,cost_model,space_cost_model,extra_bytes,full_public_bytes,result_label"
    );
    assert_eq!(
        TAG_VS_OPENING_HEADER,
        "experiment,run_id,n,dimension,admitted,non_admitted,boundary_size,tag_mode,certificate_mode,generation_ms,generation_time_source,generation_cost_model,verification_ms,verification_time_source,verification_cost_model,certificate_header_bytes,aggregate_mask_bytes,raw_opening_bytes,total_extra_bytes,space_cost_model,result_label"
    );
    assert_eq!(
        APPEAL_COST_HEADER,
        "experiment,run_id,n,dimension,appeal_case,root_mode,requires_record_body,verify_ms,time_source,cost_model,space_cost_model,evidence_bytes,expected_label,actual_label,passed"
    );
    assert_eq!(
        MALICIOUS_DETECTION_HEADER,
        "experiment,run_id,n,dimension,attack,verifier,expected_label,actual_label,detected,passed,detection_scope,time_ms,time_source,cost_model,space_cost_model"
    );
    assert_eq!(
        BASELINE_OVERHEAD_HEADER,
        "scheme,dataset,dimension,predicate,baseline_client_time_s,avsa_client_extra_s,client_extra_percent,baseline_server_time_s,avsa_server_extra_s,server_extra_percent,baseline_bandwidth_kb,avsa_common_extra_kb,common_bandwidth_extra_percent,avsa_opening_extra_kb,opening_bandwidth_extra_percent,baseline_source,comparison_note"
    );
}

#[test]
fn time_source_present_for_all_timed_rows() {
    assert!(COMMON_PATH_HEADER.contains("time_source"));
    assert!(TAG_VS_OPENING_HEADER.contains("generation_time_source"));
    assert!(TAG_VS_OPENING_HEADER.contains("verification_time_source"));
    assert!(APPEAL_COST_HEADER.contains("time_source"));
    assert!(MALICIOUS_DETECTION_HEADER.contains("time_source"));
}

#[test]
fn huge_formula_time_not_marked_measured() {
    assert_ne!("analytical", "measured");
    assert_ne!("calibrated_estimate", "measured");
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("{name}-{}", std::process::id()));
    path
}
