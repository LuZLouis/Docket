use crate::audit::aggregate::{verify_aggregate_certificate, AggregateCertificate};
use crate::audit::appeal::verify_appeal;
use crate::audit::decision::{
    verify_accepted_decision, AcceptAllPredicateVerifier, DecisionCertificate, DecisionEntry,
    DecisionStatus, PublicAuditContext, RejectReason,
};
use crate::audit::maskcert::{
    verify_mask_certificate, AdmittedSet, MaskCertificate, PairMaskOpening, SelfMaskOpening,
};
use crate::bench::cases::{BenchBackend, BenchConfig};
use crate::commit::Generators;
use crate::mask::{aggregate_output, required_boundary_pairs};
use crate::proof::l2::{l2_prove, l2_verify, L2Proof, L2Statement, L2Witness};
use crate::proof::range::{
    signed_range_prove, signed_range_verify, MockRangeProof, MockRangeProofBackend,
    RangeProofBackend, SignedRangeProof,
};
use crate::proof::submit::{
    ordered_peer_tags_from_map, submit_prove, submit_verify_record, SubmitPublicInputs,
    SubmitWitness,
};
use crate::receipt::{issue_receipt_for_record, verify_receipt, ServerReceipt};
use crate::record::ClientRecord;
use crate::sim::round::{build_honest_round, HonestRound};
use crate::transcript::{record_digest, verify_record_membership, MembershipProof, Transcript};
use crate::{AvsaError, ClientId, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(feature = "bulletproofs-backend")]
use crate::proof::range::{BulletproofsRangeBackend, BulletproofsRangeProof};

pub const RUNTIME_HEADER: &str = "run_id,backend,case_name,n_selected,n_admitted,n_dropped,n_rejected,dim,b_inf,b2_sq,bit_size,component,operation,iterations,warmup,mean_ms,p50_ms,p95_ms,min_ms,max_ms,success";
pub const SIZE_HEADER: &str = "run_id,backend,case_name,n_selected,n_admitted,n_dropped,n_rejected,dim,object_type,count,total_bytes,mean_bytes,min_bytes,max_bytes";
pub const CORRECTNESS_HEADER: &str =
    "run_id,backend,case_name,check_name,expected,observed,success,error";

#[derive(Clone, Debug)]
pub struct BenchRunSummary {
    pub runtime_rows: usize,
    pub size_rows: usize,
    pub correctness_rows: usize,
    pub success: bool,
    pub out_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct BenchRound<P> {
    pub generators: Generators,
    pub round: HonestRound,
    pub admitted: Vec<ClientId>,
    pub dropped: Vec<ClientId>,
    pub rejected: Vec<ClientId>,
    pub records: Vec<ClientRecord>,
    pub transcript: Transcript,
    pub receipts: BTreeMap<ClientId, ServerReceipt>,
    pub decision_cert: DecisionCertificate,
    pub decision_entries: Vec<DecisionEntry>,
    pub mask_certificate: MaskCertificate,
    pub aggregate_certificate: AggregateCertificate,
    pub signed_range_proofs: BTreeMap<ClientId, SignedRangeProof<P>>,
    pub l2_proofs: BTreeMap<ClientId, L2Proof<P>>,
}

pub trait BenchProofBytes {
    fn write_bench_bytes(&self, out: &mut Vec<u8>);
}

impl BenchProofBytes for MockRangeProof {
    fn write_bench_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.context_digest);
        push_u64(out, self.shifted_values.len() as u64);
        for value in &self.shifted_values {
            push_u64(out, *value);
        }
        push_scalar_slice(out, &self.blindings);
    }
}

#[cfg(feature = "bulletproofs-backend")]
impl BenchProofBytes for BulletproofsRangeProof {
    fn write_bench_bytes(&self, out: &mut Vec<u8>) {
        push_u64(out, self.proof_chunks.len() as u64);
        for chunk in &self.proof_chunks {
            push_len_prefixed(out, &chunk.proof_bytes);
        }
    }
}

pub fn run(config: &BenchConfig) -> Result<BenchRunSummary> {
    match config.backend {
        BenchBackend::Mock => run_with_backend::<MockRangeProofBackend>(config),
        BenchBackend::Bulletproofs => run_bulletproofs(config),
    }
}

#[cfg(feature = "bulletproofs-backend")]
fn run_bulletproofs(config: &BenchConfig) -> Result<BenchRunSummary> {
    run_with_backend::<BulletproofsRangeBackend>(config)
}

#[cfg(not(feature = "bulletproofs-backend"))]
fn run_bulletproofs(_config: &BenchConfig) -> Result<BenchRunSummary> {
    Err(AvsaError::UnsupportedBenchBackend(
        "bulletproofs backend requires --features bulletproofs-backend".into(),
    ))
}

pub fn generate_bench_round<B: RangeProofBackend>(
    config: &BenchConfig,
) -> Result<BenchRound<B::Proof>> {
    config.validate()?;
    let selected = config.selected_clients()?;
    let admitted = config.admitted_clients()?;
    let dropped = config.dropped_clients()?;
    let rejected = config.rejected_clients()?;
    let signed_updates = generate_signed_updates(config, &selected)?;
    let generators = Generators::default();
    let mut rng = StdRng::seed_from_u64(config.seed ^ 0xA75A_BEEF);
    let round = build_honest_round(
        format!("rid-bench-{}-{}", config.case_name(), config.seed),
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .map_err(|err| AvsaError::BenchGenerationFailed(err.to_string()))?;
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records)
        .map_err(|err| AvsaError::BenchGenerationFailed(err.to_string()))?;
    let receipts = records
        .iter()
        .map(|record| (record.client_id, issue_receipt_for_record(record, 1, 10)))
        .collect();
    let (decision_cert, decision_entries) =
        decision_certificate(&round, &transcript, &admitted, &dropped, &rejected);
    let mask_certificate = honest_mask_certificate(&round, &admitted)?;
    let aggregate_certificate =
        honest_aggregate_certificate(&round, &admitted, &decision_cert, &mask_certificate)?;
    let signed_range_proofs = signed_range_proofs::<B>(&round, config, &generators)?;
    let l2_proofs = l2_proofs::<B>(&round, config, &generators)?;

    Ok(BenchRound {
        generators,
        round,
        admitted,
        dropped,
        rejected,
        records,
        transcript,
        receipts,
        decision_cert,
        decision_entries,
        mask_certificate,
        aggregate_certificate,
        signed_range_proofs,
        l2_proofs,
    })
}

fn run_with_backend<B>(config: &BenchConfig) -> Result<BenchRunSummary>
where
    B: RangeProofBackend,
    B::Proof: BenchProofBytes,
{
    config.validate()?;
    create_dir_all(&config.out_dir)
        .map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;

    let artifacts = generate_bench_round::<B>(config)?;
    let mut runtime_rows = Vec::new();
    let mut correctness_rows = Vec::new();
    let size_rows = collect_size_rows::<B>(config, &artifacts);

    collect_correctness_rows::<B>(config, &artifacts, &mut correctness_rows);
    collect_runtime_rows::<B>(config, &artifacts, &mut runtime_rows);

    write_runtime_csv(&config.out_dir, &runtime_rows)?;
    write_size_csv(&config.out_dir, &size_rows)?;
    write_correctness_csv(&config.out_dir, &correctness_rows)?;

    let success = correctness_rows.iter().all(|row| row.success);
    if !success && !config.allow_failures {
        return Err(AvsaError::BenchCorrectnessFailed(
            "one or more correctness checks failed".into(),
        ));
    }

    Ok(BenchRunSummary {
        runtime_rows: runtime_rows.len(),
        size_rows: size_rows.len(),
        correctness_rows: correctness_rows.len(),
        success,
        out_dir: config.out_dir.clone(),
    })
}

fn generate_signed_updates(
    config: &BenchConfig,
    selected: &[ClientId],
) -> Result<BTreeMap<ClientId, Vec<i64>>> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut out = BTreeMap::new();
    for client in selected {
        let mut values = Vec::with_capacity(config.dim);
        for _ in 0..config.dim {
            values.push(rng.gen_range(-config.b_inf..=config.b_inf));
        }
        out.insert(*client, values);
    }
    Ok(out)
}

fn decision_certificate(
    round: &HonestRound,
    transcript: &Transcript,
    admitted: &[ClientId],
    dropped: &[ClientId],
    rejected: &[ClientId],
) -> (DecisionCertificate, Vec<DecisionEntry>) {
    let admitted_set: BTreeSet<_> = admitted.iter().copied().collect();
    let dropped_set: BTreeSet<_> = dropped.iter().copied().collect();
    let rejected_set: BTreeSet<_> = rejected.iter().copied().collect();
    let entries: Vec<_> = round
        .records
        .values()
        .map(|record| DecisionEntry {
            round_id: record.round_id.clone(),
            client_id: record.client_id,
            record_digest: record_digest(record),
            status: if admitted_set.contains(&record.client_id) {
                DecisionStatus::Accepted
            } else if dropped_set.contains(&record.client_id) {
                DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("dropped".into()))
            } else if rejected_set.contains(&record.client_id) {
                DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("rejected".into()))
            } else {
                DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("not-admitted".into()))
            },
            membership_proof: transcript.proof_for_client(record.client_id),
        })
        .collect();
    (
        DecisionCertificate {
            round_id: round.round_id.clone(),
            transcript_root: transcript.root,
            entries: entries.clone(),
        },
        entries,
    )
}

fn honest_mask_certificate(round: &HonestRound, admitted: &[ClientId]) -> Result<MaskCertificate> {
    let self_openings = admitted
        .iter()
        .map(|client| {
            Ok(SelfMaskOpening {
                client_id: *client,
                mask: round.graph.self_mask(*client)?.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let pair_openings = required_boundary_pairs(&round.selected, admitted)?
        .into_iter()
        .map(|(admitted_client, other_client)| {
            Ok(PairMaskOpening {
                admitted_client,
                other_client,
                mask: round
                    .graph
                    .pair_mask(admitted_client, other_client)?
                    .clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MaskCertificate {
        round_id: round.round_id.clone(),
        selected_clients: round.selected.clone(),
        admitted_set: AdmittedSet::new(admitted.to_vec())?,
        aggregate_mask: round.graph.aggregate_mask(admitted)?,
        self_openings,
        pair_openings,
    })
}

fn honest_aggregate_certificate(
    round: &HonestRound,
    admitted: &[ClientId],
    decision_cert: &DecisionCertificate,
    mask_certificate: &MaskCertificate,
) -> Result<AggregateCertificate> {
    Ok(AggregateCertificate {
        round_id: round.round_id.clone(),
        transcript_root: decision_cert.transcript_root,
        admitted_set: AdmittedSet::new(admitted.to_vec())?,
        aggregate_output: aggregate_output(&round.records, &round.graph, admitted)?,
        mask_certificate: mask_certificate.clone(),
    })
}

fn signed_range_proofs<B: RangeProofBackend>(
    round: &HonestRound,
    config: &BenchConfig,
    generators: &Generators,
) -> Result<BTreeMap<ClientId, SignedRangeProof<B::Proof>>> {
    let mut out = BTreeMap::new();
    for (client_id, record) in &round.records {
        let values = round
            .signed_updates
            .get(client_id)
            .ok_or(AvsaError::MissingClient(*client_id))?;
        let blindings = round
            .commitment_blindings
            .get(client_id)
            .ok_or(AvsaError::MissingClient(*client_id))?;
        let proof = signed_range_prove::<B>(
            round.round_id.as_str(),
            *client_id,
            &record.commitments,
            values,
            blindings,
            config.b_inf as u64,
            config.bit_size,
            generators,
        )?;
        out.insert(*client_id, proof);
    }
    Ok(out)
}

fn l2_proofs<B: RangeProofBackend>(
    round: &HonestRound,
    config: &BenchConfig,
    generators: &Generators,
) -> Result<BTreeMap<ClientId, L2Proof<B::Proof>>> {
    let mut out = BTreeMap::new();
    let mut rng = StdRng::seed_from_u64(config.seed ^ 0x1234_5678);
    for (client_id, record) in &round.records {
        let values = round
            .signed_updates
            .get(client_id)
            .ok_or(AvsaError::MissingClient(*client_id))?;
        let blindings = round
            .commitment_blindings
            .get(client_id)
            .ok_or(AvsaError::MissingClient(*client_id))?;
        let statement = L2Statement {
            rid: round.round_id.as_str(),
            client_id: *client_id,
            commitments: &record.commitments,
            b2_sq: config.b2_sq as u64,
            bit_size: config.bit_size,
        };
        let witness = L2Witness { values, blindings };
        let proof = l2_prove::<B, _>(&statement, &witness, generators, &mut rng)?;
        out.insert(*client_id, proof);
    }
    Ok(out)
}

fn collect_runtime_rows<B>(
    config: &BenchConfig,
    artifacts: &BenchRound<B::Proof>,
    rows: &mut Vec<RuntimeRow>,
) where
    B: RangeProofBackend,
    B::Proof: BenchProofBytes,
{
    let first_client = artifacts.round.selected[0];
    let first_record = artifacts
        .round
        .records
        .get(&first_client)
        .expect("generated first record");
    let first_values = artifacts
        .round
        .signed_updates
        .get(&first_client)
        .expect("generated signed update");
    let first_update = artifacts
        .round
        .updates
        .get(&first_client)
        .expect("generated scalar update");
    let first_blindings = artifacts
        .round
        .commitment_blindings
        .get(&first_client)
        .expect("generated blindings");
    let first_range_proof = artifacts
        .signed_range_proofs
        .get(&first_client)
        .expect("generated range proof");
    let first_l2_proof = artifacts
        .l2_proofs
        .get(&first_client)
        .expect("generated L2 proof");
    let first_receipt = artifacts
        .receipts
        .get(&first_client)
        .expect("generated receipt");
    let first_entry = artifacts
        .decision_cert
        .entry_for(first_client)
        .expect("generated decision entry");
    let first_membership = first_entry
        .membership_proof
        .as_ref()
        .expect("generated membership proof");
    let context = public_context(artifacts);

    push_measurement(config, rows, "setup", "round_generation", || {
        generate_bench_round::<B>(config).map(|_| ())
    });
    push_measurement(config, rows, "commit", "commit_vector", || {
        artifacts
            .generators
            .commit_vector(first_update, first_blindings)
            .map(|_| ())
    });
    push_measurement(config, rows, "mask", "mask_tag_generation", || {
        artifacts
            .round
            .graph
            .client_tags(&artifacts.generators, first_client)
            .map(|_| ())
    });
    push_measurement(config, rows, "submit", "submit_prove", || {
        let submitted_mask = artifacts.round.graph.submitted_mask(first_client)?;
        let pair_tags = ordered_peer_tags_from_map(
            first_client,
            &artifacts.round.selected,
            &first_record.aux.pair_tags,
        )?;
        let public = SubmitPublicInputs {
            rid: &artifacts.round.round_id,
            client_id: first_client,
            selected_clients: &artifacts.round.selected,
            masked_update: &first_record.masked_update,
            commitments: &first_record.commitments,
            submitted_tag: &first_record.submitted_tag,
            self_tag: &first_record.aux.self_tag,
            pair_tags: &pair_tags,
        };
        let witness = SubmitWitness {
            update: first_update,
            commitment_blinding: first_blindings,
            submitted_mask: &submitted_mask,
        };
        let mut rng = StdRng::seed_from_u64(config.seed ^ 0x9999);
        submit_prove(&public, &witness, &artifacts.generators, &mut rng).map(|_| ())
    });
    push_measurement(config, rows, "submit", "submit_verify", || {
        submit_verify_record(
            first_record,
            &artifacts.round.selected,
            &artifacts.generators,
        )
    });
    push_measurement(config, rows, "range", "signed_range_prove", || {
        signed_range_prove::<B>(
            &artifacts.round.round_id,
            first_client,
            &first_record.commitments,
            first_values,
            first_blindings,
            config.b_inf as u64,
            config.bit_size,
            &artifacts.generators,
        )
        .map(|_| ())
    });
    push_measurement(config, rows, "range", "signed_range_verify", || {
        signed_range_verify::<B>(
            &artifacts.round.round_id,
            first_client,
            &first_record.commitments,
            first_range_proof,
            &artifacts.generators,
        )
    });
    push_measurement(config, rows, "l2", "l2_prove", || {
        let statement = L2Statement {
            rid: &artifacts.round.round_id,
            client_id: first_client,
            commitments: &first_record.commitments,
            b2_sq: config.b2_sq as u64,
            bit_size: config.bit_size,
        };
        let witness = L2Witness {
            values: first_values,
            blindings: first_blindings,
        };
        let mut rng = StdRng::seed_from_u64(config.seed ^ 0xABCD);
        l2_prove::<B, _>(&statement, &witness, &artifacts.generators, &mut rng).map(|_| ())
    });
    push_measurement(config, rows, "l2", "l2_verify", || {
        let statement = L2Statement {
            rid: &artifacts.round.round_id,
            client_id: first_client,
            commitments: &first_record.commitments,
            b2_sq: config.b2_sq as u64,
            bit_size: config.bit_size,
        };
        l2_verify::<B>(&statement, first_l2_proof, &artifacts.generators)
    });
    push_measurement(config, rows, "transcript", "transcript_root_build", || {
        Transcript::from_records(&artifacts.records).map(|_| ())
    });
    push_measurement(config, rows, "transcript", "membership_verify", || {
        verify_record_membership(
            &artifacts.transcript.root,
            &artifacts.round.round_id,
            first_client,
            &record_digest(first_record),
            first_membership,
        )
    });
    push_measurement(config, rows, "receipt", "receipt_verify", || {
        verify_receipt(first_receipt, first_record).map(|_| ())
    });
    push_measurement(config, rows, "decision", "verify_accepted_decision", || {
        verify_accepted_decision(
            &artifacts.decision_cert,
            first_entry,
            first_record,
            &AcceptAllPredicateVerifier,
            &context,
        )
    });
    push_measurement(config, rows, "appeal", "verify_appeal", || {
        verify_appeal(
            first_receipt,
            first_record,
            &artifacts.decision_cert,
            Some(first_entry),
            &AcceptAllPredicateVerifier,
            &context,
        )
        .map(|_| ())
    });
    push_measurement(config, rows, "mask", "verify_mask_certificate", || {
        verify_mask_certificate(
            &artifacts.mask_certificate,
            &artifacts.round.records,
            &context,
        )
    });
    push_measurement(
        config,
        rows,
        "aggregate",
        "verify_aggregate_certificate",
        || {
            verify_aggregate_certificate(
                &artifacts.aggregate_certificate,
                &artifacts.records,
                &artifacts.decision_cert,
                &artifacts.decision_entries,
                &AcceptAllPredicateVerifier,
                &context,
            )
        },
    );
    push_measurement(
        config,
        rows,
        "pipeline",
        "honest_full_audit_pipeline",
        || honest_full_audit_pipeline::<B>(config, artifacts),
    );
}

fn collect_correctness_rows<B>(
    config: &BenchConfig,
    artifacts: &BenchRound<B::Proof>,
    rows: &mut Vec<CorrectnessRow>,
) where
    B: RangeProofBackend,
    B::Proof: BenchProofBytes,
{
    let context = public_context(artifacts);
    push_check(config, rows, "submit_verify_all", || {
        for record in artifacts.round.records.values() {
            submit_verify_record(record, &artifacts.round.selected, &artifacts.generators)?;
        }
        Ok("all submit proofs verified".into())
    });
    push_check(config, rows, "signed_range_verify_all", || {
        for (client, proof) in &artifacts.signed_range_proofs {
            let record = artifacts
                .round
                .records
                .get(client)
                .ok_or(AvsaError::MissingClient(*client))?;
            signed_range_verify::<B>(
                &artifacts.round.round_id,
                *client,
                &record.commitments,
                proof,
                &artifacts.generators,
            )?;
        }
        Ok("all signed range proofs verified".into())
    });
    push_check(config, rows, "l2_verify_all", || {
        for (client, proof) in &artifacts.l2_proofs {
            let record = artifacts
                .round
                .records
                .get(client)
                .ok_or(AvsaError::MissingClient(*client))?;
            let statement = L2Statement {
                rid: &artifacts.round.round_id,
                client_id: *client,
                commitments: &record.commitments,
                b2_sq: config.b2_sq as u64,
                bit_size: config.bit_size,
            };
            l2_verify::<B>(&statement, proof, &artifacts.generators)?;
        }
        Ok("all L2 proofs verified".into())
    });
    push_check(config, rows, "accepted_decisions_verify", || {
        for client in &artifacts.admitted {
            let record = artifacts
                .round
                .records
                .get(client)
                .ok_or(AvsaError::MissingClient(*client))?;
            let entry = artifacts
                .decision_cert
                .entry_for(*client)
                .ok_or(AvsaError::MissingClient(*client))?;
            verify_accepted_decision(
                &artifacts.decision_cert,
                entry,
                record,
                &AcceptAllPredicateVerifier,
                &context,
            )?;
        }
        Ok("accepted decisions verified".into())
    });
    push_check(config, rows, "mask_certificate_verify", || {
        verify_mask_certificate(
            &artifacts.mask_certificate,
            &artifacts.round.records,
            &context,
        )?;
        Ok("mask certificate verified".into())
    });
    push_check(config, rows, "aggregate_certificate_verify", || {
        verify_aggregate_certificate(
            &artifacts.aggregate_certificate,
            &artifacts.records,
            &artifacts.decision_cert,
            &artifacts.decision_entries,
            &AcceptAllPredicateVerifier,
            &context,
        )?;
        Ok("aggregate certificate verified".into())
    });
    push_check(config, rows, "honest_full_audit_pipeline", || {
        honest_full_audit_pipeline::<B>(config, artifacts)?;
        Ok("full pipeline verified".into())
    });
}

fn honest_full_audit_pipeline<B: RangeProofBackend>(
    config: &BenchConfig,
    artifacts: &BenchRound<B::Proof>,
) -> Result<()> {
    for record in artifacts.round.records.values() {
        submit_verify_record(record, &artifacts.round.selected, &artifacts.generators)?;
    }
    for client in &artifacts.admitted {
        let record = artifacts
            .round
            .records
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        let range_proof = artifacts
            .signed_range_proofs
            .get(client)
            .ok_or(AvsaError::MissingDataProof(*client))?;
        signed_range_verify::<B>(
            &artifacts.round.round_id,
            *client,
            &record.commitments,
            range_proof,
            &artifacts.generators,
        )?;
        let l2_proof = artifacts
            .l2_proofs
            .get(client)
            .ok_or(AvsaError::MissingDataProof(*client))?;
        let statement = L2Statement {
            rid: &artifacts.round.round_id,
            client_id: *client,
            commitments: &record.commitments,
            b2_sq: config.b2_sq as u64,
            bit_size: config.bit_size,
        };
        l2_verify::<B>(&statement, l2_proof, &artifacts.generators)?;
    }
    let context = public_context(artifacts);
    verify_aggregate_certificate(
        &artifacts.aggregate_certificate,
        &artifacts.records,
        &artifacts.decision_cert,
        &artifacts.decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
}

fn collect_size_rows<B>(config: &BenchConfig, artifacts: &BenchRound<B::Proof>) -> Vec<SizeRow>
where
    B: RangeProofBackend,
    B::Proof: BenchProofBytes,
{
    let mut rows = Vec::new();
    push_size_row(
        config,
        &mut rows,
        "ClientRecord",
        artifacts
            .records
            .iter()
            .map(|record| record.canonical_bytes()),
    );
    push_size_row(
        config,
        &mut rows,
        "SubmitProof",
        artifacts
            .records
            .iter()
            .map(|record| serialize_submit_proof(&record.submission_proof)),
    );
    push_size_row(
        config,
        &mut rows,
        "SignedRangeProof",
        artifacts
            .signed_range_proofs
            .values()
            .map(serialize_signed_range_proof::<B::Proof>),
    );
    push_size_row(
        config,
        &mut rows,
        "L2Proof",
        artifacts
            .l2_proofs
            .values()
            .map(serialize_l2_proof::<B::Proof>),
    );
    push_size_row(
        config,
        &mut rows,
        "RecordDigest",
        artifacts
            .records
            .iter()
            .map(|record| record_digest(record).0.to_vec()),
    );
    push_size_row(
        config,
        &mut rows,
        "TranscriptRoot",
        std::iter::once(artifacts.transcript.root.0.to_vec()),
    );
    push_size_row(
        config,
        &mut rows,
        "Transcript",
        std::iter::once(serialize_transcript(&artifacts.transcript)),
    );
    push_size_row(
        config,
        &mut rows,
        "MembershipProof",
        artifacts
            .decision_entries
            .iter()
            .filter_map(|entry| entry.membership_proof.as_ref())
            .map(serialize_membership_proof),
    );
    push_size_row(
        config,
        &mut rows,
        "Receipt",
        artifacts.receipts.values().map(serialize_receipt),
    );
    push_size_row(
        config,
        &mut rows,
        "DecisionCertificate",
        std::iter::once(serialize_decision_certificate(&artifacts.decision_cert)),
    );
    if let Some((client, receipt)) = artifacts.receipts.iter().next() {
        if let (Some(record), Some(entry)) = (
            artifacts.round.records.get(client),
            artifacts.decision_cert.entry_for(*client),
        ) {
            push_size_row(
                config,
                &mut rows,
                "AppealInput",
                std::iter::once(serialize_appeal_input(receipt, record, entry)),
            );
        }
    }
    push_size_row(
        config,
        &mut rows,
        "MaskCertificate",
        std::iter::once(serialize_mask_certificate(&artifacts.mask_certificate)),
    );
    push_size_row(
        config,
        &mut rows,
        "AggregateCertificate",
        std::iter::once(serialize_aggregate_certificate(
            &artifacts.aggregate_certificate,
        )),
    );
    push_size_row(
        config,
        &mut rows,
        "AggregateOutput",
        std::iter::once(serialize_scalar_slice(
            &artifacts.aggregate_certificate.aggregate_output,
        )),
    );
    rows
}

fn push_measurement<F>(
    config: &BenchConfig,
    rows: &mut Vec<RuntimeRow>,
    component: &str,
    operation: &str,
    mut op: F,
) where
    F: FnMut() -> Result<()>,
{
    for _ in 0..config.warmup {
        if op().is_err() {
            rows.push(RuntimeRow::failed(config, component, operation));
            return;
        }
    }
    let mut durations = Vec::with_capacity(config.iters);
    for _ in 0..config.iters {
        let start = Instant::now();
        if op().is_err() {
            rows.push(RuntimeRow::failed(config, component, operation));
            return;
        }
        durations.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    rows.push(RuntimeRow::from_durations(
        config, component, operation, durations,
    ));
}

fn push_check<F>(config: &BenchConfig, rows: &mut Vec<CorrectnessRow>, check_name: &str, check: F)
where
    F: FnOnce() -> Result<String>,
{
    match check() {
        Ok(observed) => rows.push(CorrectnessRow::success(config, check_name, observed)),
        Err(err) => rows.push(CorrectnessRow::failure(config, check_name, err.to_string())),
    }
}

fn push_size_row<I>(config: &BenchConfig, rows: &mut Vec<SizeRow>, object_type: &str, values: I)
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let sizes: Vec<usize> = values.into_iter().map(|value| value.len()).collect();
    if sizes.is_empty() {
        return;
    }
    rows.push(SizeRow::from_sizes(config, object_type, &sizes));
}

#[derive(Clone, Debug)]
struct RuntimeRow {
    run_id: String,
    backend: String,
    case_name: String,
    n_selected: usize,
    n_admitted: usize,
    n_dropped: usize,
    n_rejected: usize,
    dim: usize,
    b_inf: i64,
    b2_sq: u128,
    bit_size: usize,
    component: String,
    operation: String,
    iterations: usize,
    warmup: usize,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
    success: bool,
}

impl RuntimeRow {
    fn from_durations(
        config: &BenchConfig,
        component: &str,
        operation: &str,
        durations: Vec<f64>,
    ) -> Self {
        let mut sorted = durations.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mean = durations.iter().sum::<f64>() / durations.len() as f64;
        let min = *sorted.first().unwrap_or(&0.0);
        let max = *sorted.last().unwrap_or(&0.0);
        Self {
            run_id: config.run_id(),
            backend: config.backend.as_str().into(),
            case_name: config.case_name().into(),
            n_selected: config.n_selected,
            n_admitted: config.n_admitted,
            n_dropped: config.n_dropped,
            n_rejected: config.n_rejected,
            dim: config.dim,
            b_inf: config.b_inf,
            b2_sq: config.b2_sq,
            bit_size: config.bit_size,
            component: component.into(),
            operation: operation.into(),
            iterations: config.iters,
            warmup: config.warmup,
            mean_ms: mean,
            p50_ms: percentile(&sorted, 0.50),
            p95_ms: percentile(&sorted, 0.95),
            min_ms: min,
            max_ms: max,
            success: true,
        }
    }

    fn failed(config: &BenchConfig, component: &str, operation: &str) -> Self {
        Self {
            run_id: config.run_id(),
            backend: config.backend.as_str().into(),
            case_name: config.case_name().into(),
            n_selected: config.n_selected,
            n_admitted: config.n_admitted,
            n_dropped: config.n_dropped,
            n_rejected: config.n_rejected,
            dim: config.dim,
            b_inf: config.b_inf,
            b2_sq: config.b2_sq,
            bit_size: config.bit_size,
            component: component.into(),
            operation: operation.into(),
            iterations: config.iters,
            warmup: config.warmup,
            mean_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            success: false,
        }
    }

    fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{}",
            csv(&self.run_id),
            csv(&self.backend),
            csv(&self.case_name),
            self.n_selected,
            self.n_admitted,
            self.n_dropped,
            self.n_rejected,
            self.dim,
            self.b_inf,
            self.b2_sq,
            self.bit_size,
            csv(&self.component),
            csv(&self.operation),
            self.iterations,
            self.warmup,
            self.mean_ms,
            self.p50_ms,
            self.p95_ms,
            self.min_ms,
            self.max_ms,
            self.success
        )
    }
}

#[derive(Clone, Debug)]
struct SizeRow {
    run_id: String,
    backend: String,
    case_name: String,
    n_selected: usize,
    n_admitted: usize,
    n_dropped: usize,
    n_rejected: usize,
    dim: usize,
    object_type: String,
    count: usize,
    total_bytes: usize,
    mean_bytes: f64,
    min_bytes: usize,
    max_bytes: usize,
}

impl SizeRow {
    fn from_sizes(config: &BenchConfig, object_type: &str, sizes: &[usize]) -> Self {
        let total_bytes = sizes.iter().sum::<usize>();
        let min_bytes = sizes.iter().copied().min().unwrap_or(0);
        let max_bytes = sizes.iter().copied().max().unwrap_or(0);
        Self {
            run_id: config.run_id(),
            backend: config.backend.as_str().into(),
            case_name: config.case_name().into(),
            n_selected: config.n_selected,
            n_admitted: config.n_admitted,
            n_dropped: config.n_dropped,
            n_rejected: config.n_rejected,
            dim: config.dim,
            object_type: object_type.into(),
            count: sizes.len(),
            total_bytes,
            mean_bytes: total_bytes as f64 / sizes.len() as f64,
            min_bytes,
            max_bytes,
        }
    }

    fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{}",
            csv(&self.run_id),
            csv(&self.backend),
            csv(&self.case_name),
            self.n_selected,
            self.n_admitted,
            self.n_dropped,
            self.n_rejected,
            self.dim,
            csv(&self.object_type),
            self.count,
            self.total_bytes,
            self.mean_bytes,
            self.min_bytes,
            self.max_bytes
        )
    }
}

#[derive(Clone, Debug)]
struct CorrectnessRow {
    run_id: String,
    backend: String,
    case_name: String,
    check_name: String,
    expected: String,
    observed: String,
    success: bool,
    error: String,
}

impl CorrectnessRow {
    fn success(config: &BenchConfig, check_name: &str, observed: String) -> Self {
        Self {
            run_id: config.run_id(),
            backend: config.backend.as_str().into(),
            case_name: config.case_name().into(),
            check_name: check_name.into(),
            expected: "success".into(),
            observed,
            success: true,
            error: String::new(),
        }
    }

    fn failure(config: &BenchConfig, check_name: &str, error: String) -> Self {
        Self {
            run_id: config.run_id(),
            backend: config.backend.as_str().into(),
            case_name: config.case_name().into(),
            check_name: check_name.into(),
            expected: "success".into(),
            observed: "failure".into(),
            success: false,
            error,
        }
    }

    fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{}",
            csv(&self.run_id),
            csv(&self.backend),
            csv(&self.case_name),
            csv(&self.check_name),
            csv(&self.expected),
            csv(&self.observed),
            self.success,
            csv(&self.error)
        )
    }
}

fn write_runtime_csv(out_dir: &Path, rows: &[RuntimeRow]) -> Result<()> {
    write_csv(
        &out_dir.join("avsa_runtime.csv"),
        RUNTIME_HEADER,
        rows.iter().map(RuntimeRow::csv),
    )
}

fn write_size_csv(out_dir: &Path, rows: &[SizeRow]) -> Result<()> {
    write_csv(
        &out_dir.join("avsa_sizes.csv"),
        SIZE_HEADER,
        rows.iter().map(SizeRow::csv),
    )
}

fn write_correctness_csv(out_dir: &Path, rows: &[CorrectnessRow]) -> Result<()> {
    write_csv(
        &out_dir.join("avsa_correctness.csv"),
        CORRECTNESS_HEADER,
        rows.iter().map(CorrectnessRow::csv),
    )
}

fn write_csv<I>(path: &Path, header: &str, rows: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let file = File::create(path).map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{header}").map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;
    for row in rows {
        writeln!(writer, "{row}").map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;
    }
    writer
        .flush()
        .map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len().saturating_sub(1)) as f64 * q).ceil() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn public_context<'a, P>(artifacts: &'a BenchRound<P>) -> PublicAuditContext<'a> {
    PublicAuditContext {
        round_id: &artifacts.round.round_id,
        selected_clients: &artifacts.round.selected,
        generators: &artifacts.generators,
    }
}

fn csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn serialize_submit_proof(proof: &crate::proof::submit::SubmitProof) -> Vec<u8> {
    let mut out = Vec::new();
    proof.write_canonical_bytes(&mut out);
    out
}

fn serialize_signed_range_proof<P: BenchProofBytes>(proof: &SignedRangeProof<P>) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, proof.b_inf);
    push_u64(&mut out, proof.bit_size as u64);
    push_point_slice(&mut out, &proof.shifted_commitments);
    proof.backend_proof.write_bench_bytes(&mut out);
    out
}

fn serialize_l2_proof<P: BenchProofBytes>(proof: &L2Proof<P>) -> Vec<u8> {
    let mut out = Vec::new();
    push_point(&mut out, &proof.norm_commitment);
    push_point(&mut out, &proof.slack_commitment);
    push_point_slice(&mut out, &proof.a);
    push_point(&mut out, &proof.c_times);
    push_point(&mut out, &proof.c_plus);
    push_scalar_slice(&mut out, &proof.z);
    push_scalar_slice(&mut out, &proof.theta_commitments);
    push_scalar(&mut out, &proof.theta_norm);
    proof.range_proof.write_bench_bytes(&mut out);
    out
}

fn serialize_transcript(transcript: &Transcript) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, &transcript.root.0);
    push_u64(&mut out, transcript.leaves.len() as u64);
    for leaf in &transcript.leaves {
        push_len_prefixed(&mut out, leaf.round_id.as_bytes());
        push_u64(&mut out, leaf.client_id);
        push_bytes(&mut out, &leaf.hash.0);
    }
    out
}

fn serialize_membership_proof(proof: &MembershipProof) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, proof.client_id);
    push_u64(&mut out, proof.index as u64);
    push_bytes(&mut out, &proof.leaf_hash.0);
    push_u64(&mut out, proof.all_leaves.len() as u64);
    for leaf in &proof.all_leaves {
        push_len_prefixed(&mut out, leaf.round_id.as_bytes());
        push_u64(&mut out, leaf.client_id);
        push_bytes(&mut out, &leaf.hash.0);
    }
    out
}

fn serialize_receipt(receipt: &ServerReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, receipt.round_id.as_bytes());
    push_u64(&mut out, receipt.client_id);
    push_bytes(&mut out, &receipt.record_digest.0);
    push_u64(&mut out, receipt.receive_seq);
    push_u64(&mut out, receipt.deadline_seq);
    match &receipt.server_signature {
        Some(signature) => {
            out.push(1);
            push_len_prefixed(&mut out, signature);
        }
        None => out.push(0),
    }
    out
}

fn serialize_decision_certificate(cert: &DecisionCertificate) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, cert.round_id.as_bytes());
    push_bytes(&mut out, &cert.transcript_root.0);
    push_u64(&mut out, cert.entries.len() as u64);
    for entry in &cert.entries {
        serialize_decision_entry_into(&mut out, entry);
    }
    out
}

fn serialize_decision_entry_into(out: &mut Vec<u8>, entry: &DecisionEntry) {
    push_len_prefixed(out, entry.round_id.as_bytes());
    push_u64(out, entry.client_id);
    push_bytes(out, &entry.record_digest.0);
    match &entry.status {
        DecisionStatus::Accepted => out.push(1),
        DecisionStatus::Rejected(reason) => {
            out.push(2);
            push_len_prefixed(out, reject_reason_label(reason).as_bytes());
        }
    }
    match &entry.membership_proof {
        Some(proof) => {
            out.push(1);
            out.extend_from_slice(&serialize_membership_proof(proof));
        }
        None => out.push(0),
    }
}

fn reject_reason_label(reason: &RejectReason) -> String {
    match reason {
        RejectReason::InvalidSubmitProof => "invalid-submit".into(),
        RejectReason::InvalidDataPredicate => "invalid-data".into(),
        RejectReason::InvalidMaskTag => "invalid-mask-tag".into(),
        RejectReason::LateSubmission => "late".into(),
        RejectReason::DuplicateSubmission => "duplicate".into(),
        RejectReason::MissingRecord => "missing".into(),
        RejectReason::OtherPublicPolicy(label) => format!("policy:{label}"),
    }
}

fn serialize_appeal_input(
    receipt: &ServerReceipt,
    record: &ClientRecord,
    entry: &DecisionEntry,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&serialize_receipt(receipt));
    push_len_prefixed(&mut out, &record.canonical_bytes());
    serialize_decision_entry_into(&mut out, entry);
    out
}

fn serialize_mask_certificate(cert: &MaskCertificate) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, cert.round_id.as_bytes());
    push_u64(&mut out, cert.selected_clients.len() as u64);
    for client in &cert.selected_clients {
        push_u64(&mut out, *client);
    }
    push_u64(&mut out, cert.admitted_set.clients.len() as u64);
    for client in &cert.admitted_set.clients {
        push_u64(&mut out, *client);
    }
    push_scalar_slice(&mut out, &cert.aggregate_mask);
    push_u64(&mut out, cert.self_openings.len() as u64);
    for opening in &cert.self_openings {
        push_u64(&mut out, opening.client_id);
        push_scalar_slice(&mut out, &opening.mask);
    }
    push_u64(&mut out, cert.pair_openings.len() as u64);
    for opening in &cert.pair_openings {
        push_u64(&mut out, opening.admitted_client);
        push_u64(&mut out, opening.other_client);
        push_scalar_slice(&mut out, &opening.mask);
    }
    out
}

fn serialize_aggregate_certificate(cert: &AggregateCertificate) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, cert.round_id.as_bytes());
    push_bytes(&mut out, &cert.transcript_root.0);
    push_u64(&mut out, cert.admitted_set.clients.len() as u64);
    for client in &cert.admitted_set.clients {
        push_u64(&mut out, *client);
    }
    push_scalar_slice(&mut out, &cert.aggregate_output);
    out.extend_from_slice(&serialize_mask_certificate(&cert.mask_certificate));
    out
}

fn serialize_scalar_slice(values: &[Scalar]) -> Vec<u8> {
    let mut out = Vec::new();
    push_scalar_slice(&mut out, values);
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_scalar(out: &mut Vec<u8>, value: &Scalar) {
    out.extend_from_slice(&value.to_bytes());
}

fn push_scalar_slice(out: &mut Vec<u8>, values: &[Scalar]) {
    push_u64(out, values.len() as u64);
    for value in values {
        push_scalar(out, value);
    }
}

fn push_point(out: &mut Vec<u8>, value: &RistrettoPoint) {
    out.extend_from_slice(value.compress().as_bytes());
}

fn push_point_slice(out: &mut Vec<u8>, values: &[RistrettoPoint]) {
    push_u64(out, values.len() as u64);
    for value in values {
        push_point(out, value);
    }
}
