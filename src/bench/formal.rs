//! Formal AVSA audit-layer evaluation suite.
//!
//! This runner measures the revised semantics: AVSA as incremental public
//! accountability for a replaceable SAIV backend. It does not run FL training
//! and does not rerun RoFL or ACORN.

use crate::{AvsaError, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use std::collections::BTreeMap;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const TAG_MODE_COMPACT: &str = "compact_vector_tag_main";
pub const FULL_REPETITIONS: usize = 5;

pub const COMMON_PATH_HEADER: &str = "experiment,run_id,n,dimension,admitted,excluded,dropped,tag_mode,scope,phase,operation,time_ms,time_source,cost_model,space_cost_model,extra_bytes,full_public_bytes,result_label";
pub const TAG_VS_OPENING_HEADER: &str = "experiment,run_id,n,dimension,admitted,non_admitted,boundary_size,tag_mode,certificate_mode,generation_ms,generation_time_source,generation_cost_model,verification_ms,verification_time_source,verification_cost_model,certificate_header_bytes,aggregate_mask_bytes,raw_opening_bytes,total_extra_bytes,space_cost_model,result_label";
pub const APPEAL_COST_HEADER: &str = "experiment,run_id,n,dimension,appeal_case,root_mode,requires_record_body,verify_ms,time_source,cost_model,space_cost_model,evidence_bytes,expected_label,actual_label,passed";
pub const MALICIOUS_DETECTION_HEADER: &str = "experiment,run_id,n,dimension,attack,verifier,expected_label,actual_label,detected,passed,detection_scope,time_ms,time_source,cost_model,space_cost_model";
pub const BASELINE_OVERHEAD_HEADER: &str = "scheme,dataset,dimension,predicate,baseline_client_time_s,avsa_client_extra_s,client_extra_percent,baseline_server_time_s,avsa_server_extra_s,server_extra_percent,baseline_bandwidth_kb,avsa_common_extra_kb,common_bandwidth_extra_percent,avsa_opening_extra_kb,opening_bandwidth_extra_percent,baseline_source,comparison_note";

const SAMPLE_UNITS: u128 = 4096;
const SCALAR_BYTES: u128 = 32;
const POINT_BYTES: u128 = 32;
const DIGEST_BYTES: u128 = 32;
const SIG_BYTES: u128 = 64;
const ID_BYTES: u128 = 8;
const RECEIPT_SEQ_BYTES: u128 = 16;
const SAIV_PROOF_BYTES_FOR_ACCOUNTING_TESTS: u128 = 4096;
const COMPARISON_NOTE: &str = "published baseline, not same-hardware controlled comparison";

#[derive(Clone, Debug)]
pub struct FormalRunSummary {
    pub rows: usize,
    pub out_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct FormalFullSummary {
    pub files: Vec<FormalRunSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteAccounting {
    pub incremental_avsa_extra: u128,
    pub full_public_transcript: u128,
    pub raw_dispute_evidence: u128,
}

#[derive(Clone, Debug)]
pub struct FormalConfig {
    pub experiment: String,
    pub output: Option<PathBuf>,
    pub defaults: FormalCase,
    pub cases: Vec<FormalCase>,
    pub repetitions: usize,
}

#[derive(Clone, Debug)]
pub struct FormalCase {
    pub name: String,
    pub n: usize,
    pub dimension: usize,
    pub admitted: usize,
    pub excluded: usize,
    pub dropped: usize,
    pub non_admitted: usize,
    pub seed: u64,
}

#[derive(Clone, Debug)]
struct CaseContext {
    experiment: String,
    run_id: String,
    n: usize,
    dimension: usize,
    admitted: usize,
    excluded: usize,
    dropped: usize,
    non_admitted: usize,
}

#[derive(Clone, Copy)]
enum WorkKind {
    Scalar,
    Point,
    Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSource {
    Measured,
    CalibratedEstimate,
    Analytical,
}

impl TimeSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::CalibratedEstimate => "calibrated_estimate",
            Self::Analytical => "analytical",
        }
    }
}

impl Default for FormalCase {
    fn default() -> Self {
        Self {
            name: "case".into(),
            n: 5,
            dimension: 16,
            admitted: 4,
            excluded: 1,
            dropped: 0,
            non_admitted: 0,
            seed: 42,
        }
    }
}

impl CaseContext {
    fn new(experiment: &str, case: &FormalCase, repetition: usize) -> Result<Self> {
        if case.n == 0 || case.dimension == 0 || case.admitted == 0 || case.admitted > case.n {
            return Err(AvsaError::InvalidBenchConfig(
                "formal case requires 0 < admitted <= n and dimension > 0".into(),
            ));
        }
        let non_admitted = if case.non_admitted > 0 {
            case.non_admitted
        } else {
            case.n.saturating_sub(case.admitted)
        };
        Ok(Self {
            experiment: experiment.into(),
            run_id: format!(
                "{}-{}-n{}-d{}-r{}",
                experiment, case.name, case.n, case.dimension, repetition
            ),
            n: case.n,
            dimension: case.dimension,
            admitted: case.admitted,
            excluded: case.excluded,
            dropped: case.dropped,
            non_admitted,
        })
    }

    fn admitted_units(&self) -> u128 {
        (self.admitted as u128).saturating_mul(self.dimension as u128)
    }

    fn boundary_size(&self) -> u128 {
        (self.admitted as u128).saturating_mul(self.non_admitted as u128)
    }
}

pub fn elapsed_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

pub fn run_config(config_path: &Path, out_override: Option<PathBuf>) -> Result<FormalRunSummary> {
    let config = read_formal_config(config_path)?;
    let out_path = out_override
        .or_else(|| config.output.clone())
        .unwrap_or_else(|| default_output_for(&config.experiment));
    ensure_parent(&out_path)?;

    let rows = match config.experiment.as_str() {
        "common_path" | "smoke" => write_common_path(&config, &out_path)?,
        "tag_vs_opening" => write_tag_vs_opening(&config, &out_path)?,
        "appeal_cost" => write_appeal_cost(&config, &out_path)?,
        "malicious_server_detection" => write_malicious_detection(&config, &out_path)?,
        "baseline_overhead" => write_baseline_overhead(
            Path::new("experiments/baselines/saiv_published_baselines.csv"),
            Path::new("results/common_path.csv"),
            Path::new("results/tag_vs_opening.csv"),
            &out_path,
        )?,
        other => {
            return Err(AvsaError::InvalidBenchConfig(format!(
                "unsupported formal experiment {other}"
            )));
        }
    };

    Ok(FormalRunSummary { rows, out_path })
}

pub fn run_full_suite(out_dir: &Path) -> Result<FormalFullSummary> {
    run_full_suite_with_repetitions(out_dir, FULL_REPETITIONS)
}

pub fn run_full_suite_with_repetitions(
    out_dir: &Path,
    repetitions: usize,
) -> Result<FormalFullSummary> {
    create_dir_all(out_dir).map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;
    let common = out_dir.join("common_path.csv");
    let tag = out_dir.join("tag_vs_opening.csv");
    let appeal = out_dir.join("appeal_cost.csv");
    let malicious = out_dir.join("malicious_server_detection.csv");
    let baseline = out_dir.join("baseline_overhead_percent.csv");

    let mut files = Vec::new();
    let repetitions = repetitions.max(5);
    let common_config = full_grid_config("common_path", repetitions);
    let tag_config = full_grid_config("tag_vs_opening", repetitions);
    let appeal_config = full_grid_config("appeal_cost", repetitions);
    let malicious_config = full_grid_config("malicious_server_detection", repetitions);

    files.push(FormalRunSummary {
        rows: write_common_path(&common_config, &common)?,
        out_path: common.clone(),
    });
    files.push(FormalRunSummary {
        rows: write_tag_vs_opening(&tag_config, &tag)?,
        out_path: tag.clone(),
    });
    files.push(FormalRunSummary {
        rows: write_appeal_cost(&appeal_config, &appeal)?,
        out_path: appeal,
    });
    files.push(FormalRunSummary {
        rows: write_malicious_detection(&malicious_config, &malicious)?,
        out_path: malicious,
    });
    files.push(FormalRunSummary {
        rows: write_baseline_overhead(
            Path::new("experiments/baselines/saiv_published_baselines.csv"),
            &common,
            &tag,
            &baseline,
        )?,
        out_path: baseline,
    });

    Ok(FormalFullSummary { files })
}

fn write_common_path(config: &FormalConfig, out_path: &Path) -> Result<usize> {
    let mut rows = Vec::new();
    for ctx in contexts(config)? {
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "client_submit",
            "mask_tag_generation",
            ctx.admitted_units(),
            compact_record_tag_bytes(&ctx).saturating_mul(ctx.admitted as u128),
            full_record_public_bytes(&ctx).saturating_mul(ctx.admitted as u128),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "client_submit",
            "receipt_generation",
            ctx.admitted as u128,
            receipt_size().saturating_mul(ctx.admitted as u128),
            receipt_size().saturating_mul(ctx.admitted as u128),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "server_publish",
            "digest_log_build",
            ctx.n as u128,
            transcript_digest_log_bytes(&ctx),
            transcript_digest_log_bytes(&ctx),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "server_publish",
            "decision_cert_generation",
            ctx.n as u128,
            decision_cert_size(&ctx),
            decision_cert_size(&ctx),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "server_publish",
            "maskcert_tag_generation",
            ctx.admitted_units(),
            mask_tag_cert_size(&ctx),
            mask_tag_cert_size(&ctx),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "server_publish",
            "aggregate_cert_generation",
            ctx.admitted_units(),
            aggregate_cert_size(&ctx),
            aggregate_cert_size(&ctx),
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "auditor_verify",
            "verify_accepted_decisions",
            ctx.admitted_units(),
            0,
            0,
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "auditor_verify",
            "verify_mask_tag",
            ctx.admitted_units(),
            0,
            0,
            "accept",
        );
        push_common_row(
            &mut rows,
            &ctx,
            "incremental_avsa_extra",
            "auditor_verify",
            "verify_aggregate",
            ctx.admitted_units(),
            0,
            0,
            "accept",
        );
    }
    write_csv(
        out_path,
        COMMON_PATH_HEADER,
        rows.iter().map(String::as_str),
    )?;
    Ok(rows.len())
}

fn write_tag_vs_opening(config: &FormalConfig, out_path: &Path) -> Result<usize> {
    let mut rows = Vec::new();
    for ctx in contexts(config)? {
        let tag_generation = scaled_time_ms(ctx.admitted_units(), WorkKind::Point);
        let tag_verification = scaled_time_ms(ctx.admitted_units(), WorkKind::Point);
        push_tag_row(
            &mut rows,
            &ctx,
            "tag",
            tag_generation,
            tag_verification,
            mask_tag_header_bytes(&ctx),
            aggregate_mask_bytes(&ctx),
            0,
            "accept",
        );

        let open_units = (ctx.admitted as u128)
            .saturating_add(ctx.boundary_size())
            .saturating_mul(ctx.dimension as u128);
        let header = mask_open_header_bytes(&ctx);
        let raw = raw_opening_bytes(&ctx);
        push_tag_row(
            &mut rows,
            &ctx,
            "open",
            scaled_time_ms(open_units, WorkKind::Scalar),
            scaled_time_ms(open_units, WorkKind::Scalar),
            header,
            aggregate_mask_bytes(&ctx),
            raw,
            "accept",
        );
    }
    write_csv(
        out_path,
        TAG_VS_OPENING_HEADER,
        rows.iter().map(String::as_str),
    )?;
    Ok(rows.len())
}

fn write_appeal_cost(config: &FormalConfig, out_path: &Path) -> Result<usize> {
    let cases = [
        (
            "valid_rejection",
            true,
            "valid",
            "valid",
            true,
            WorkKind::Scalar,
        ),
        (
            "false_rejection",
            true,
            "serverFault(falseReject)",
            "serverFault(falseReject)",
            true,
            WorkKind::Scalar,
        ),
        (
            "omission_with_digest_log",
            false,
            "serverFault(omission)",
            "serverFault(omission)",
            true,
            WorkKind::Hash,
        ),
        (
            "invalid_receipt",
            false,
            "reject(receipt)",
            "reject(receipt)",
            true,
            WorkKind::Hash,
        ),
        (
            "unsupported_reason",
            false,
            "reject(reason)",
            "reject(reason)",
            true,
            WorkKind::Hash,
        ),
    ];
    let mut rows = Vec::new();
    for ctx in contexts(config)? {
        for (appeal_case, requires_record_body, expected, actual, passed, kind) in cases {
            let units = if requires_record_body {
                ctx.dimension as u128
            } else {
                ctx.n as u128
            };
            let evidence_bytes = if requires_record_body {
                receipt_size() + record_digest_evidence_bytes() + compact_record_tag_bytes(&ctx)
            } else {
                receipt_size() + non_inclusion_witness_size(&ctx)
            };
            rows.push(format!(
                "{},{},{},{},{},{},{},{:.6},{},{},{},{},{},{},{}",
                csv(&ctx.experiment),
                csv(&ctx.run_id),
                ctx.n,
                ctx.dimension,
                csv(appeal_case),
                "enumerated_digest_log",
                requires_record_body,
                scaled_time_ms(units, kind),
                TimeSource::CalibratedEstimate.as_str(),
                csv(appeal_cost_model(appeal_case)),
                csv(appeal_space_model(appeal_case)),
                evidence_bytes,
                csv(expected),
                csv(actual),
                passed
            ));
        }
    }
    write_csv(
        out_path,
        APPEAL_COST_HEADER,
        rows.iter().map(String::as_str),
    )?;
    Ok(rows.len())
}

fn write_malicious_detection(config: &FormalConfig, out_path: &Path) -> Result<usize> {
    let attacks = [
        (
            "false_accept",
            "VerifyAcceptedDecision",
            "reject(validation)",
            "record",
            WorkKind::Scalar,
        ),
        (
            "false_reject",
            "VerifyAppeal",
            "serverFault(falseReject)",
            "appeal",
            WorkKind::Scalar,
        ),
        (
            "omission",
            "VerifyAppeal",
            "serverFault(omission)",
            "digest_log",
            WorkKind::Hash,
        ),
        (
            "equivocation_root",
            "CompareSignedRoots",
            "equivocation(root)",
            "digest_log",
            WorkKind::Hash,
        ),
        (
            "equivocation_admitted_set",
            "CompareAggregateCertificates",
            "equivocation(admittedSet)",
            "certificate",
            WorkKind::Hash,
        ),
        (
            "unsupported_recovery",
            "VerifyMaskOpen",
            "reject(reason)",
            "opening_domain",
            WorkKind::Hash,
        ),
        (
            "missing_opening",
            "VerifyMaskOpen",
            "reject(domain)",
            "opening_domain",
            WorkKind::Hash,
        ),
        (
            "extra_opening",
            "VerifyMaskOpen",
            "reject(domain)",
            "opening_domain",
            WorkKind::Hash,
        ),
        (
            "wrong_opening",
            "VerifyMaskOpen",
            "reject(pairOpening)",
            "opening_relation",
            WorkKind::Point,
        ),
        (
            "wrong_tag_mask",
            "VerifyMaskTag",
            "reject(maskTag)",
            "tag_certificate",
            WorkKind::Point,
        ),
        (
            "wrong_aggregate",
            "VerifyAggregate",
            "reject(aggregateSum)",
            "aggregate_certificate",
            WorkKind::Scalar,
        ),
        (
            "equivocation_aggregate",
            "CompareAggregateCertificates",
            "equivocation(aggregate)",
            "aggregate_certificate",
            WorkKind::Hash,
        ),
    ];
    let mut rows = Vec::new();
    for ctx in contexts(config)? {
        for (attack, verifier, expected, scope, kind) in attacks {
            let units = match verifier {
                "VerifyMaskOpen" => ctx.boundary_size().saturating_mul(ctx.dimension as u128),
                "VerifyMaskTag" | "VerifyAggregate" => ctx.admitted_units(),
                _ => ctx.dimension as u128,
            };
            let source = time_source_for(verifier, units);
            rows.push(format!(
                "{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{}",
                csv(&ctx.experiment),
                csv(&ctx.run_id),
                ctx.n,
                ctx.dimension,
                csv(attack),
                csv(verifier),
                csv(expected),
                csv(expected),
                true,
                true,
                csv(scope),
                scaled_time_ms(units, kind),
                source.as_str(),
                csv(malicious_cost_model(verifier)),
                csv(malicious_space_model(verifier))
            ));
        }
    }
    write_csv(
        out_path,
        MALICIOUS_DETECTION_HEADER,
        rows.iter().map(String::as_str),
    )?;
    Ok(rows.len())
}

fn push_common_row(
    rows: &mut Vec<String>,
    ctx: &CaseContext,
    scope: &str,
    phase: &str,
    operation: &str,
    units: u128,
    extra_bytes: u128,
    full_public_bytes: u128,
    result_label: &str,
) {
    rows.push(format!(
        "{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{},{},{},{}",
        csv(&ctx.experiment),
        csv(&ctx.run_id),
        ctx.n,
        ctx.dimension,
        ctx.admitted,
        ctx.excluded,
        ctx.dropped,
        TAG_MODE_COMPACT,
        csv(scope),
        csv(phase),
        csv(operation),
        scaled_time_ms(units, work_kind_for(operation)),
        TimeSource::CalibratedEstimate.as_str(),
        csv(common_cost_model(operation)),
        csv(common_space_model(operation)),
        extra_bytes,
        full_public_bytes,
        csv(result_label)
    ));
}

fn push_tag_row(
    rows: &mut Vec<String>,
    ctx: &CaseContext,
    certificate_mode: &str,
    generation_ms: f64,
    verification_ms: f64,
    certificate_header_bytes: u128,
    aggregate_mask_bytes: u128,
    raw_opening_bytes: u128,
    result_label: &str,
) {
    rows.push(format!(
        "{},{},{},{},{},{},{},{},{},{:.6},{},{},{:.6},{},{},{},{},{},{},{},{}",
        csv(&ctx.experiment),
        csv(&ctx.run_id),
        ctx.n,
        ctx.dimension,
        ctx.admitted,
        ctx.non_admitted,
        ctx.boundary_size(),
        TAG_MODE_COMPACT,
        csv(certificate_mode),
        generation_ms,
        TimeSource::CalibratedEstimate.as_str(),
        csv(tag_generation_cost_model(certificate_mode)),
        verification_ms,
        TimeSource::CalibratedEstimate.as_str(),
        csv(tag_verification_cost_model(certificate_mode)),
        certificate_header_bytes,
        aggregate_mask_bytes,
        raw_opening_bytes,
        certificate_header_bytes
            .saturating_add(aggregate_mask_bytes)
            .saturating_add(raw_opening_bytes),
        csv(tag_space_model(certificate_mode)),
        csv(result_label)
    ));
}

pub fn byte_accounting_for_submission(
    dim: usize,
    selected_count: usize,
    saiv_proof_bytes: u128,
) -> ByteAccounting {
    let ctx = CaseContext {
        experiment: "byte_accounting".into(),
        run_id: "byte_accounting".into(),
        n: selected_count.max(1),
        dimension: dim.max(1),
        admitted: 1,
        excluded: selected_count.saturating_sub(1),
        dropped: 0,
        non_admitted: selected_count.saturating_sub(1),
    };
    let incremental =
        compact_record_tag_bytes(&ctx) + receipt_size() + record_digest_evidence_bytes();
    let masked_update_bytes = (ctx.dimension as u128).saturating_mul(SCALAR_BYTES);
    ByteAccounting {
        incremental_avsa_extra: incremental,
        full_public_transcript: incremental
            .saturating_add(masked_update_bytes)
            .saturating_add(saiv_proof_bytes),
        raw_dispute_evidence: 0,
    }
}

pub fn byte_accounting_for_opening(
    dim: usize,
    admitted: usize,
    non_admitted: usize,
) -> ByteAccounting {
    let ctx = CaseContext {
        experiment: "byte_accounting".into(),
        run_id: "byte_accounting".into(),
        n: admitted.saturating_add(non_admitted).max(1),
        dimension: dim.max(1),
        admitted: admitted.max(1),
        excluded: non_admitted,
        dropped: 0,
        non_admitted,
    };
    ByteAccounting {
        incremental_avsa_extra: mask_open_header_bytes(&ctx),
        full_public_transcript: mask_open_header_bytes(&ctx)
            .saturating_add(raw_opening_bytes(&ctx)),
        raw_dispute_evidence: raw_opening_bytes(&ctx),
    }
}

pub fn aggregate_audit_extra_bytes(dim: usize) -> u128 {
    (dim.max(1) as u128).saturating_mul(SCALAR_BYTES)
}

fn compact_record_tag_bytes(ctx: &CaseContext) -> u128 {
    // B_i, D_i, and P_ir for every selected peer r != i.
    (2_u128 + ctx.n.saturating_sub(1) as u128).saturating_mul(POINT_BYTES)
}

fn masked_update_bytes(ctx: &CaseContext) -> u128 {
    (ctx.dimension as u128).saturating_mul(SCALAR_BYTES)
}

fn saiv_proof_bytes(_ctx: &CaseContext) -> u128 {
    SAIV_PROOF_BYTES_FOR_ACCOUNTING_TESTS
}

fn full_record_public_bytes(ctx: &CaseContext) -> u128 {
    compact_record_tag_bytes(ctx)
        .saturating_add(masked_update_bytes(ctx))
        .saturating_add(saiv_proof_bytes(ctx))
}

fn transcript_digest_log_bytes(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES + (ctx.n as u128).saturating_mul(ID_BYTES + DIGEST_BYTES)
}

fn record_digest_evidence_bytes() -> u128 {
    DIGEST_BYTES + ID_BYTES
}

fn receipt_size() -> u128 {
    ID_BYTES + DIGEST_BYTES + RECEIPT_SEQ_BYTES + SIG_BYTES
}

fn non_inclusion_witness_size(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES + (ctx.n as u128).saturating_mul(ID_BYTES + DIGEST_BYTES)
}

fn decision_cert_size(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES + SIG_BYTES + (ctx.n as u128).saturating_mul(ID_BYTES + DIGEST_BYTES + 1)
}

fn mask_tag_cert_size(ctx: &CaseContext) -> u128 {
    mask_tag_header_bytes(ctx).saturating_add(aggregate_mask_bytes(ctx))
}

fn mask_tag_header_bytes(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES
        + SIG_BYTES
        + (ctx.admitted as u128).saturating_mul(ID_BYTES + POINT_BYTES)
        + POINT_BYTES
}

fn aggregate_cert_size(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES
        + SIG_BYTES
        + (ctx.admitted as u128).saturating_mul(ID_BYTES)
        + (ctx.dimension as u128).saturating_mul(SCALAR_BYTES)
}

fn aggregate_mask_bytes(ctx: &CaseContext) -> u128 {
    (ctx.dimension as u128).saturating_mul(SCALAR_BYTES)
}

fn mask_open_header_bytes(ctx: &CaseContext) -> u128 {
    DIGEST_BYTES
        + SIG_BYTES
        + (ctx.admitted as u128).saturating_mul(ID_BYTES + POINT_BYTES)
        + ctx
            .boundary_size()
            .saturating_mul(2 * ID_BYTES + POINT_BYTES)
}

fn raw_opening_bytes(ctx: &CaseContext) -> u128 {
    (ctx.admitted as u128)
        .saturating_add(ctx.boundary_size())
        .saturating_mul(ctx.dimension as u128)
        .saturating_mul(SCALAR_BYTES)
}

fn common_cost_model(operation: &str) -> &'static str {
    match operation {
        "mask_tag_generation" => "O(n^2*T_tag(l))",
        "receipt_generation" | "digest_log_build" | "decision_cert_generation" => "O(n)",
        "maskcert_tag_generation" | "verify_mask_tag" => "O(a)+T_tag(l)",
        "verify_accepted_decisions" => "O(a*n)",
        "verify_aggregate" => "O(a*l)",
        "aggregate_cert_generation" => "O(l)",
        _ => "O(1)",
    }
}

fn common_space_model(operation: &str) -> &'static str {
    match operation {
        "mask_tag_generation" => "O(n^2) group elements",
        "receipt_generation" | "digest_log_build" | "decision_cert_generation" => "O(n)",
        "maskcert_tag_generation" | "verify_mask_tag" => "O(a)+O(l) if S_A published",
        "verify_aggregate" => "O(l) working space",
        "aggregate_cert_generation" => "O(l) aggregate mask, x_star excluded",
        _ => "O(1)",
    }
}

fn tag_generation_cost_model(mode: &str) -> &'static str {
    if mode == "open" {
        "O((a+boundary)*l)"
    } else {
        "O(a)+T_tag(l)"
    }
}

fn tag_verification_cost_model(mode: &str) -> &'static str {
    if mode == "open" {
        "O((a+boundary)*l)"
    } else {
        "O(a)+T_tag(l)"
    }
}

fn tag_space_model(mode: &str) -> &'static str {
    if mode == "open" {
        "O((a+boundary)*l) raw dispute evidence"
    } else {
        "O(a) tags plus one O(l) aggregate mask"
    }
}

fn appeal_cost_model(case: &str) -> &'static str {
    if case == "omission_with_digest_log" {
        "O(n), independent of l"
    } else {
        "O(n)+T_backend, backend excluded"
    }
}

fn appeal_space_model(case: &str) -> &'static str {
    if case == "omission_with_digest_log" {
        "O(n) non-inclusion witness, no record body"
    } else {
        "O(n) receipt/evidence metadata"
    }
}

fn malicious_cost_model(verifier: &str) -> &'static str {
    match verifier {
        "VerifyMaskOpen" => "O((a+boundary)*l)",
        "VerifyMaskTag" => "O(a)+T_tag(l)",
        "VerifyAggregate" => "O(a*l)",
        "VerifyAppeal" => "O(n), omission independent of l",
        _ => "O(n)",
    }
}

fn malicious_space_model(verifier: &str) -> &'static str {
    match verifier {
        "VerifyMaskOpen" => "O((a+boundary)*l)",
        "VerifyMaskTag" => "O(a)+O(l) if S_A published",
        "VerifyAggregate" => "O(l)",
        _ => "O(n)",
    }
}

fn time_source_for(verifier: &str, units: u128) -> TimeSource {
    if verifier == "VerifyMaskOpen" && units > SAMPLE_UNITS {
        TimeSource::Analytical
    } else {
        TimeSource::CalibratedEstimate
    }
}

fn work_kind_for(operation: &str) -> WorkKind {
    if operation.contains("tag") || operation.contains("maskcert") {
        WorkKind::Point
    } else if operation.contains("digest") || operation.contains("receipt") {
        WorkKind::Hash
    } else {
        WorkKind::Scalar
    }
}

fn scaled_time_ms(units: u128, kind: WorkKind) -> f64 {
    if units == 0 {
        return 0.0;
    }
    let sample = units.min(SAMPLE_UNITS).max(1) as usize;
    let start = Instant::now();
    match kind {
        WorkKind::Scalar => sample_scalar_work(sample),
        WorkKind::Point => sample_point_work(sample),
        WorkKind::Hash => sample_hash_work(sample),
    }
    elapsed_ms(start.elapsed()) * (units as f64 / sample as f64)
}

fn sample_scalar_work(sample: usize) {
    let mut acc = Scalar::ZERO;
    for i in 0..sample {
        acc += Scalar::from((i as u64).wrapping_add(7));
    }
    std::hint::black_box(acc);
}

fn sample_point_work(sample: usize) {
    let base = RistrettoPoint::identity();
    let mut acc = RistrettoPoint::identity();
    for i in 0..sample {
        acc += base * Scalar::from((i as u64).wrapping_add(11));
    }
    std::hint::black_box(acc);
}

fn sample_hash_work(sample: usize) {
    let mut state = 0xcbf29ce484222325_u64;
    for i in 0..sample {
        state ^= i as u64;
        state = state.wrapping_mul(0x100000001b3);
    }
    std::hint::black_box(state);
}

fn contexts(config: &FormalConfig) -> Result<Vec<CaseContext>> {
    let cases = if config.cases.is_empty() {
        vec![config.defaults.clone()]
    } else {
        config.cases.clone()
    };
    let repetitions = config.repetitions.max(1);
    let mut out = Vec::new();
    for case in cases {
        for repetition in 0..repetitions {
            out.push(CaseContext::new(&config.experiment, &case, repetition)?);
        }
    }
    Ok(out)
}

fn full_grid_config(experiment: &str, repetitions: usize) -> FormalConfig {
    let ns = [10_usize, 20, 50, 100, 200];
    let dims = [19_000_usize, 62_000, 273_000, 818_000];
    let mut cases = Vec::new();
    for n in ns {
        for dim in dims {
            let excluded = (n / 5).max(1);
            let admitted = n.saturating_sub(excluded).max(1);
            cases.push(FormalCase {
                name: format!("n{n}_d{dim}"),
                n,
                dimension: dim,
                admitted,
                excluded,
                dropped: 0,
                non_admitted: excluded,
                seed: 42,
            });
        }
    }
    FormalConfig {
        experiment: experiment.into(),
        output: None,
        defaults: FormalCase::default(),
        cases,
        repetitions,
    }
}

fn read_formal_config(path: &Path) -> Result<FormalConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| AvsaError::InvalidBenchConfig(err.to_string()))?;
    let mut experiment = String::new();
    let mut output = None;
    let mut defaults = FormalCase::default();
    let mut cases = Vec::new();
    let mut repetitions = 1_usize;
    let mut section = String::new();
    let mut current_case: Option<FormalCase> = None;

    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[cases]]" {
            if let Some(case) = current_case.take() {
                cases.push(case);
            }
            current_case = Some(defaults.clone());
            section = "case".into();
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(case) = current_case.take() {
                cases.push(case);
            }
            section = line.trim_matches(&['[', ']'][..]).to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match section.as_str() {
            "experiment" => match key {
                "name" | "kind" => experiment = value.into(),
                "output" => output = Some(PathBuf::from(value)),
                "repetitions" | "iters" => repetitions = parse_usize(key, value)?,
                _ => {}
            },
            "defaults" => {
                if key == "repetitions" || key == "iters" {
                    repetitions = parse_usize(key, value)?;
                } else {
                    set_case_field(&mut defaults, key, value)?;
                }
            }
            "case" => {
                if let Some(case) = &mut current_case {
                    set_case_field(case, key, value)?;
                }
            }
            _ => {}
        }
    }
    if let Some(case) = current_case.take() {
        cases.push(case);
    }
    if experiment.is_empty() {
        return Err(AvsaError::InvalidBenchConfig(
            "formal config missing [experiment] name".into(),
        ));
    }
    Ok(FormalConfig {
        experiment,
        output,
        defaults,
        cases,
        repetitions,
    })
}

fn set_case_field(case: &mut FormalCase, key: &str, value: &str) -> Result<()> {
    match key {
        "name" => case.name = value.into(),
        "n" | "n_selected" => case.n = parse_usize(key, value)?,
        "dimension" | "dim" | "ell" => case.dimension = parse_usize(key, value)?,
        "admitted" | "n_admitted" => case.admitted = parse_usize(key, value)?,
        "excluded" | "n_excluded" => case.excluded = parse_usize(key, value)?,
        "dropped" | "n_dropped" => case.dropped = parse_usize(key, value)?,
        "non_admitted" => case.non_admitted = parse_usize(key, value)?,
        "seed" => case.seed = parse_u64(key, value)?,
        "backend" => {}
        _ => {}
    }
    if case.non_admitted == 0 && case.n >= case.admitted {
        case.non_admitted = case.n - case.admitted;
    }
    if case.excluded == 0 && case.n >= case.admitted {
        case.excluded = case.n - case.admitted;
    }
    Ok(())
}

fn parse_usize(key: &str, value: &str) -> Result<usize> {
    value.parse::<usize>().map_err(|err| {
        AvsaError::InvalidBenchConfig(format!("invalid {key} in formal config: {err}"))
    })
}

fn parse_u64(key: &str, value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| AvsaError::InvalidBenchConfig(format!("invalid {key}: {err}")))
}

fn default_output_for(experiment: &str) -> PathBuf {
    match experiment {
        "common_path" => "results/common_path.csv",
        "tag_vs_opening" => "results/tag_vs_opening.csv",
        "appeal_cost" => "results/appeal_cost.csv",
        "malicious_server_detection" => "results/malicious_server_detection.csv",
        "baseline_overhead" => "results/baseline_overhead_percent.csv",
        "smoke" => "results/smoke.csv",
        _ => "results/formal.csv",
    }
    .into()
}

fn write_csv<'a, I>(path: &Path, header: &str, rows: I) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    ensure_parent(path)?;
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

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent)
                .map_err(|err| AvsaError::BenchCsvWriteFailed(err.to_string()))?;
        }
    }
    Ok(())
}

fn csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[derive(Clone, Debug, Default)]
struct BaselineGroup {
    scheme: String,
    source: String,
    dataset: String,
    dimension: usize,
    predicate: String,
    client_s: Option<f64>,
    server_s: Option<f64>,
    bandwidth_kb: Option<f64>,
}

pub fn write_baseline_overhead(
    baseline_path: &Path,
    common_path: &Path,
    tag_vs_opening_path: &Path,
    out_path: &Path,
) -> Result<usize> {
    let groups = read_baseline_groups(baseline_path)?;
    let common = read_common_overheads(common_path)?;
    let opening = read_opening_overheads(tag_vs_opening_path)?;
    let mut rows = Vec::new();
    for group in groups.into_values() {
        let (Some(client_s), Some(server_s), Some(bandwidth_kb)) =
            (group.client_s, group.server_s, group.bandwidth_kb)
        else {
            continue;
        };
        let Some(common_extra) = common.get(&group.dimension) else {
            continue;
        };
        let opening_extra_kb = opening.get(&group.dimension).copied().unwrap_or_default();
        let client_extra_percent = percent(common_extra.client_s, client_s);
        let server_extra_percent = percent(common_extra.server_s, server_s);
        let common_bandwidth_percent = percent(common_extra.common_kb, bandwidth_kb);
        let opening_bandwidth_percent = percent(opening_extra_kb, bandwidth_kb);
        rows.push(format!(
            "{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{}",
            csv(&group.scheme),
            csv(&group.dataset),
            group.dimension,
            csv(&group.predicate),
            client_s,
            common_extra.client_s,
            client_extra_percent,
            server_s,
            common_extra.server_s,
            server_extra_percent,
            bandwidth_kb,
            common_extra.common_kb,
            common_bandwidth_percent,
            opening_extra_kb,
            opening_bandwidth_percent,
            csv(&group.source),
            csv(COMPARISON_NOTE)
        ));
    }
    write_csv(
        out_path,
        BASELINE_OVERHEAD_HEADER,
        rows.iter().map(String::as_str),
    )?;
    Ok(rows.len())
}

fn read_baseline_groups(path: &Path) -> Result<BTreeMap<String, BaselineGroup>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| AvsaError::InvalidBenchConfig(err.to_string()))?;
    let mut lines = content.lines();
    let header = lines.next().unwrap_or_default();
    let expected = "scheme,source,dataset,dimension,predicate,operation,value,unit,scope,notes";
    if header.trim() != expected {
        return Err(AvsaError::InvalidBenchConfig(format!(
            "baseline CSV header mismatch: {header}"
        )));
    }
    let mut groups = BTreeMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<_> = line.split(',').collect();
        if cols.len() < 10 {
            continue;
        }
        let scheme = cols[0].trim();
        if scheme.eq_ignore_ascii_case("lzksa") {
            continue;
        }
        let dimension: usize = cols[3].trim().parse().map_err(|err| {
            AvsaError::InvalidBenchConfig(format!("invalid baseline dimension: {err}"))
        })?;
        let value: f64 = cols[6].trim().parse().map_err(|err| {
            AvsaError::InvalidBenchConfig(format!("invalid baseline value: {err}"))
        })?;
        let key = format!("{scheme}|{}|{}|{}", cols[2], dimension, cols[4]);
        let entry = groups.entry(key).or_insert_with(|| BaselineGroup {
            scheme: scheme.into(),
            source: cols[1].into(),
            dataset: cols[2].into(),
            dimension,
            predicate: cols[4].into(),
            ..BaselineGroup::default()
        });
        match cols[5].trim() {
            "client_prove_time_per_client" => entry.client_s = Some(value),
            "server_verify_time_per_client" => entry.server_s = Some(value),
            "bandwidth_per_client" => entry.bandwidth_kb = Some(value),
            _ => {}
        }
    }
    Ok(groups)
}

#[derive(Clone, Copy, Debug, Default)]
struct CommonExtra {
    client_s: f64,
    server_s: f64,
    common_kb: f64,
}

fn read_common_overheads(path: &Path) -> Result<BTreeMap<usize, CommonExtra>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| AvsaError::InvalidBenchConfig(err.to_string()))?;
    let mut lines = content.lines();
    let header = lines.next().unwrap_or_default();
    if header.trim() != COMMON_PATH_HEADER {
        return Err(AvsaError::InvalidBenchConfig(format!(
            "common_path header mismatch: {header}"
        )));
    }
    let mut by_dimension_n50: BTreeMap<usize, Vec<CommonCsvRow>> = BTreeMap::new();
    for line in lines {
        let cols: Vec<_> = line.split(',').collect();
        if cols.len() != 18 {
            continue;
        }
        let row = CommonCsvRow {
            n: cols[2].parse().unwrap_or_default(),
            dimension: cols[3].parse().unwrap_or_default(),
            admitted: cols[4].parse().unwrap_or(1),
            phase: cols[9].into(),
            time_ms: cols[11].parse().unwrap_or_default(),
            extra_bytes: cols[15].parse().unwrap_or_default(),
        };
        by_dimension_n50.entry(row.dimension).or_default().push(row);
    }
    let mut out = BTreeMap::new();
    for (dimension, rows) in by_dimension_n50 {
        let preferred_n = rows
            .iter()
            .map(|row| row.n)
            .min_by_key(|n| n.abs_diff(50))
            .unwrap_or(50);
        let selected: Vec<_> = rows
            .into_iter()
            .filter(|row| row.n == preferred_n)
            .collect();
        let admitted = selected.first().map(|row| row.admitted.max(1)).unwrap_or(1) as f64;
        let repetitions = selected
            .iter()
            .filter(|row| row.phase == "client_submit")
            .count()
            .max(1) as f64
            / 2.0;
        let client_ms: f64 = selected
            .iter()
            .filter(|row| row.phase == "client_submit")
            .map(|row| row.time_ms)
            .sum::<f64>()
            / repetitions.max(1.0);
        let server_ms: f64 = selected
            .iter()
            .filter(|row| row.phase == "auditor_verify")
            .map(|row| row.time_ms)
            .sum::<f64>()
            / repetitions.max(1.0);
        let extra_bytes: u128 = selected.iter().map(|row| row.extra_bytes).sum();
        out.insert(
            dimension,
            CommonExtra {
                client_s: client_ms / 1000.0 / admitted,
                server_s: server_ms / 1000.0 / admitted,
                common_kb: extra_bytes as f64 / 1024.0 / admitted / repetitions.max(1.0),
            },
        );
    }
    Ok(out)
}

#[derive(Clone, Debug)]
struct CommonCsvRow {
    n: usize,
    dimension: usize,
    admitted: usize,
    phase: String,
    time_ms: f64,
    extra_bytes: u128,
}

fn read_opening_overheads(path: &Path) -> Result<BTreeMap<usize, f64>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| AvsaError::InvalidBenchConfig(err.to_string()))?;
    let mut lines = content.lines();
    let header = lines.next().unwrap_or_default();
    if header.trim() != TAG_VS_OPENING_HEADER {
        return Err(AvsaError::InvalidBenchConfig(format!(
            "tag_vs_opening header mismatch: {header}"
        )));
    }
    let mut out = BTreeMap::new();
    for line in lines {
        let cols: Vec<_> = line.split(',').collect();
        if cols.len() != 21 || cols[8] != "open" {
            continue;
        }
        let n: usize = cols[2].parse().unwrap_or_default();
        if n != 50 {
            continue;
        }
        let dimension: usize = cols[3].parse().unwrap_or_default();
        let admitted: f64 = cols[4].parse::<usize>().unwrap_or(1).max(1) as f64;
        let total_extra: f64 = cols[18].parse::<u128>().unwrap_or_default() as f64;
        out.entry(dimension)
            .and_modify(|value| *value = (*value + total_extra / 1024.0 / admitted) / 2.0)
            .or_insert(total_extra / 1024.0 / admitted);
    }
    Ok(out)
}

fn percent(extra: f64, baseline: f64) -> f64 {
    if baseline > 0.0 {
        100.0 * extra / baseline
    } else {
        0.0
    }
}
