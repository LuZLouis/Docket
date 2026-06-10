use crate::audit::decision::PublicAuditContext;
use crate::mask::{required_boundary_pairs, sigma};
use crate::record::ClientRecord;
use crate::vector::{add_vectors, sub_vectors, zero_vector, ScalarVector};
use crate::{AvsaError, ClientId, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use std::collections::{BTreeMap, BTreeSet};

/// Canonical admitted client set A.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedSet {
    pub clients: Vec<ClientId>,
}

impl AdmittedSet {
    pub fn new(clients: impl Into<Vec<ClientId>>) -> Result<Self> {
        let mut clients = clients.into();
        clients.sort_unstable();
        for window in clients.windows(2) {
            if window[0] == window[1] {
                return Err(AvsaError::DuplicateAdmittedClient(window[0]));
            }
        }
        if clients.is_empty() {
            return Err(AvsaError::EmptyInput("admitted set"));
        }
        Ok(Self { clients })
    }

    pub fn validate_subset_of(&self, selected_clients: &[ClientId]) -> Result<()> {
        if self.clients.is_empty() {
            return Err(AvsaError::InvalidAdmittedSet);
        }
        for window in self.clients.windows(2) {
            if window[0] >= window[1] {
                return Err(AvsaError::InvalidAdmittedSet);
            }
        }
        let selected = canonical_client_vec(selected_clients)?;
        let mut seen = BTreeSet::new();
        for client in &self.clients {
            if !seen.insert(*client) {
                return Err(AvsaError::DuplicateAdmittedClient(*client));
            }
            if !selected.contains(client) {
                return Err(AvsaError::AdmittedSetNotSubsetOfSelected);
            }
        }
        Ok(())
    }
}

/// Raw opening of an admitted client's self mask r_i.
#[derive(Clone, Debug, PartialEq)]
pub struct SelfMaskOpening {
    pub client_id: ClientId,
    pub mask: ScalarVector,
}

/// Raw opening of p_it where admitted_client is in A and other_client is in D_s \ A.
#[derive(Clone, Debug, PartialEq)]
pub struct PairMaskOpening {
    pub admitted_client: ClientId,
    pub other_client: ClientId,
    pub mask: ScalarVector,
}

/// Raw-evidence mask certificate from Algorithm 8.
#[derive(Clone, Debug, PartialEq)]
pub struct MaskCertificate {
    pub round_id: String,
    pub selected_clients: Vec<ClientId>,
    pub admitted_set: AdmittedSet,
    pub aggregate_mask: ScalarVector,
    pub self_openings: Vec<SelfMaskOpening>,
    pub pair_openings: Vec<PairMaskOpening>,
}

/// Backward-compatible alias for the Round 1 skeleton name.
pub type MaskCert = MaskCertificate;

/// Compact common-path mask certificate.
///
/// This certificate exposes only the aggregate mask S_A and compact tag
/// relation; it does not contain raw self or pairwise openings.
#[derive(Clone, Debug, PartialEq)]
pub struct MaskTagCertificate {
    pub round_id: String,
    pub selected_clients: Vec<ClientId>,
    pub admitted_set: AdmittedSet,
    pub aggregate_mask: ScalarVector,
}

pub fn required_self_openings(admitted_set: &AdmittedSet) -> BTreeSet<ClientId> {
    admitted_set.clients.iter().copied().collect()
}

pub fn required_pair_openings(
    selected_clients: &[ClientId],
    admitted_set: &AdmittedSet,
) -> Result<BTreeSet<(ClientId, ClientId)>> {
    Ok(
        required_boundary_pairs(selected_clients, &admitted_set.clients)?
            .into_iter()
            .collect(),
    )
}

pub fn verify_mask_certificate(
    cert: &MaskCertificate,
    records_by_client: &BTreeMap<ClientId, ClientRecord>,
    context: &PublicAuditContext<'_>,
) -> Result<()> {
    if cert.round_id != context.round_id {
        return Err(AvsaError::MaskCertificateRoundMismatch);
    }

    let selected = canonical_client_vec(&cert.selected_clients)?;
    let context_selected = canonical_client_vec(context.selected_clients)?;
    if selected != context_selected {
        return Err(AvsaError::MaskCertificateSelectedSetMismatch);
    }

    cert.admitted_set.validate_subset_of(&selected)?;
    let admitted = cert.admitted_set.clients.clone();
    let admitted_set: BTreeSet<_> = admitted.iter().copied().collect();
    let dim = mask_dimension(records_by_client, &admitted, &cert.aggregate_mask)?;

    for client in &admitted {
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        if record.round_id != cert.round_id {
            return Err(AvsaError::MaskCertificateRoundMismatch);
        }
        if record.dim() != dim {
            return Err(AvsaError::InvalidMaskOpeningDimension);
        }
    }

    let self_openings = collect_self_openings(&cert.self_openings, dim)?;
    let pair_openings = collect_pair_openings(&cert.pair_openings, dim)?;
    check_self_coverage(&required_self_openings(&cert.admitted_set), &self_openings)?;
    let required_pairs = required_pair_openings(&selected, &cert.admitted_set)?;
    check_pair_coverage(&required_pairs, &pair_openings)?;

    let mut recomputed_mask = zero_vector(dim);
    for client in &admitted {
        let opening = self_openings
            .get(client)
            .ok_or(AvsaError::MissingSelfOpening(*client))?;
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        if context.generators.tag_vector(opening)? != record.aux.self_tag {
            return Err(AvsaError::InvalidSelfMaskOpening);
        }
        recomputed_mask = add_vectors(&recomputed_mask, opening)?;
    }

    for (admitted_client, other_client) in &required_pairs {
        if !admitted_set.contains(admitted_client) || admitted_set.contains(other_client) {
            return Err(AvsaError::InvalidPairMaskOpening);
        }
        let opening = pair_openings
            .get(&(*admitted_client, *other_client))
            .ok_or(AvsaError::MissingPairOpening {
                admitted: *admitted_client,
                other: *other_client,
            })?;
        let admitted_record = records_by_client
            .get(admitted_client)
            .ok_or(AvsaError::MissingClient(*admitted_client))?;
        let expected_tag = context.generators.tag_vector(opening)?;
        let admitted_pair_tag =
            admitted_record
                .aux
                .pair_tags
                .get(other_client)
                .ok_or(AvsaError::MissingPairTag {
                    client: *admitted_client,
                    peer: *other_client,
                })?;
        if expected_tag != *admitted_pair_tag {
            return Err(AvsaError::InvalidPairMaskOpening);
        }
        if let Some(other_record) = records_by_client.get(other_client) {
            let other_pair_tag = other_record.aux.pair_tags.get(admitted_client).ok_or(
                AvsaError::MissingPairTag {
                    client: *other_client,
                    peer: *admitted_client,
                },
            )?;
            if expected_tag != *other_pair_tag {
                return Err(AvsaError::InvalidPairMaskOpening);
            }
        }

        recomputed_mask = if sigma(*admitted_client, *other_client) == 1 {
            add_vectors(&recomputed_mask, opening)?
        } else {
            sub_vectors(&recomputed_mask, opening)?
        };
    }

    if recomputed_mask != cert.aggregate_mask {
        return Err(AvsaError::InvalidAggregateMask);
    }

    verify_aggregate_tag_relation(
        &admitted,
        records_by_client,
        &cert.aggregate_mask,
        context,
        dim,
    )
}

pub fn verify_mask_tag_certificate(
    cert: &MaskTagCertificate,
    records_by_client: &BTreeMap<ClientId, ClientRecord>,
    context: &PublicAuditContext<'_>,
) -> Result<()> {
    if cert.round_id != context.round_id {
        return Err(AvsaError::MaskCertificateRoundMismatch);
    }
    let selected = canonical_client_vec(&cert.selected_clients)?;
    let context_selected = canonical_client_vec(context.selected_clients)?;
    if selected != context_selected {
        return Err(AvsaError::MaskCertificateSelectedSetMismatch);
    }
    cert.admitted_set.validate_subset_of(&selected)?;
    let admitted = cert.admitted_set.clients.clone();
    let dim = mask_dimension(records_by_client, &admitted, &cert.aggregate_mask)?;
    verify_aggregate_tag_relation(
        &admitted,
        records_by_client,
        &cert.aggregate_mask,
        context,
        dim,
    )
}

impl From<&MaskCertificate> for MaskTagCertificate {
    fn from(cert: &MaskCertificate) -> Self {
        Self {
            round_id: cert.round_id.clone(),
            selected_clients: cert.selected_clients.clone(),
            admitted_set: cert.admitted_set.clone(),
            aggregate_mask: cert.aggregate_mask.clone(),
        }
    }
}

fn mask_dimension(
    records_by_client: &BTreeMap<ClientId, ClientRecord>,
    admitted: &[ClientId],
    aggregate_mask: &[Scalar],
) -> Result<usize> {
    let dim = aggregate_mask.len();
    if dim == 0 {
        return Err(AvsaError::EmptyInput("aggregate mask"));
    }
    for client in admitted {
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        if record.dim() != dim {
            return Err(AvsaError::InvalidMaskOpeningDimension);
        }
    }
    Ok(dim)
}

fn collect_self_openings(
    openings: &[SelfMaskOpening],
    dim: usize,
) -> Result<BTreeMap<ClientId, ScalarVector>> {
    let mut out = BTreeMap::new();
    for opening in openings {
        if opening.mask.len() != dim {
            return Err(AvsaError::InvalidMaskOpeningDimension);
        }
        if out
            .insert(opening.client_id, opening.mask.clone())
            .is_some()
        {
            return Err(AvsaError::ExtraSelfOpening(opening.client_id));
        }
    }
    Ok(out)
}

fn collect_pair_openings(
    openings: &[PairMaskOpening],
    dim: usize,
) -> Result<BTreeMap<(ClientId, ClientId), ScalarVector>> {
    let mut out = BTreeMap::new();
    for opening in openings {
        if opening.mask.len() != dim {
            return Err(AvsaError::InvalidMaskOpeningDimension);
        }
        let key = (opening.admitted_client, opening.other_client);
        if out.insert(key, opening.mask.clone()).is_some() {
            return Err(AvsaError::ExtraPairOpening {
                admitted: key.0,
                other: key.1,
            });
        }
    }
    Ok(out)
}

fn check_self_coverage(
    required: &BTreeSet<ClientId>,
    actual: &BTreeMap<ClientId, ScalarVector>,
) -> Result<()> {
    for client in required {
        if !actual.contains_key(client) {
            return Err(AvsaError::MissingSelfOpening(*client));
        }
    }
    for client in actual.keys() {
        if !required.contains(client) {
            return Err(AvsaError::ExtraSelfOpening(*client));
        }
    }
    Ok(())
}

fn check_pair_coverage(
    required: &BTreeSet<(ClientId, ClientId)>,
    actual: &BTreeMap<(ClientId, ClientId), ScalarVector>,
) -> Result<()> {
    for (admitted, other) in required {
        if !actual.contains_key(&(*admitted, *other)) {
            return Err(AvsaError::MissingPairOpening {
                admitted: *admitted,
                other: *other,
            });
        }
    }
    for (admitted, other) in actual.keys() {
        if !required.contains(&(*admitted, *other)) {
            return Err(AvsaError::ExtraPairOpening {
                admitted: *admitted,
                other: *other,
            });
        }
    }
    Ok(())
}

fn verify_aggregate_tag_relation(
    admitted: &[ClientId],
    records_by_client: &BTreeMap<ClientId, ClientRecord>,
    aggregate_mask: &[Scalar],
    context: &PublicAuditContext<'_>,
    _dim: usize,
) -> Result<()> {
    let mut tag_product = RistrettoPoint::identity();
    for client in admitted {
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        tag_product += record.submitted_tag;
    }
    let expected = context.generators.tag_vector(aggregate_mask)?;
    if tag_product == expected {
        Ok(())
    } else {
        Err(AvsaError::InvalidAggregateTagRelation)
    }
}

fn canonical_client_vec(clients: &[ClientId]) -> Result<Vec<ClientId>> {
    if clients.is_empty() {
        return Err(AvsaError::EmptyInput("client set"));
    }
    let mut out = clients.to_vec();
    out.sort_unstable();
    for window in out.windows(2) {
        if window[0] == window[1] {
            return Err(AvsaError::DuplicateClient(window[0]));
        }
    }
    Ok(out)
}
