use crate::commit::{Generators, MaskTag};
use crate::record::ClientRecord;
use crate::vector::{add_vectors, random_scalar_vector, sub_vectors, zero_vector, ScalarVector};
use crate::{AvsaError, ClientId, Result};
use curve25519_dalek::traits::Identity;
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};

/// Canonical storage key for one shared pairwise mask p_{ir} = p_{ri}.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientPair {
    pub low: ClientId,
    pub high: ClientId,
}

impl ClientPair {
    pub fn new(left: ClientId, right: ClientId) -> Result<Self> {
        if left == right {
            return Err(AvsaError::InvalidParams(
                "pairwise mask endpoints must differ".into(),
            ));
        }
        if left < right {
            Ok(Self {
                low: left,
                high: right,
            })
        } else {
            Ok(Self {
                low: right,
                high: left,
            })
        }
    }
}

/// The sign sigma_ir from the manuscript: +1 if i < r, otherwise -1.
pub fn sigma(client: ClientId, peer: ClientId) -> i8 {
    if client < peer {
        1
    } else {
        -1
    }
}

/// Complete pairwise-mask graph over the selected set D_s.
#[derive(Clone, Debug)]
pub struct PairwiseMaskGraph {
    selected: Vec<ClientId>,
    dim: usize,
    self_masks: BTreeMap<ClientId, ScalarVector>,
    pair_masks: BTreeMap<ClientPair, ScalarVector>,
}

/// Public tag material derived from a client's masks.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientMaskTags {
    pub self_tag: MaskTag,
    pub pair_tags: BTreeMap<ClientId, MaskTag>,
    pub submitted_tag: MaskTag,
}

pub type AllClientMaskTags = BTreeMap<ClientId, ClientMaskTags>;

impl PairwiseMaskGraph {
    /// Sample self masks and all pairwise masks for a complete selected graph.
    pub fn sample_complete<R: RngCore + ?Sized>(
        selected: &[ClientId],
        dim: usize,
        rng: &mut R,
    ) -> Result<Self> {
        if dim == 0 {
            return Err(AvsaError::InvalidParams(
                "mask dimension must be positive".into(),
            ));
        }
        let selected = canonical_client_vec(selected)?;
        let mut self_masks = BTreeMap::new();
        for client in &selected {
            self_masks.insert(*client, random_scalar_vector(dim, rng));
        }

        let mut pair_masks = BTreeMap::new();
        for left_index in 0..selected.len() {
            for right_index in (left_index + 1)..selected.len() {
                let pair = ClientPair::new(selected[left_index], selected[right_index])?;
                pair_masks.insert(pair, random_scalar_vector(dim, rng));
            }
        }

        Ok(Self {
            selected,
            dim,
            self_masks,
            pair_masks,
        })
    }

    pub fn selected(&self) -> &[ClientId] {
        &self.selected
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn self_masks(&self) -> &BTreeMap<ClientId, ScalarVector> {
        &self.self_masks
    }

    pub fn pair_masks(&self) -> &BTreeMap<ClientPair, ScalarVector> {
        &self.pair_masks
    }

    pub fn self_mask(&self, client: ClientId) -> Result<&ScalarVector> {
        self.self_masks
            .get(&client)
            .ok_or(AvsaError::UnknownClient(client))
    }

    pub fn pair_mask(&self, left: ClientId, right: ClientId) -> Result<&ScalarVector> {
        let pair = ClientPair::new(left, right)?;
        self.pair_masks
            .get(&pair)
            .ok_or(AvsaError::MissingPair { left, right })
    }

    /// Compute only the signed pairwise contribution sum_r sigma_ir p_ir.
    pub fn pairwise_contribution(&self, client: ClientId) -> Result<ScalarVector> {
        ensure_selected(&self.selected, client)?;
        let mut acc = zero_vector(self.dim);
        for peer in &self.selected {
            if *peer == client {
                continue;
            }
            let pair_mask = self.pair_mask(client, *peer)?;
            acc = if sigma(client, *peer) == 1 {
                add_vectors(&acc, pair_mask)?
            } else {
                sub_vectors(&acc, pair_mask)?
            };
        }
        Ok(acc)
    }

    /// Compute s_i = r_i + sum_r sigma_ir p_ir.
    pub fn submitted_mask(&self, client: ClientId) -> Result<ScalarVector> {
        let self_mask = self.self_mask(client)?.clone();
        add_vectors(&self_mask, &self.pairwise_contribution(client)?)
    }

    /// Compute u_i = x_i + s_i.
    pub fn masked_update(
        &self,
        client: ClientId,
        update: &[curve25519_dalek::scalar::Scalar],
    ) -> Result<ScalarVector> {
        add_vectors(update, &self.submitted_mask(client)?)
    }

    /// Compute the compact public tags B_i, P_ir, and D_i for one client.
    pub fn client_tags(&self, generators: &Generators, client: ClientId) -> Result<ClientMaskTags> {
        self.all_client_tags(generators)?
            .remove(&client)
            .ok_or(AvsaError::UnknownClient(client))
    }

    /// Compute every B_i and unordered P_ir once, then derive D_i from tags.
    pub fn all_client_tags(&self, generators: &Generators) -> Result<AllClientMaskTags> {
        let mut out = BTreeMap::new();
        for client in &self.selected {
            out.insert(
                *client,
                ClientMaskTags {
                    self_tag: generators.tag_vector(self.self_mask(*client)?)?,
                    pair_tags: BTreeMap::new(),
                    submitted_tag: MaskTag::identity(),
                },
            );
        }
        for (pair, mask) in &self.pair_masks {
            let tag = generators.tag_vector(mask)?;
            out.get_mut(&pair.low)
                .ok_or(AvsaError::UnknownClient(pair.low))?
                .pair_tags
                .insert(pair.high, tag);
            out.get_mut(&pair.high)
                .ok_or(AvsaError::UnknownClient(pair.high))?
                .pair_tags
                .insert(pair.low, tag);
        }
        for client in &self.selected {
            let tags = out.get_mut(client).ok_or(AvsaError::UnknownClient(*client))?;
            tags.submitted_tag = expected_submitted_tag_from_components(
                *client,
                &self.selected,
                &tags.self_tag,
                &tags.pair_tags,
            )?;
        }
        Ok(out)
    }

    /// Compute Eq. (5): S_A = sum_{i in A} r_i + sum_{i in A,t in D_s\A} sigma_it p_it.
    pub fn aggregate_mask(&self, admitted: &[ClientId]) -> Result<ScalarVector> {
        let admitted = validate_subset(&self.selected, admitted)?;
        let mut acc = zero_vector(self.dim);

        for client in &admitted {
            acc = add_vectors(&acc, self.self_mask(*client)?)?;
        }

        for client in &admitted {
            for peer in &self.selected {
                if admitted.contains(peer) {
                    continue;
                }
                let pair_mask = self.pair_mask(*client, *peer)?;
                acc = if sigma(*client, *peer) == 1 {
                    add_vectors(&acc, pair_mask)?
                } else {
                    sub_vectors(&acc, pair_mask)?
                };
            }
        }

        Ok(acc)
    }
}

/// Return exactly {(i,t): i in A, t in D_s \ A}.
pub fn required_boundary_pairs(
    selected: &[ClientId],
    admitted: &[ClientId],
) -> Result<Vec<(ClientId, ClientId)>> {
    let selected = canonical_client_vec(selected)?;
    let admitted = validate_subset(&selected, admitted)?;
    let admitted_set: BTreeSet<_> = admitted.iter().copied().collect();
    let mut pairs = Vec::new();
    for client in &admitted {
        for peer in &selected {
            if !admitted_set.contains(peer) {
                pairs.push((*client, *peer));
            }
        }
    }
    Ok(pairs)
}

/// Check whether a candidate boundary set exactly equals A x (D_s \ A).
pub fn boundary_pairs_match(
    selected: &[ClientId],
    admitted: &[ClientId],
    candidate: &[(ClientId, ClientId)],
) -> Result<bool> {
    let required: BTreeSet<_> = required_boundary_pairs(selected, admitted)?
        .into_iter()
        .collect();
    let candidate: BTreeSet<_> = candidate.iter().copied().collect();
    Ok(required == candidate)
}

/// Reconstruct D_i from B_i and P_ir component tags.
pub fn expected_submitted_tag_from_components(
    client: ClientId,
    selected: &[ClientId],
    self_tag: &MaskTag,
    pair_tags: &BTreeMap<ClientId, MaskTag>,
) -> Result<MaskTag> {
    let selected = canonical_client_vec(selected)?;
    ensure_selected(&selected, client)?;
    let mut acc = *self_tag;
    for peer in selected {
        if peer == client {
            continue;
        }
        let pair_tag = pair_tags
            .get(&peer)
            .ok_or(AvsaError::MissingPairTag { client, peer })?;
        acc = if sigma(client, peer) == 1 {
            acc + *pair_tag
        } else {
            acc - *pair_tag
        };
    }
    Ok(acc)
}

/// Check D_i = B_i prod_r P_ir^{sigma_ir} in additive Ristretto notation.
pub fn submitted_tag_equation_holds(record: &ClientRecord, selected: &[ClientId]) -> Result<bool> {
    let expected = expected_submitted_tag_from_components(
        record.client_id,
        selected,
        &record.aux.self_tag,
        &record.aux.pair_tags,
    )?;
    Ok(expected == record.submitted_tag)
}

/// Sum masked updates for the admitted clients.
pub fn aggregate_masked_updates(
    records: &BTreeMap<ClientId, ClientRecord>,
    admitted: &[ClientId],
) -> Result<ScalarVector> {
    let first = admitted
        .first()
        .ok_or(AvsaError::EmptyInput("admitted set"))?;
    let dim = records
        .get(first)
        .ok_or(AvsaError::MissingClient(*first))?
        .dim();
    let mut acc = zero_vector(dim);
    for client in admitted {
        let record = records
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        acc = add_vectors(&acc, &record.masked_update)?;
    }
    Ok(acc)
}

/// Compute Eq. (6): x* = sum_{i in A} u_i - S_A.
pub fn aggregate_output(
    records: &BTreeMap<ClientId, ClientRecord>,
    graph: &PairwiseMaskGraph,
    admitted: &[ClientId],
) -> Result<ScalarVector> {
    let masked_sum = aggregate_masked_updates(records, admitted)?;
    let aggregate_mask = graph.aggregate_mask(admitted)?;
    sub_vectors(&masked_sum, &aggregate_mask)
}

/// Sum the original admitted updates retained by the simulation harness.
pub fn aggregate_plain_updates(
    updates: &BTreeMap<ClientId, ScalarVector>,
    admitted: &[ClientId],
) -> Result<ScalarVector> {
    let first = admitted
        .first()
        .ok_or(AvsaError::EmptyInput("admitted set"))?;
    let dim = updates
        .get(first)
        .ok_or(AvsaError::MissingClient(*first))?
        .len();
    let mut acc = zero_vector(dim);
    for client in admitted {
        let update = updates
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        acc = add_vectors(&acc, update)?;
    }
    Ok(acc)
}

/// Sum submitted masks for a client set.
pub fn sum_submitted_masks(
    graph: &PairwiseMaskGraph,
    clients: &[ClientId],
) -> Result<ScalarVector> {
    let mut acc = zero_vector(graph.dim());
    for client in clients {
        acc = add_vectors(&acc, &graph.submitted_mask(*client)?)?;
    }
    Ok(acc)
}

/// Sum self masks for a client set.
pub fn sum_self_masks(graph: &PairwiseMaskGraph, clients: &[ClientId]) -> Result<ScalarVector> {
    let mut acc = zero_vector(graph.dim());
    for client in clients {
        acc = add_vectors(&acc, graph.self_mask(*client)?)?;
    }
    Ok(acc)
}

pub fn component_tag_sum(tags: &[&MaskTag]) -> Result<MaskTag> {
    let mut acc = MaskTag::identity();
    for tag in tags {
        acc += **tag;
    }
    Ok(acc)
}

fn canonical_client_vec(clients: &[ClientId]) -> Result<Vec<ClientId>> {
    if clients.is_empty() {
        return Err(AvsaError::EmptyInput("client set"));
    }
    let mut set = BTreeSet::new();
    for client in clients {
        if !set.insert(*client) {
            return Err(AvsaError::DuplicateClient(*client));
        }
    }
    Ok(set.into_iter().collect())
}

fn ensure_selected(selected: &[ClientId], client: ClientId) -> Result<()> {
    if selected.binary_search(&client).is_ok() {
        Ok(())
    } else {
        Err(AvsaError::UnknownClient(client))
    }
}

fn validate_subset(selected: &[ClientId], subset: &[ClientId]) -> Result<Vec<ClientId>> {
    let selected = canonical_client_vec(selected)?;
    let subset = canonical_client_vec(subset)?;
    for client in &subset {
        ensure_selected(&selected, *client)?;
    }
    Ok(subset)
}
