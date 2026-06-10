use crate::commit::Generators;
use crate::mask::PairwiseMaskGraph;
use crate::proof::submit::{
    ordered_peer_tags_from_map, submit_prove, SubmitPublicInputs, SubmitWitness,
};
use crate::record::{ClientAux, ClientRecord, ProofPlaceholder};
use crate::vector::{add_vectors, encode_signed_vector, random_scalar_vector, ScalarVector};
use crate::{AvsaError, ClientId, Result};
use rand::RngCore;
use std::collections::BTreeMap;

/// Honest simulated round state used by algebraic unit tests.
#[derive(Clone, Debug)]
pub struct HonestRound {
    pub round_id: String,
    pub selected: Vec<ClientId>,
    pub signed_updates: BTreeMap<ClientId, Vec<i64>>,
    pub updates: BTreeMap<ClientId, ScalarVector>,
    pub commitment_blindings: BTreeMap<ClientId, ScalarVector>,
    pub graph: PairwiseMaskGraph,
    pub records: BTreeMap<ClientId, ClientRecord>,
}

/// Build honest Round 1 records from signed simulated updates.
pub fn build_honest_round<R: RngCore + ?Sized>(
    round_id: impl Into<String>,
    selected: &[ClientId],
    signed_updates: BTreeMap<ClientId, Vec<i64>>,
    generators: &Generators,
    rng: &mut R,
) -> Result<HonestRound> {
    let round_id = round_id.into();
    let first_client = selected
        .first()
        .ok_or(AvsaError::EmptyInput("selected set"))?;
    let dim = signed_updates
        .get(first_client)
        .ok_or(AvsaError::MissingClient(*first_client))?
        .len();
    let graph = PairwiseMaskGraph::sample_complete(selected, dim, rng)?;
    let all_tags = graph.all_client_tags(generators)?;

    let mut updates = BTreeMap::new();
    let mut commitment_blindings = BTreeMap::new();
    let mut records = BTreeMap::new();

    for client in graph.selected() {
        let signed_update = signed_updates
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        if signed_update.len() != dim {
            return Err(AvsaError::DimensionMismatch {
                context: "honest round signed update",
                expected: dim,
                actual: signed_update.len(),
            });
        }

        let update = encode_signed_vector(signed_update);
        let blindings = random_scalar_vector(dim, rng);
        let commitments = generators.commit_vector(&update, &blindings)?;
        let tags = all_tags
            .get(client)
            .ok_or(AvsaError::UnknownClient(*client))?
            .clone();
        let submitted_mask = graph.submitted_mask(*client)?;
        let masked_update = add_vectors(&update, &submitted_mask)?;
        let submission_proof = {
            let pair_tags = ordered_peer_tags_from_map(*client, graph.selected(), &tags.pair_tags)?;
            let public = SubmitPublicInputs {
                rid: &round_id,
                client_id: *client,
                selected_clients: graph.selected(),
                masked_update: &masked_update,
                commitments: &commitments,
                submitted_tag: &tags.submitted_tag,
                self_tag: &tags.self_tag,
                pair_tags: &pair_tags,
            };
            let witness = SubmitWitness {
                update: &update,
                commitment_blinding: &blindings,
                submitted_mask: &submitted_mask,
            };
            submit_prove(&public, &witness, generators, rng)?
        };
        let record = ClientRecord::new(
            round_id.clone(),
            *client,
            masked_update,
            commitments,
            tags.submitted_tag,
            ClientAux {
                self_tag: tags.self_tag,
                pair_tags: tags.pair_tags,
            },
            submission_proof,
            ProofPlaceholder::new("round1-data-placeholder"),
        )?;

        updates.insert(*client, update);
        commitment_blindings.insert(*client, blindings);
        records.insert(*client, record);
    }

    Ok(HonestRound {
        round_id,
        selected: graph.selected().to_vec(),
        signed_updates,
        updates,
        commitment_blindings,
        graph,
        records,
    })
}
