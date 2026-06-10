use crate::commit::{Generators, MaskTag, PointVector};
use crate::mask::sigma;
use crate::record::ClientRecord;
use crate::vector::{add_vectors, ensure_same_len, random_scalar_vector, ScalarVector};
use crate::{AvsaError, ClientId, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet};

const SUBMIT_TRANSCRIPT_LABEL: &[u8] = b"AVSA-Round2-SubmitProof-v1";

/// Ordered public pair tag P_ir for one peer r.
#[derive(Clone, Copy, Debug)]
pub struct OrderedPeerTag<'a> {
    pub peer: ClientId,
    pub tag: &'a MaskTag,
}

/// Public inputs for Algorithm 2.
#[derive(Clone, Debug)]
pub struct SubmitPublicInputs<'a> {
    pub rid: &'a str,
    pub client_id: ClientId,
    pub selected_clients: &'a [ClientId],
    pub masked_update: &'a [Scalar],
    pub commitments: &'a [RistrettoPoint],
    pub submitted_tag: &'a MaskTag,
    pub self_tag: &'a MaskTag,
    pub pair_tags: &'a [OrderedPeerTag<'a>],
}

/// Private witnesses for Algorithm 2.
#[derive(Clone, Debug)]
pub struct SubmitWitness<'a> {
    pub update: &'a [Scalar],
    pub commitment_blinding: &'a [Scalar],
    pub submitted_mask: &'a [Scalar],
}

/// First-message view used to derive the Fiat-Shamir challenge.
#[derive(Clone, Copy, Debug)]
pub struct SubmitFirstMessages<'a> {
    pub a_u: &'a [Scalar],
    pub a_c: &'a [RistrettoPoint],
    pub a_d: &'a MaskTag,
}

/// Schnorr-style submission-binding proof from manuscript Algorithm 2.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitProof {
    /// Linear first message A_u = a_x + a_s.
    pub a_u: ScalarVector,
    /// Pedersen first-message commitments A_C,j = g^{a_x,j} h^{a_rho,j}.
    pub a_c: PointVector,
    /// Compact tag first message A_D = Tag(a_s).
    pub a_d: MaskTag,
    /// Responses z_x = a_x + c x_i.
    pub z_x: ScalarVector,
    /// Responses z_rho = a_rho + c rho_i.
    pub z_rho: ScalarVector,
    /// Responses z_s = a_s + c s_i.
    pub z_s: ScalarVector,
}

impl SubmitProof {
    pub fn dim(&self) -> usize {
        self.a_u.len()
    }

    pub fn first_messages(&self) -> SubmitFirstMessages<'_> {
        SubmitFirstMessages {
            a_u: &self.a_u,
            a_c: &self.a_c,
            a_d: &self.a_d,
        }
    }

    /// Deterministic proof encoding for record hashing.
    pub fn write_canonical_bytes(&self, out: &mut Vec<u8>) {
        push_scalar_vector(out, &self.a_u);
        push_point_vector(out, &self.a_c);
        push_point(out, &self.a_d);
        push_scalar_vector(out, &self.z_x);
        push_scalar_vector(out, &self.z_rho);
        push_scalar_vector(out, &self.z_s);
    }
}

/// Build the deterministic ordered peer-tag list selected by D_s \ {i}.
pub fn ordered_peer_tags_from_map<'a>(
    client_id: ClientId,
    selected_clients: &[ClientId],
    pair_tags: &'a BTreeMap<ClientId, MaskTag>,
) -> Result<Vec<OrderedPeerTag<'a>>> {
    validate_selected_clients(client_id, selected_clients)?;
    let expected_len = selected_clients.len().saturating_sub(1);
    if pair_tags.len() != expected_len {
        return Err(AvsaError::InvalidPeerOrder(
            "peer tag map must contain exactly D_s \\ {i}".into(),
        ));
    }

    let mut ordered = Vec::with_capacity(expected_len);
    for peer in selected_clients {
        if *peer == client_id {
            continue;
        }
        let tag = pair_tags.get(peer).ok_or(AvsaError::MissingPeerTag {
            client: client_id,
            peer: *peer,
        })?;
        ordered.push(OrderedPeerTag { peer: *peer, tag });
    }
    Ok(ordered)
}

/// Prove Algorithm 2 for one client record witness.
pub fn submit_prove<R: RngCore + ?Sized>(
    public: &SubmitPublicInputs<'_>,
    witness: &SubmitWitness<'_>,
    generators: &Generators,
    rng: &mut R,
) -> Result<SubmitProof> {
    let dim = validate_public_inputs(public)?;
    ensure_same_len("submit witness update", dim, witness.update.len())?;
    ensure_same_len(
        "submit witness commitment blinding",
        dim,
        witness.commitment_blinding.len(),
    )?;
    ensure_same_len(
        "submit witness submitted mask",
        dim,
        witness.submitted_mask.len(),
    )?;

    let a_x = random_scalar_vector(dim, rng);
    let a_rho = random_scalar_vector(dim, rng);
    let a_s = random_scalar_vector(dim, rng);
    let a_u = add_vectors(&a_x, &a_s)?;
    let a_c = generators.commit_vector(&a_x, &a_rho)?;
    let a_d = generators.tag_vector(&a_s)?;

    let first_messages = SubmitFirstMessages {
        a_u: &a_u,
        a_c: &a_c,
        a_d: &a_d,
    };
    let challenge = submit_challenge(public, &first_messages, generators)?;

    let z_x = a_x
        .iter()
        .zip(witness.update.iter())
        .map(|(a, value)| *a + challenge * *value)
        .collect();
    let z_rho = a_rho
        .iter()
        .zip(witness.commitment_blinding.iter())
        .map(|(a, value)| *a + challenge * *value)
        .collect();
    let z_s = a_s
        .iter()
        .zip(witness.submitted_mask.iter())
        .map(|(a, value)| *a + challenge * *value)
        .collect();

    Ok(SubmitProof {
        a_u,
        a_c,
        a_d,
        z_x,
        z_rho,
        z_s,
    })
}

/// Verify Algorithm 2 for the supplied public inputs and proof.
pub fn submit_verify(
    public: &SubmitPublicInputs<'_>,
    proof: &SubmitProof,
    generators: &Generators,
) -> Result<()> {
    let dim = validate_public_inputs(public)?;
    validate_proof_dimensions(dim, proof)?;
    verify_mask_tag_equation(public)?;

    let challenge = submit_challenge(public, &proof.first_messages(), generators)?;

    for j in 0..dim {
        let linear_left = proof.z_x[j] + proof.z_s[j];
        let linear_right = proof.a_u[j] + challenge * public.masked_update[j];
        if linear_left != linear_right {
            return Err(AvsaError::InvalidSubmitProof(
                "masked-update linear equation failed",
            ));
        }

        let commitment_left = generators.g * proof.z_x[j] + generators.h * proof.z_rho[j];
        let commitment_right = proof.a_c[j] + public.commitments[j] * challenge;
        if commitment_left != commitment_right {
            return Err(AvsaError::InvalidSubmitProof(
                "Pedersen commitment equation failed",
            ));
        }
    }

    let tag_left = generators.tag_vector(&proof.z_s)?;
    let tag_right = proof.a_d + *public.submitted_tag * challenge;
    if tag_left != tag_right {
        return Err(AvsaError::InvalidSubmitProof(
            "submitted mask-tag equation failed",
        ));
    }

    Ok(())
}

/// Verify the submission proof embedded in a client record.
pub fn submit_verify_record(
    record: &ClientRecord,
    selected_clients: &[ClientId],
    generators: &Generators,
) -> Result<()> {
    let pair_tags =
        ordered_peer_tags_from_map(record.client_id, selected_clients, &record.aux.pair_tags)?;
    let public = SubmitPublicInputs {
        rid: &record.round_id,
        client_id: record.client_id,
        selected_clients,
        masked_update: &record.masked_update,
        commitments: &record.commitments,
        submitted_tag: &record.submitted_tag,
        self_tag: &record.aux.self_tag,
        pair_tags: &pair_tags,
    };
    submit_verify(&public, &record.submission_proof, generators)
}

/// Recompute the Fiat-Shamir challenge for an existing record proof.
pub fn challenge_for_record(
    record: &ClientRecord,
    selected_clients: &[ClientId],
    generators: &Generators,
) -> Result<Scalar> {
    let pair_tags =
        ordered_peer_tags_from_map(record.client_id, selected_clients, &record.aux.pair_tags)?;
    let public = SubmitPublicInputs {
        rid: &record.round_id,
        client_id: record.client_id,
        selected_clients,
        masked_update: &record.masked_update,
        commitments: &record.commitments,
        submitted_tag: &record.submitted_tag,
        self_tag: &record.aux.self_tag,
        pair_tags: &pair_tags,
    };
    submit_challenge(
        &public,
        &record.submission_proof.first_messages(),
        generators,
    )
}

/// Deterministic Fiat-Shamir challenge derived with canonical serialization.
pub fn submit_challenge(
    public: &SubmitPublicInputs<'_>,
    first_messages: &SubmitFirstMessages<'_>,
    generators: &Generators,
) -> Result<Scalar> {
    let dim = validate_public_inputs(public)?;
    ensure_same_len("submit transcript A_u", dim, first_messages.a_u.len())?;
    ensure_same_len("submit transcript A_C", dim, first_messages.a_c.len())?;

    let mut hasher = Sha512::new();
    hasher.update(SUBMIT_TRANSCRIPT_LABEL);
    push_len_prefixed_hasher(&mut hasher, public.rid.as_bytes());
    hasher.update(public.client_id.to_le_bytes());
    hasher.update((dim as u64).to_le_bytes());
    push_client_list_hasher(&mut hasher, public.selected_clients);
    push_point_hasher(&mut hasher, &generators.g);
    push_point_hasher(&mut hasher, &generators.h);
    push_point_hasher(&mut hasher, &generators.k);
    push_scalar_slice_hasher(&mut hasher, public.masked_update);
    push_point_slice_hasher(&mut hasher, public.commitments);
    push_point_hasher(&mut hasher, public.submitted_tag);
    push_point_hasher(&mut hasher, public.self_tag);
    push_peer_tags_hasher(&mut hasher, public.pair_tags);
    push_scalar_slice_hasher(&mut hasher, first_messages.a_u);
    push_point_slice_hasher(&mut hasher, first_messages.a_c);
    push_point_hasher(&mut hasher, first_messages.a_d);

    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide.copy_from_slice(&digest);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn validate_public_inputs(public: &SubmitPublicInputs<'_>) -> Result<usize> {
    validate_selected_clients(public.client_id, public.selected_clients)?;
    validate_peer_order(public.client_id, public.selected_clients, public.pair_tags)?;

    let dim = public.masked_update.len();
    if dim == 0 {
        return Err(AvsaError::EmptyInput("submission vector"));
    }
    ensure_same_len("submit commitments", dim, public.commitments.len())?;
    Ok(dim)
}

fn validate_proof_dimensions(dim: usize, proof: &SubmitProof) -> Result<()> {
    ensure_same_len("submit proof A_u", dim, proof.a_u.len())?;
    ensure_same_len("submit proof A_C", dim, proof.a_c.len())?;
    ensure_same_len("submit proof z_x", dim, proof.z_x.len())?;
    ensure_same_len("submit proof z_rho", dim, proof.z_rho.len())?;
    ensure_same_len("submit proof z_s", dim, proof.z_s.len())?;
    Ok(())
}

fn validate_selected_clients(client_id: ClientId, selected_clients: &[ClientId]) -> Result<()> {
    if selected_clients.is_empty() {
        return Err(AvsaError::EmptyInput("selected clients"));
    }

    let mut seen = BTreeSet::new();
    let mut found_client = false;
    for client in selected_clients {
        if !seen.insert(*client) {
            return Err(AvsaError::InvalidPeerOrder(
                "selected-client list contains duplicates".into(),
            ));
        }
        if *client == client_id {
            found_client = true;
        }
    }
    if !found_client {
        return Err(AvsaError::InvalidPeerOrder(
            "selected-client list does not contain the prover".into(),
        ));
    }
    Ok(())
}

fn validate_peer_order(
    client_id: ClientId,
    selected_clients: &[ClientId],
    pair_tags: &[OrderedPeerTag<'_>],
) -> Result<()> {
    let expected_len = selected_clients.len().saturating_sub(1);
    if pair_tags.len() != expected_len {
        return Err(AvsaError::InvalidPeerOrder(
            "ordered peer tags must match D_s \\ {i}".into(),
        ));
    }

    let mut tag_iter = pair_tags.iter();
    for peer in selected_clients {
        if *peer == client_id {
            continue;
        }
        let tag = tag_iter
            .next()
            .ok_or_else(|| AvsaError::InvalidPeerOrder("ordered peer tags ended early".into()))?;
        if tag.peer != *peer {
            return Err(AvsaError::InvalidPeerOrder(
                "ordered peer tags are not aligned with selected clients".into(),
            ));
        }
    }
    if tag_iter.next().is_some() {
        return Err(AvsaError::InvalidPeerOrder(
            "ordered peer tags contain extra entries".into(),
        ));
    }
    Ok(())
}

fn verify_mask_tag_equation(public: &SubmitPublicInputs<'_>) -> Result<()> {
    let mut expected = *public.self_tag;
    for peer_tag in public.pair_tags {
        expected = if sigma(public.client_id, peer_tag.peer) == 1 {
            expected + *peer_tag.tag
        } else {
            expected - *peer_tag.tag
        };
    }
    if expected == *public.submitted_tag {
        Ok(())
    } else {
        Err(AvsaError::InvalidMaskTagEquation)
    }
}

fn push_len_prefixed_hasher(hasher: &mut Sha512, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn push_client_list_hasher(hasher: &mut Sha512, clients: &[ClientId]) {
    hasher.update((clients.len() as u64).to_le_bytes());
    for client in clients {
        hasher.update(client.to_le_bytes());
    }
}

fn push_scalar_slice_hasher(hasher: &mut Sha512, values: &[Scalar]) {
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update(value.to_bytes());
    }
}

fn push_point_hasher(hasher: &mut Sha512, point: &RistrettoPoint) {
    hasher.update(point.compress().as_bytes());
}

fn push_point_slice_hasher(hasher: &mut Sha512, values: &[RistrettoPoint]) {
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        push_point_hasher(hasher, value);
    }
}

fn push_peer_tags_hasher(hasher: &mut Sha512, pair_tags: &[OrderedPeerTag<'_>]) {
    hasher.update((pair_tags.len() as u64).to_le_bytes());
    for pair_tag in pair_tags {
        hasher.update(pair_tag.peer.to_le_bytes());
        push_point_hasher(hasher, pair_tag.tag);
    }
}

fn push_scalar_vector(out: &mut Vec<u8>, values: &[Scalar]) {
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value.to_bytes());
    }
}

fn push_point_vector(out: &mut Vec<u8>, values: &[RistrettoPoint]) {
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        out.extend_from_slice(value.compress().as_bytes());
    }
}

fn push_point(out: &mut Vec<u8>, value: &RistrettoPoint) {
    out.extend_from_slice(value.compress().as_bytes());
}
