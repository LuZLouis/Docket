use crate::commit::{MaskTag, PointVector};
use crate::proof::submit::SubmitProof;
use crate::vector::{ensure_same_len, ScalarVector};
use crate::{ClientId, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Placeholder proof object used until later rounds implement real proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofPlaceholder {
    pub label: String,
}

impl ProofPlaceholder {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

impl Default for ProofPlaceholder {
    fn default() -> Self {
        Self::new("round1-proof-placeholder")
    }
}

/// Auxiliary public tag material carried by a client record in Round 1.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientAux {
    pub self_tag: MaskTag,
    pub pair_tags: BTreeMap<ClientId, MaskTag>,
}

/// Skeleton of the AVSA client record M_i.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientRecord {
    pub round_id: String,
    pub client_id: ClientId,
    pub masked_update: ScalarVector,
    pub commitments: PointVector,
    pub submitted_tag: MaskTag,
    pub aux: ClientAux,
    pub submission_proof: SubmitProof,
    pub data_proof: ProofPlaceholder,
}

impl ClientRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        round_id: impl Into<String>,
        client_id: ClientId,
        masked_update: ScalarVector,
        commitments: PointVector,
        submitted_tag: MaskTag,
        aux: ClientAux,
        submission_proof: SubmitProof,
        data_proof: ProofPlaceholder,
    ) -> Result<Self> {
        let dim = masked_update.len();
        ensure_same_len("record commitments", dim, commitments.len())?;
        ensure_same_len("record submit proof A_u", dim, submission_proof.a_u.len())?;
        ensure_same_len("record submit proof A_C", dim, submission_proof.a_c.len())?;
        ensure_same_len("record submit proof z_x", dim, submission_proof.z_x.len())?;
        ensure_same_len(
            "record submit proof z_rho",
            dim,
            submission_proof.z_rho.len(),
        )?;
        ensure_same_len("record submit proof z_s", dim, submission_proof.z_s.len())?;

        Ok(Self {
            round_id: round_id.into(),
            client_id,
            masked_update,
            commitments,
            submitted_tag,
            aux,
            submission_proof,
            data_proof,
        })
    }

    pub fn dim(&self) -> usize {
        self.masked_update.len()
    }

    /// Deterministic byte encoding for hashing transcript leaves.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len_prefixed(&mut out, self.round_id.as_bytes());
        out.extend_from_slice(&self.client_id.to_le_bytes());
        push_scalar_vector(&mut out, &self.masked_update);
        push_point_vector(&mut out, &self.commitments);
        push_point(&mut out, &self.submitted_tag);
        push_point(&mut out, &self.aux.self_tag);
        out.extend_from_slice(&(self.aux.pair_tags.len() as u64).to_le_bytes());
        for (peer, tag) in &self.aux.pair_tags {
            out.extend_from_slice(&peer.to_le_bytes());
            push_point(&mut out, tag);
        }
        self.submission_proof.write_canonical_bytes(&mut out);
        push_len_prefixed(&mut out, self.data_proof.label.as_bytes());
        out
    }

    pub fn hash_bytes(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
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
