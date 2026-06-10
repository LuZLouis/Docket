use crate::record::ClientRecord;
use crate::{AvsaError, ClientId, Result};
use sha2::{Digest, Sha256};

/// Canonical digest of one AVSA client record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordDigest(pub [u8; 32]);

/// Backward-compatible alias for the Round 1 name.
pub type RecordHash = RecordDigest;

/// Deterministic Round 1 transcript root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TranscriptRoot(pub [u8; 32]);

/// Leaf material committed by the simple hash-list transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptLeaf {
    pub round_id: String,
    pub client_id: ClientId,
    pub hash: RecordDigest,
}

/// Placeholder membership proof. It deliberately stores the full leaf list so
/// the interface can later be replaced by a real Merkle proof without changing
/// callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub client_id: ClientId,
    pub index: usize,
    pub leaf_hash: RecordHash,
    pub all_leaves: Vec<TranscriptLeaf>,
}

/// Deterministic non-inclusion witness for the enumerated digest log.
///
/// This skeleton intentionally carries only public digest-log leaves. It does
/// not carry or require the omitted record body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    pub client_id: ClientId,
    pub digest: RecordDigest,
    pub all_leaves: Vec<TranscriptLeaf>,
}

/// Deterministic hash-list transcript skeleton.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub root: TranscriptRoot,
    pub leaves: Vec<TranscriptLeaf>,
}

impl Transcript {
    /// Build a deterministic root by sorting records by client id.
    pub fn from_records(records: &[ClientRecord]) -> Result<Self> {
        if records.is_empty() {
            return Err(AvsaError::EmptyInput("client records"));
        }
        let mut leaves: Vec<_> = records
            .iter()
            .map(|record| TranscriptLeaf {
                round_id: record.round_id.clone(),
                client_id: record.client_id,
                hash: record_digest(record),
            })
            .collect();
        leaves.sort_by_key(|leaf| leaf.client_id);
        for window in leaves.windows(2) {
            if window[0].client_id == window[1].client_id {
                return Err(AvsaError::DuplicateTranscriptRecord(window[0].client_id));
            }
        }
        let root = compute_root(&leaves);
        Ok(Self { root, leaves })
    }

    pub fn proof_for_client(&self, client_id: ClientId) -> Option<MembershipProof> {
        self.leaves
            .iter()
            .position(|leaf| leaf.client_id == client_id)
            .map(|index| MembershipProof {
                client_id,
                index,
                leaf_hash: self.leaves[index].hash,
                all_leaves: self.leaves.clone(),
            })
    }

    pub fn non_membership_proof(
        &self,
        client_id: ClientId,
        digest: RecordDigest,
    ) -> Option<NonMembershipProof> {
        if self
            .leaves
            .iter()
            .any(|leaf| leaf.client_id == client_id || leaf.hash == digest)
        {
            None
        } else {
            Some(NonMembershipProof {
                client_id,
                digest,
                all_leaves: self.leaves.clone(),
            })
        }
    }

    pub fn verify_membership(root: TranscriptRoot, proof: &MembershipProof) -> Result<bool> {
        match verify_record_membership(
            &root,
            proof
                .all_leaves
                .get(proof.index)
                .map(|leaf| leaf.round_id.as_str())
                .unwrap_or_default(),
            proof.client_id,
            &proof.leaf_hash,
            proof,
        ) {
            Ok(()) => Ok(true),
            Err(AvsaError::InvalidMembershipProof)
            | Err(AvsaError::InvalidTranscriptRoot)
            | Err(AvsaError::InvalidRecordDigest) => Ok(false),
            Err(err) => Err(err),
        }
    }
}

pub fn build_transcript_tree(records: &[ClientRecord]) -> Result<Transcript> {
    Transcript::from_records(records)
}

pub fn hash_client_record(record: &ClientRecord) -> RecordDigest {
    record_digest(record)
}

pub fn record_digest(record: &ClientRecord) -> RecordDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"AVSA:record:v1");
    push_len_prefixed(&mut hasher, record.round_id.as_bytes());
    hasher.update(record.client_id.to_le_bytes());
    hasher.update((record.dim() as u64).to_le_bytes());
    push_selected_set_from_record(&mut hasher, record);
    push_len_prefixed(&mut hasher, &record.canonical_bytes());
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    RecordDigest(out)
}

pub fn verify_record_membership(
    root: &TranscriptRoot,
    round_id: &str,
    client_id: ClientId,
    record_digest: &RecordDigest,
    proof: &MembershipProof,
) -> Result<()> {
    if proof.client_id != client_id || &proof.leaf_hash != record_digest {
        return Err(AvsaError::InvalidMembershipProof);
    }
    let leaf = proof
        .all_leaves
        .get(proof.index)
        .ok_or(AvsaError::InvalidMembershipProof)?;
    if leaf.round_id != round_id || leaf.client_id != client_id || &leaf.hash != record_digest {
        return Err(AvsaError::InvalidMembershipProof);
    }
    let computed = compute_root(&proof.all_leaves);
    if &computed != root {
        return Err(AvsaError::InvalidTranscriptRoot);
    }
    Ok(())
}

pub fn verify_record_non_membership(
    root: &TranscriptRoot,
    round_id: &str,
    client_id: ClientId,
    record_digest: &RecordDigest,
    proof: &NonMembershipProof,
) -> Result<()> {
    if proof.client_id != client_id || &proof.digest != record_digest {
        return Err(AvsaError::InvalidMembershipProof);
    }
    for leaf in &proof.all_leaves {
        if leaf.round_id != round_id {
            return Err(AvsaError::InvalidMembershipProof);
        }
        if leaf.client_id == client_id || &leaf.hash == record_digest {
            return Err(AvsaError::InvalidMembershipProof);
        }
    }
    let computed = compute_root(&proof.all_leaves);
    if &computed != root {
        return Err(AvsaError::InvalidTranscriptRoot);
    }
    Ok(())
}

fn compute_root(leaves: &[TranscriptLeaf]) -> TranscriptRoot {
    let mut hasher = Sha256::new();
    hasher.update(b"AVSA:transcript-root:v1");
    hasher.update((leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        push_len_prefixed(&mut hasher, leaf.round_id.as_bytes());
        hasher.update(leaf.client_id.to_le_bytes());
        hasher.update(leaf.hash.0);
    }
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    TranscriptRoot(out)
}

fn push_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn push_selected_set_from_record(hasher: &mut Sha256, record: &ClientRecord) {
    let mut selected = Vec::with_capacity(record.aux.pair_tags.len() + 1);
    selected.push(record.client_id);
    selected.extend(record.aux.pair_tags.keys().copied());
    selected.sort_unstable();
    hasher.update((selected.len() as u64).to_le_bytes());
    for client_id in selected {
        hasher.update(client_id.to_le_bytes());
    }
}
