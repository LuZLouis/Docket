use super::{crypto::*, hash, parse, require, wire, Hash, Result};
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub type Kem = X25519HkdfSha256;
pub type PrivateKey = <Kem as KemTrait>::PrivateKey;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Config {
    pub round: String,
    pub n: usize,
    pub m: usize,
    pub t: usize,
    pub f_r: usize,
    pub f_c: usize,
    pub unavailable: usize,
    pub dim: usize,
    pub profile: Profile,
    pub bound: u64,
    pub norm: Option<u64>,
    pub receipt_cutoff: u64,
    pub appeal_cutoff: u64,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.round.is_empty() && self.n >= self.f_c + 2 && self.dim > 0 && self.m > 0,
            "configuration dimensions/honest participants",
        )?;
        require(
            self.f_r < self.t && self.t <= self.m && 2 * self.t > self.m + self.f_r,
            "threshold security",
        )?;
        require(
            self.f_r + self.unavailable <= self.m && self.t <= self.m - self.f_r - self.unavailable,
            "threshold progress",
        )?;
        // Conservative host/resource domain also implies both paper field no-wrap inequalities.
        require(
            self.n <= 200
                && self.m <= 200
                && self.dim <= 818000
                && self.bound <= 1_000_000
                && self.bound > 0,
            "supported integer/resource bounds",
        )?;
        require(
            self.norm
                .map(|n| n > 0 && n <= 1_000_000_000_000_000)
                .unwrap_or(true),
            "norm bound",
        )?;
        require(self.receipt_cutoff < self.appeal_cutoff, "cutoff order")
    }
    pub fn secret_dim(&self) -> usize {
        if self.profile == Profile::Native {
            1
        } else {
            self.dim
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Descriptor {
    pub config: Config,
    pub clients: Vec<[u8; 32]>,
    pub holders: Vec<[u8; 32]>,
    pub encryption: Vec<Vec<u8>>,
    pub server: [u8; 32],
    pub log: [u8; 32],
    pub parameter_version: String,
}
impl Descriptor {
    pub fn ctx(&self) -> Hash {
        hash(self)
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.clients.len() == self.config.n
                && self.holders.len() == self.config.m
                && self.encryption.len() == self.config.m,
            "key dimensions",
        )?;
        require(
            self.parameter_version == "ristretto-sha512-bp5-ed25519-hpke11-v1",
            "parameter version",
        )?;
        let keys: BTreeSet<_> = self
            .clients
            .iter()
            .chain(&self.holders)
            .chain([&self.server, &self.log])
            .collect();
        require(
            keys.len() == self.clients.len() + self.holders.len() + 2,
            "duplicate signing key",
        )?;
        let encryption: BTreeSet<_> = self.encryption.iter().collect();
        require(
            encryption.len() == self.config.m,
            "duplicate encryption key",
        )
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Coeff {
    pub points: Vec<Point>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Share {
    pub v: Vec<Scalar>,
    pub beta: Scalar,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PrivateShare {
    pub recipient: usize,
    pub coefficient: Hash,
    pub share: Share,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Packet {
    pub ctx: Hash,
    pub client: usize,
    pub recipient: usize,
    pub coefficient: Hash,
    pub encapsulation: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Ack {
    pub client: usize,
    pub coefficient: Hash,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Setup {
    pub coefficients: Auth<Coeff>,
    pub acknowledgments: Vec<Auth<Ack>>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Record {
    pub setup: Setup,
    pub commitments: Vec<Point>,
    pub encoding: Encoding,
    pub predicate: Predicate,
    pub link: Link,
}
pub type SignedRecord = Auth<Record>;
pub fn coeff_verify(d: &Descriptor, c: &Auth<Coeff>) -> Result<()> {
    require(c.id < d.config.n, "client identity")?;
    verify(c, d.ctx(), "coefficients", c.id, &d.clients[c.id])?;
    require(c.body.points.len() == d.config.t, "coefficient dimensions")
}
pub fn share_verify(d: &Descriptor, g: &Bases, c: &Auth<Coeff>, r: usize, s: &Share) -> Result<()> {
    require(
        r < d.config.m && s.v.len() == d.config.secret_dim(),
        "share dimensions",
    )?;
    coeff_verify(d, c)?;
    let mut pow = Scalar::ONE;
    let x = Scalar::from((r + 1) as u64);
    let rhs: Point = c
        .body
        .points
        .iter()
        .map(|p| {
            let q = p * pow;
            pow *= x;
            q
        })
        .sum();
    require(
        g.com(d.config.profile, &s.v, s.beta) == rhs,
        "share equation",
    )
}
pub fn make_setup(
    d: &Descriptor,
    g: &Bases,
    id: usize,
    v: &[Scalar],
    beta: Scalar,
    key: &SigningKey,
) -> (Auth<Coeff>, Vec<Share>) {
    let cfg = &d.config;
    let mut polys = vec![v.to_vec()];
    let mut blinds = vec![beta];
    for _ in 1..cfg.t {
        polys.push((0..cfg.secret_dim()).map(|_| random()).collect());
        blinds.push(random());
    }
    let coefficients = sign(
        d.ctx(),
        "coefficients",
        id,
        Coeff {
            points: polys
                .iter()
                .zip(&blinds)
                .map(|(v, b)| g.com(cfg.profile, v, *b))
                .collect(),
        },
        key,
    );
    let shares = (0..cfg.m)
        .map(|r| {
            let mut v = vec![Scalar::ZERO; cfg.secret_dim()];
            let mut beta = Scalar::ZERO;
            let mut pow = Scalar::ONE;
            for a in 0..cfg.t {
                for j in 0..v.len() {
                    v[j] += pow * polys[a][j];
                }
                beta += pow * blinds[a];
                pow *= Scalar::from((r + 1) as u64);
            }
            Share { v, beta }
        })
        .collect();
    (coefficients, shares)
}
fn packet_aad(ctx: Hash, client: usize, recipient: usize, coefficient: Hash) -> Vec<u8> {
    wire(&(
        "private-setup",
        ctx,
        client as u64,
        recipient as u64,
        coefficient,
    ))
}
pub fn encrypt(
    d: &Descriptor,
    c: &Auth<Coeff>,
    r: usize,
    s: Share,
    key: &SigningKey,
) -> Result<Packet> {
    let coefficient = hash(c);
    let aad = packet_aad(d.ctx(), c.id, r, coefficient);
    let plain = sign(
        d.ctx(),
        "private-share",
        c.id,
        PrivateShare {
            recipient: r,
            coefficient,
            share: s,
        },
        key,
    );
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&d.encryption[r]).map_err(|_| "HPKE key")?;
    let (enc, mut sender) =
        hpke::setup_sender::<AesGcm128, HkdfSha256, Kem, _>(&OpModeS::Base, &pk, &aad, &mut OsRng)
            .map_err(|_| "HPKE setup")?;
    let ciphertext = sender.seal(&wire(&plain), &aad).map_err(|_| "HPKE seal")?;
    Ok(Packet {
        ctx: d.ctx(),
        client: c.id,
        recipient: r,
        coefficient,
        encapsulation: enc.to_bytes().to_vec(),
        ciphertext,
    })
}
pub fn decrypt(
    d: &Descriptor,
    g: &Bases,
    c: &Auth<Coeff>,
    r: usize,
    p: &Packet,
    key: &PrivateKey,
) -> Result<Share> {
    require(
        p.ctx == d.ctx() && p.client == c.id && p.recipient == r && p.coefficient == hash(c),
        "packet context",
    )?;
    let aad = packet_aad(p.ctx, p.client, r, p.coefficient);
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&p.encapsulation)
        .map_err(|_| "HPKE encapsulation")?;
    let mut receiver =
        hpke::setup_receiver::<AesGcm128, HkdfSha256, Kem>(&OpModeR::Base, key, &enc, &aad)
            .map_err(|_| "HPKE receiver")?;
    let plain = receiver
        .open(&p.ciphertext, &aad)
        .map_err(|_| "HPKE authentication")?;
    let s: Auth<PrivateShare> = parse(&plain)?;
    verify(&s, d.ctx(), "private-share", c.id, &d.clients[c.id])?;
    require(
        s.body.recipient == r && s.body.coefficient == hash(c),
        "private share binding",
    )?;
    share_verify(d, g, c, r, &s.body.share)?;
    Ok(s.body.share)
}
pub fn setup_verify(d: &Descriptor, s: &Setup, id: usize) -> Result<()> {
    require(s.coefficients.id == id, "setup owner")?;
    coeff_verify(d, &s.coefficients)?;
    require(
        s.acknowledgments.len() == d.config.m,
        "all holders must acknowledge",
    )?;
    for (r, a) in s.acknowledgments.iter().enumerate() {
        verify(a, d.ctx(), "ack", r, &d.holders[r])?;
        require(
            a.body.client == id && a.body.coefficient == hash(&s.coefficients),
            "ack binding",
        )?;
    }
    Ok(())
}
pub fn record_verify(d: &Descriptor, g: &Bases, r: &SignedRecord) -> Result<()> {
    require(r.id < d.config.n, "record identity")?;
    verify(r, d.ctx(), "record", r.id, &d.clients[r.id])?;
    let b = &r.body;
    setup_verify(d, &b.setup, r.id)?;
    predicate_verify(
        d.ctx(),
        r.id,
        &b.commitments,
        &b.predicate,
        d.config.bound,
        d.config.norm,
        g,
    )?;
    link_verify(
        &Statement {
            ctx: d.ctx(),
            id: r.id,
            profile: d.config.profile,
            c: &b.commitments,
            enc: &b.encoding,
            d: b.setup.coefficients.body.points[0],
            meta: hash(&b.setup),
        },
        &b.predicate,
        &b.link,
        g,
    )
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Receipt {
    pub client: usize,
    pub record: Hash,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Decision {
    pub client: usize,
    pub record: Option<Hash>,
    pub status: String,
    pub reason: String,
    pub evidence: Hash,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Map {
    pub slots: Vec<Option<Hash>>,
    pub root: Hash,
}
pub fn merkle(ctx: Hash, slots: &[Option<Hash>]) -> Hash {
    let mut level: Vec<_> = slots
        .iter()
        .enumerate()
        .map(|(i, v)| hash(&("leaf", ctx, i as u64, v)))
        .collect();
    let n = level.len().next_power_of_two();
    for i in level.len()..n {
        level.push(hash(&("padding", ctx, i as u64)));
    }
    let mut depth = 0u64;
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| hash(&("node", ctx, depth, p[0], p[1])))
            .collect();
        depth += 1;
    }
    level[0]
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct MapWitness {
    pub slot: Option<Hash>,
    pub siblings: Vec<Hash>,
}
pub fn map_witness(ctx: Hash, slots: &[Option<Hash>], id: usize) -> MapWitness {
    let mut level: Vec<_> = slots
        .iter()
        .enumerate()
        .map(|(i, v)| hash(&("leaf", ctx, i as u64, v)))
        .collect();
    let n = level.len().next_power_of_two();
    for i in level.len()..n {
        level.push(hash(&("padding", ctx, i as u64)));
    }
    let mut index = id;
    let mut siblings = Vec::new();
    let mut depth = 0u64;
    while level.len() > 1 {
        siblings.push(level[index ^ 1]);
        level = level
            .chunks(2)
            .map(|p| hash(&("node", ctx, depth, p[0], p[1])))
            .collect();
        index >>= 1;
        depth += 1;
    }
    MapWitness {
        slot: slots[id],
        siblings,
    }
}
pub fn witness_verify(ctx: Hash, root: Hash, n: usize, id: usize, w: &MapWitness) -> Result<()> {
    require(
        id < n && w.siblings.len() == n.next_power_of_two().trailing_zeros() as usize,
        "map path dimensions",
    )?;
    let mut p = hash(&("leaf", ctx, id as u64, &w.slot));
    let mut index = id;
    for (depth, sibling) in w.siblings.iter().enumerate() {
        p = if index & 1 == 0 {
            hash(&("node", ctx, depth as u64, p, *sibling))
        } else {
            hash(&("node", ctx, depth as u64, *sibling, p))
        };
        index >>= 1;
    }
    require(p == root, "map witness root")
}
pub fn map_make(d: &Descriptor, slots: Vec<Option<Hash>>, key: &SigningKey) -> Auth<Map> {
    let root = merkle(d.ctx(), &slots);
    sign(d.ctx(), "map", 0, Map { slots, root }, key)
}
pub fn map_verify(d: &Descriptor, m: &Auth<Map>) -> Result<()> {
    verify(m, d.ctx(), "map", 0, &d.server)?;
    require(m.body.slots.len() == d.config.n, "map dimensions")?;
    require(m.body.root == merkle(d.ctx(), &m.body.slots), "map root")
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Appeal {
    pub record: SignedRecord,
    pub receipt: Auth<Receipt>,
    pub proposed_map: Auth<Map>,
    pub witness: MapWitness,
    pub decision: Auth<Decision>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Event {
    Receipt(Auth<Receipt>),
    Appeal(Box<Auth<Appeal>>),
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Entry {
    pub tick: u64,
    pub event: Event,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Checkpoint {
    pub cutoff: u64,
    pub length: usize,
    pub root: Hash,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Log {
    pub entries: Vec<Entry>,
    pub receipt: Auth<Checkpoint>,
    pub appeal: Auth<Checkpoint>,
}
// Obtained directly from the assumed common log, never accepted from the server's transcript.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Trust {
    pub descriptor: Auth<Descriptor>,
    pub receipt_checkpoint: Hash,
    pub appeal_checkpoint: Hash,
}
pub fn checkpoint(
    d: &Descriptor,
    entries: &[Entry],
    cutoff: u64,
    key: &SigningKey,
) -> Auth<Checkpoint> {
    sign(
        d.ctx(),
        "checkpoint",
        0,
        Checkpoint {
            cutoff,
            length: entries.len(),
            root: hash(&("prefix", d.ctx(), entries)),
        },
        key,
    )
}
pub fn log_verify(d: &Descriptor, l: &Log, trust: &Trust) -> Result<Vec<Auth<Receipt>>> {
    verify(&trust.descriptor, d.ctx(), "descriptor", 0, &d.server)?;
    require(trust.descriptor.body == *d, "descriptor binding")?;
    require(
        hash(&l.receipt) == trust.receipt_checkpoint && hash(&l.appeal) == trust.appeal_checkpoint,
        "common checkpoint mismatch",
    )?;
    let mut prev = 0;
    for e in &l.entries {
        require(
            e.tick > prev && e.tick <= d.config.appeal_cutoff,
            "log timing/order",
        )?;
        prev = e.tick;
    }
    let k = l
        .entries
        .iter()
        .take_while(|e| e.tick <= d.config.receipt_cutoff)
        .count();
    for (cp, cutoff, prefix) in [
        (&l.receipt, d.config.receipt_cutoff, &l.entries[..k]),
        (&l.appeal, d.config.appeal_cutoff, l.entries.as_slice()),
    ] {
        verify(cp, d.ctx(), "checkpoint", 0, &d.log)?;
        require(
            cp.body.cutoff == cutoff
                && cp.body.length == prefix.len()
                && cp.body.root == hash(&("prefix", d.ctx(), prefix)),
            "checkpoint prefix",
        )?;
    }
    let mut receipts = Vec::new();
    let mut ids = BTreeMap::new();
    for e in &l.entries[..k] {
        if let Event::Receipt(r) = &e.event {
            require(r.body.client < d.config.n, "receipt client")?;
            verify(r, d.ctx(), "receipt", 0, &d.server)?;
            if let Some(old) = ids.insert(r.body.client, r.body.record) {
                require(old == r.body.record, "conflicting receipted records: abort")?;
            } else {
                receipts.push(r.clone());
            }
        } else {
            return Err("appeal in receipt phase".into());
        }
    }
    require(
        l.entries[k..]
            .iter()
            .all(|e| matches!(e.event, Event::Appeal(_))),
        "receipt after closed prefix",
    )?;
    Ok(receipts)
}
pub fn appeal_verify(
    d: &Descriptor,
    g: &Bases,
    a: &Auth<Appeal>,
    receipts: &[Auth<Receipt>],
) -> Result<String> {
    require(a.id < d.config.n, "appeal client")?;
    verify(a, d.ctx(), "appeal", a.id, &d.clients[a.id])?;
    let b = &a.body;
    require(
        b.record.id == a.id && b.receipt.body.client == a.id,
        "appeal identity",
    )?;
    verify(&b.receipt, d.ctx(), "receipt", 0, &d.server)?;
    require(
        receipts.contains(&b.receipt) && b.receipt.body.record == hash(&b.record),
        "appeal timeliness/digest",
    )?;
    map_verify(d, &b.proposed_map)?;
    witness_verify(
        d.ctx(),
        b.proposed_map.body.root,
        d.config.n,
        a.id,
        &b.witness,
    )?;
    require(
        b.witness.slot == b.proposed_map.body.slots[a.id],
        "map witness slot",
    )?;
    verify(&b.decision, d.ctx(), "decision", 0, &d.server)?;
    require(
        b.decision.body.client == a.id && b.decision.body.evidence == hash(&b.record),
        "appeal decision evidence",
    )?;
    // Resolving admission requires the complete proof replay, including omission appeals.
    record_verify(d, g, &b.record)?;
    if b.proposed_map.body.slots[a.id] != Some(hash(&b.record)) {
        Ok("serverFault(omission)".into())
    } else if b.decision.body.status != "accept" {
        Ok("serverFault(falseReject)".into())
    } else {
        Err("unsupported appeal".into())
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Finalization {
    pub map: Auth<Map>,
    pub admitted: Vec<usize>,
    pub decisions: Hash,
    pub appeals: Hash,
    pub checkpoint: Hash,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Public {
    pub records: Vec<SignedRecord>,
    pub log: Log,
    pub decisions: Vec<Auth<Decision>>,
    pub finalization: Finalization,
    pub endorsements: Vec<Auth<Hash>>,
}
pub fn policy_verify(d: &Descriptor, g: &Bases, p: &Public, trust: &Trust) -> Result<()> {
    d.validate()?;
    let receipts = log_verify(d, &p.log, trust)?;
    map_verify(d, &p.finalization.map)?;
    let mut records = BTreeMap::new();
    for r in &p.records {
        require(
            r.id < d.config.n && records.insert(r.id, r).is_none(),
            "duplicate/conflicting records",
        )?;
    }
    let mut slots = vec![None; d.config.n];
    let mut admitted = Vec::new();
    let mut expected = Vec::new();
    for id in 0..d.config.n {
        let receipt = receipts.iter().find(|r| r.body.client == id);
        let (record, status, reason, evidence) = if let Some(receipt) = receipt {
            let r = records.get(&id).ok_or("record unavailable")?;
            require(hash(*r) == receipt.body.record, "replacement record")?;
            slots[id] = Some(receipt.body.record);
            match record_verify(d, g, r) {
                Ok(()) => {
                    admitted.push(id);
                    (
                        Some(receipt.body.record),
                        "accept".into(),
                        String::new(),
                        receipt.body.record,
                    )
                }
                Err(e) => (
                    Some(receipt.body.record),
                    "invalid".into(),
                    e,
                    receipt.body.record,
                ),
            }
        } else {
            (None, "absent".into(), "no timely receipt".into(), [0; 32])
        };
        expected.push(Decision {
            client: id,
            record,
            status,
            reason,
            evidence,
        });
    }
    require(p.decisions.len() == d.config.n, "decision availability")?;
    for (a, e) in p.decisions.iter().zip(expected) {
        verify(a, d.ctx(), "decision", 0, &d.server)?;
        require(a.body == e, "decision policy")?;
    }
    for e in &p.log.entries {
        if let Event::Appeal(a) = &e.event {
            appeal_verify(d, g, a, &receipts)?;
        }
    }
    let f = &p.finalization;
    require(
        f.map.body.slots == slots && f.admitted == admitted && admitted.len() >= d.config.f_c + 2,
        "finalized admission policy",
    )?;
    require(
        f.decisions == hash(&p.decisions)
            && f.appeals == hash(&p.log.entries)
            && f.checkpoint == hash(&p.log.appeal),
        "finalization references",
    )
}
pub fn final_verify(d: &Descriptor, g: &Bases, p: &Public, trust: &Trust) -> Result<()> {
    policy_verify(d, g, p, trust)?;
    require(
        p.endorsements.len() >= d.config.t,
        "insufficient endorsements",
    )?;
    let mut ids = BTreeSet::new();
    for e in &p.endorsements {
        require(e.id < d.config.m && ids.insert(e.id), "duplicate endorser")?;
        verify(e, d.ctx(), "endorsement", e.id, &d.holders[e.id])?;
        require(e.body == hash(&p.finalization), "endorsement digest")?;
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Request {
    pub kappa: Hash,
    pub operation: String,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Release {
    pub kappa: Hash,
    pub operation: String,
    pub share: Share,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct State {
    ctx: Hash,
    kappa: Hash,
    endorsement: Auth<Hash>,
    release: Option<Auth<Release>>,
}
pub struct Holder {
    pub id: usize,
    pub signing: SigningKey,
    pub encryption: PrivateKey,
    pub shares: BTreeMap<usize, (Hash, Share)>,
    pub directory: PathBuf,
}
impl Holder {
    pub fn receive(
        &mut self,
        d: &Descriptor,
        g: &Bases,
        c: &Auth<Coeff>,
        packet: &Packet,
    ) -> Result<Auth<Ack>> {
        let s = decrypt(d, g, c, self.id, packet, &self.encryption)?;
        let digest = hash(c);
        if let Some((old, _)) = self.shares.get(&c.id) {
            require(*old == digest, "conflicting setup")?;
        }
        self.shares.insert(c.id, (digest, s));
        Ok(sign(
            d.ctx(),
            "ack",
            self.id,
            Ack {
                client: c.id,
                coefficient: digest,
            },
            &self.signing,
        ))
    }
    fn local_check(&self, d: &Descriptor, g: &Bases, p: &Public) -> Result<()> {
        for id in &p.finalization.admitted {
            let r = p
                .records
                .iter()
                .find(|r| r.id == *id)
                .ok_or("local record missing")?;
            let (digest, s) = self.shares.get(id).ok_or("local share missing")?;
            require(
                *digest == hash(&r.body.setup.coefficients),
                "local coefficient substitution",
            )?;
            share_verify(d, g, &r.body.setup.coefficients, self.id, s)?;
        }
        Ok(())
    }
    fn with_state<T>(
        &self,
        ctx: Hash,
        f: impl FnOnce(Option<State>) -> Result<(State, T)>,
    ) -> Result<T> {
        fs::create_dir_all(&self.directory).map_err(|e| e.to_string())?;
        let name = ctx.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.directory.join(format!("{name}.lock")))
            .map_err(|e| e.to_string())?;
        lock.lock_exclusive().map_err(|e| e.to_string())?;
        let path = self.directory.join(format!("{name}.state"));
        let old = if path.exists() {
            Some(parse(&fs::read(&path).map_err(|e| e.to_string())?)?)
        } else {
            None
        };
        let (new, result) = f(old)?;
        // Never truncate a committed choice. Choice and cached message are separate immutable files.
        let encoded = wire(&new);
        if !path.exists() {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(&encoded)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
        if let Some(release) = &new.release {
            let cache = self.directory.join(format!("{name}.release"));
            if cache.exists() {
                let old: Auth<Release> = parse(&fs::read(cache).map_err(|e| e.to_string())?)?;
                require(old == *release, "persistent release conflict")?;
            } else {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(cache)
                    .map_err(|e| e.to_string())?;
                file.write_all(&wire(release))
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
            }
        }
        FileExt::unlock(&lock).map_err(|e| e.to_string())?;
        Ok(result)
    }
    pub fn endorse(
        &self,
        d: &Descriptor,
        g: &Bases,
        p: &Public,
        trust: &Trust,
    ) -> Result<Auth<Hash>> {
        policy_verify(d, g, p, trust)?;
        self.local_check(d, g, p)?;
        let kappa = hash(&p.finalization);
        self.with_state(d.ctx(), |old| {
            let s = if let Some(s) = old {
                require(
                    s.ctx == d.ctx() && s.kappa == kappa,
                    "persistent finalization conflict",
                )?;
                s
            } else {
                State {
                    ctx: d.ctx(),
                    kappa,
                    endorsement: sign(d.ctx(), "endorsement", self.id, kappa, &self.signing),
                    release: None,
                }
            };
            let out = s.endorsement.clone();
            Ok((s, out))
        })
    }
    pub fn release(
        &self,
        d: &Descriptor,
        g: &Bases,
        p: &Public,
        trust: &Trust,
        request: &Auth<Request>,
    ) -> Result<Auth<Release>> {
        verify(request, d.ctx(), "request", 0, &d.server)?;
        let kappa = hash(&p.finalization);
        require(
            request.body
                == Request {
                    kappa,
                    operation: "aggregate".into(),
                },
            "unauthorized release request",
        )?;
        final_verify(d, g, p, trust)?;
        self.local_check(d, g, p)?;
        self.with_state(d.ctx(), |old| {
            let mut s = old.ok_or("release before local authorization")?;
            require(
                s.ctx == d.ctx() && s.kappa == kappa,
                "persistent finalization conflict",
            )?;
            let mut sum = Share {
                v: vec![Scalar::ZERO; d.config.secret_dim()],
                beta: Scalar::ZERO,
            };
            for id in &p.finalization.admitted {
                let share = &self.shares[id].1;
                for (a, b) in sum.v.iter_mut().zip(&share.v) {
                    *a += b;
                }
                sum.beta += share.beta;
            }
            let out = sign(
                d.ctx(),
                "release",
                self.id,
                Release {
                    kappa,
                    operation: "aggregate".into(),
                    share: sum,
                },
                &self.signing,
            );
            release_verify(d, g, p, &out)?;
            s.release = Some(out.clone());
            Ok((s, out))
        })
    }
}
pub fn release_verify(d: &Descriptor, g: &Bases, p: &Public, r: &Auth<Release>) -> Result<()> {
    require(r.id < d.config.m, "release holder")?;
    verify(r, d.ctx(), "release", r.id, &d.holders[r.id])?;
    require(
        r.body.kappa == hash(&p.finalization)
            && r.body.operation == "aggregate"
            && r.body.share.v.len() == d.config.secret_dim(),
        "release binding",
    )?;
    let mut coeff = vec![Point::default(); d.config.t];
    for id in &p.finalization.admitted {
        let rec = p
            .records
            .iter()
            .find(|r| r.id == *id)
            .ok_or("release record")?;
        require(
            rec.body.setup.coefficients.body.points.len() == d.config.t,
            "release coefficients",
        )?;
        for (a, b) in coeff
            .iter_mut()
            .zip(&rec.body.setup.coefficients.body.points)
        {
            *a += b;
        }
    }
    let mut pow = Scalar::ONE;
    let rhs: Point = coeff
        .iter()
        .map(|v| {
            let a = v * pow;
            pow *= Scalar::from((r.id + 1) as u64);
            a
        })
        .sum();
    require(
        g.com(d.config.profile, &r.body.share.v, r.body.share.beta) == rhs,
        "signed aggregate share equation",
    )
}
pub fn reconstruct(
    d: &Descriptor,
    g: &Bases,
    p: &Public,
    shares: &[Auth<Release>],
) -> Result<Share> {
    require(shares.len() == d.config.t, "reconstruction threshold")?;
    let mut ids = BTreeSet::new();
    for s in shares {
        require(ids.insert(s.id), "duplicate holder")?;
        release_verify(d, g, p, s)?;
    }
    let mut sum = Share {
        v: vec![Scalar::ZERO; d.config.secret_dim()],
        beta: Scalar::ZERO,
    };
    for r in shares {
        let x = Scalar::from((r.id + 1) as u64);
        let mut lambda = Scalar::ONE;
        for u in shares {
            if r.id != u.id {
                let y = Scalar::from((u.id + 1) as u64);
                lambda *= -y * (x - y).invert();
            }
        }
        for (a, b) in sum.v.iter_mut().zip(&r.body.share.v) {
            *a += lambda * b;
        }
        sum.beta += lambda * r.body.share.beta;
    }
    let commitment: Point = p
        .finalization
        .admitted
        .iter()
        .map(|id| {
            p.records
                .iter()
                .find(|r| r.id == *id)
                .unwrap()
                .body
                .setup
                .coefficients
                .body
                .points[0]
        })
        .sum();
    require(
        g.com(d.config.profile, &sum.v, sum.beta) == commitment,
        "aggregate commitment",
    )?;
    Ok(sum)
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct MaskCertificate {
    pub kappa: Hash,
    pub records: Vec<Hash>,
    pub releases: Vec<Auth<Release>>,
    pub opening: Share,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Output {
    pub kappa: Hash,
    pub mask: Hash,
    pub decisions: Hash,
    pub values: Vec<i64>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AuditBundle {
    pub public: Public,
    pub request: Auth<Request>,
    pub mask: Auth<MaskCertificate>,
    pub output: Auth<Output>,
}
pub fn aggregate(d: &Descriptor, g: &Bases, p: &Public, s: &Share) -> Result<Vec<i64>> {
    let bound = (p.finalization.admitted.len() as u64 * d.config.bound) as i64;
    match d.config.profile {
        Profile::Native => {
            let mut points = vec![Point::default(); d.config.dim];
            for id in &p.finalization.admitted {
                let r = p
                    .records
                    .iter()
                    .find(|r| r.id == *id)
                    .ok_or("aggregate record")?;
                if let Encoding::Native { y, .. } = &r.body.encoding {
                    require(y.len() == points.len(), "encoding length")?;
                    for (a, b) in points.iter_mut().zip(y) {
                        *a += b;
                    }
                } else {
                    return Err("aggregate profile".into());
                }
            }
            for (p, h) in points.iter_mut().zip(&g.hs) {
                *p -= h * s.v[0];
            }
            decode(&points, bound, g.g)
        }
        Profile::Additive => {
            let mut values = vec![Scalar::ZERO; d.config.dim];
            for id in &p.finalization.admitted {
                let r = p
                    .records
                    .iter()
                    .find(|r| r.id == *id)
                    .ok_or("aggregate record")?;
                if let Encoding::Additive(u) = &r.body.encoding {
                    require(u.len() == values.len(), "encoding length")?;
                    for (a, b) in values.iter_mut().zip(u) {
                        *a += b;
                    }
                } else {
                    return Err("aggregate profile".into());
                }
            }
            values
                .iter()
                .zip(&s.v)
                .map(|(u, s)| {
                    let x = u - s;
                    let b = x.to_bytes();
                    let pos = u64::from_le_bytes(b[..8].try_into().unwrap());
                    if b[8..].iter().all(|b| *b == 0) && pos <= bound as u64 {
                        return Ok(pos as i64);
                    }
                    let b = (-x).to_bytes();
                    let neg = u64::from_le_bytes(b[..8].try_into().unwrap());
                    require(
                        b[8..].iter().all(|b| *b == 0) && neg <= bound as u64,
                        "additive integer interval",
                    )?;
                    Ok(-(neg as i64))
                })
                .collect()
        }
    }
}
// The independent auditor takes only authenticated public materials, never Holder or client state.
pub fn audit(trust: &Trust, bundle: &AuditBundle) -> Result<()> {
    let d = &trust.descriptor.body;
    d.validate()?;
    let g = Bases::new(d.config.dim);
    let p = &bundle.public;
    final_verify(d, &g, p, trust)?;
    verify(&bundle.request, d.ctx(), "request", 0, &d.server)?;
    require(
        bundle.request.body
            == Request {
                kappa: hash(&p.finalization),
                operation: "aggregate".into(),
            },
        "certificate request",
    )?;
    verify(&bundle.mask, d.ctx(), "mask-certificate", 0, &d.server)?;
    let m = &bundle.mask.body;
    let records: Vec<_> = p
        .finalization
        .admitted
        .iter()
        .map(|id| hash(p.records.iter().find(|r| r.id == *id).unwrap()))
        .collect();
    require(
        m.kappa == hash(&p.finalization) && m.records == records,
        "mask references",
    )?;
    let s = reconstruct(d, &g, p, &m.releases)?;
    require(m.opening == s, "mask interpolation")?;
    verify(&bundle.output, d.ctx(), "output", 0, &d.server)?;
    let o = &bundle.output.body;
    require(
        o.kappa == m.kappa
            && o.mask == hash(&bundle.mask)
            && o.decisions == hash(&p.decisions)
            && o.values.len() == d.config.dim,
        "output references",
    )?;
    let bound = (p.finalization.admitted.len() as u64 * d.config.bound) as i64;
    require(
        o.values.iter().all(|v| v.unsigned_abs() <= bound as u64),
        "output interval",
    )?;
    match d.config.profile {
        Profile::Native => {
            let mut k = Point::default();
            let mut ys = vec![Point::default(); d.config.dim];
            for id in &p.finalization.admitted {
                let r = p.records.iter().find(|r| r.id == *id).unwrap();
                if let Encoding::Native { k: ki, y } = &r.body.encoding {
                    k += ki;
                    for (a, b) in ys.iter_mut().zip(y) {
                        *a += b;
                    }
                } else {
                    return Err("output profile".into());
                }
            }
            require(k == g.g * s.v[0], "aggregate K")?;
            for j in 0..ys.len() {
                require(
                    ys[j] == g.g * signed(o.values[j]) + g.hs[j] * s.v[0],
                    "aggregate output equation",
                )?;
            }
            Ok(())
        }
        Profile::Additive => require(
            o.values == aggregate(d, &g, p, &s)?,
            "aggregate output equation",
        ),
    }
}
pub fn save_public(path: &Path, trust: &Trust, bundle: &AuditBundle) -> Result<()> {
    fs::write(path, wire(&(trust, bundle))).map_err(|e| e.to_string())?;
    let ctx = trust.descriptor.body.ctx();
    let anchor = ctx.iter().map(|b| format!("{b:02x}")).collect::<String>();
    fs::write(path.with_file_name("trusted-context.txt"), anchor).map_err(|e| e.to_string())
}
