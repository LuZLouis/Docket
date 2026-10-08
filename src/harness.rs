//! Sequential role simulation with actual serialization at every transport boundary.
use super::{crypto::*, hash, parse, protocol::*, require, wire, Hash, Result};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Instant,
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Traffic {
    pub category: String,
    pub sender: String,
    pub recipient: String,
    pub bytes: usize,
    pub digest: Hash,
    pub public: bool,
}
#[derive(Default, Serialize, Deserialize)]
pub struct Meter {
    pub times_ms: BTreeMap<String, f64>,
    pub messages: Vec<Traffic>,
    pub objects: BTreeMap<Hash, usize>,
}
impl Meter {
    pub fn time(&mut self, role: &str, phase: &str, start: Instant) {
        *self.times_ms.entry(format!("{role}.{phase}")).or_default() +=
            start.elapsed().as_secs_f64() * 1000.;
    }
    pub fn send<T: Serialize + DeserializeOwned>(
        &mut self,
        category: &str,
        from: &str,
        to: &str,
        public: bool,
        value: &T,
    ) -> Result<T> {
        let bytes = wire(value);
        let digest = hash(&bytes);
        self.messages.push(Traffic {
            category: category.into(),
            sender: from.into(),
            recipient: to.into(),
            bytes: bytes.len(),
            digest,
            public,
        });
        if public {
            self.objects.insert(digest, bytes.len());
        }
        parse(&bytes)
    }
    pub fn transmission_bytes(&self) -> usize {
        self.messages.iter().map(|m| m.bytes).sum()
    }
    pub fn public_storage_bytes(&self) -> usize {
        self.objects.values().sum()
    }
}
pub struct Run {
    pub trust: Trust,
    pub bundle: AuditBundle,
    pub holders: Vec<Holder>,
    pub server: SigningKey,
    pub clients: Vec<SigningKey>,
    pub log_key: SigningKey,
    pub meter: Meter,
    pub oracle: Vec<i64>,
    pub total_ms: f64,
}
fn role(prefix: &str, id: usize) -> String {
    format!("{prefix}-{id}")
}
pub fn run(cfg: Config, path: &Path) -> Result<Run> {
    let total = Instant::now();
    cfg.validate()?;
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    let mut meter = Meter::default();
    let start = Instant::now();
    let server = SigningKey::generate(&mut OsRng);
    let log_key = SigningKey::generate(&mut OsRng);
    let clients: Vec<_> = (0..cfg.n)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect();
    let mut holders = Vec::new();
    let mut encryption = Vec::new();
    for r in 0..cfg.m {
        let (sk, pk) = Kem::gen_keypair(&mut OsRng);
        encryption.push(pk.to_bytes().to_vec());
        holders.push(Holder {
            id: r,
            signing: SigningKey::generate(&mut OsRng),
            encryption: sk,
            shares: BTreeMap::new(),
            directory: path.join(format!("private-holder-{r}")),
        });
    }
    let d = Descriptor {
        config: cfg.clone(),
        clients: clients
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect(),
        holders: holders
            .iter()
            .map(|h| h.signing.verifying_key().to_bytes())
            .collect(),
        encryption,
        server: server.verifying_key().to_bytes(),
        log: log_key.verifying_key().to_bytes(),
        parameter_version: "ristretto-sha512-bp5-ed25519-hpke11-v1".into(),
    };
    d.validate()?;
    let descriptor = sign(d.ctx(), "descriptor", 0, d.clone(), &server);
    let g = Bases::new(cfg.dim);
    meter.time("setup", "keys_parameters_descriptor", start);
    for i in 0..cfg.n {
        let _: Auth<Descriptor> = meter.send(
            "descriptor",
            "server",
            &role("client", i),
            true,
            &descriptor,
        )?;
    }
    for r in 0..cfg.m {
        let _: Auth<Descriptor> = meter.send(
            "descriptor",
            "server",
            &role("holder", r),
            true,
            &descriptor,
        )?;
    }
    let mut records = Vec::new();
    let mut entries = Vec::new();
    let mut oracle = vec![0; cfg.dim];
    for id in 0..cfg.n {
        let start = Instant::now();
        let x: Vec<i64> = (0..cfg.dim)
            .map(|j| ((id * 17 + j * 7) % 7) as i64 - 3)
            .collect();
        require(cfg.bound >= 3, "fixture requires B >= 3")?;
        for (a, b) in oracle.iter_mut().zip(&x) {
            *a += b;
        }
        let v: Vec<_> = (0..cfg.secret_dim()).map(|_| random()).collect();
        let beta = random();
        let rho: Vec<_> = (0..cfg.dim).map(|_| random()).collect();
        let (coeff, shares) = make_setup(&d, &g, id, &v, beta, &clients[id]);
        meter.time("client", "mask_vss", start);
        let mut acks = Vec::new();
        for r in 0..cfg.m {
            let start = Instant::now();
            let packet = encrypt(&d, &coeff, r, shares[r].clone(), &clients[id])?;
            let packet: Packet = meter.send(
                "private_hpke_share",
                &role("client", id),
                &role("holder", r),
                false,
                &packet,
            )?;
            let coeff: Auth<Coeff> = meter.send(
                "coefficients",
                &role("client", id),
                &role("holder", r),
                true,
                &coeff,
            )?;
            meter.time("client", "encrypt_sign_send", start);
            let start = Instant::now();
            let ack = holders[r].receive(&d, &g, &coeff, &packet)?;
            let ack = meter.send("ack", &role("holder", r), &role("client", id), true, &ack)?;
            acks.push(ack);
            meter.time("holder", "decrypt_share_ack", start);
        }
        let start = Instant::now();
        let setup = Setup {
            coefficients: coeff,
            acknowledgments: acks,
        };
        setup_verify(&d, &setup, id)?;
        let commitments: Vec<_> = x
            .iter()
            .zip(&rho)
            .map(|(x, r)| g.g * signed(*x) + g.h * r)
            .collect();
        let encoding = match cfg.profile {
            Profile::Native => Encoding::Native {
                k: g.g * v[0],
                y: x.iter()
                    .zip(&g.hs)
                    .map(|(x, h)| g.g * signed(*x) + h * v[0])
                    .collect(),
            },
            Profile::Additive => {
                Encoding::Additive(x.iter().zip(&v).map(|(x, s)| signed(*x) + s).collect())
            }
        };
        meter.time("client", "encoding_setup_verify", start);
        let start = Instant::now();
        let predicate =
            predicate_prove(d.ctx(), id, &x, &rho, &commitments, cfg.bound, cfg.norm, &g)?;
        meter.time("client", "predicate_prove", start);
        let start = Instant::now();
        let st = Statement {
            ctx: d.ctx(),
            id,
            profile: cfg.profile,
            c: &commitments,
            enc: &encoding,
            d: setup.coefficients.body.points[0],
            meta: hash(&setup),
        };
        let link = link_prove(&st, &predicate, &x, &rho, &v, beta, &g);
        meter.time("client", "link_prove", start);
        let start = Instant::now();
        let record = sign(
            d.ctx(),
            "record",
            id,
            Record {
                setup,
                commitments,
                encoding,
                predicate,
                link,
            },
            &clients[id],
        );
        let received = meter.send("record", &role("client", id), "server", true, &record)?;
        meter.time("client", "record_sign_send", start);
        let start = Instant::now();
        record_verify(&d, &g, &received)?;
        let receipt = sign(
            d.ctx(),
            "receipt",
            0,
            Receipt {
                client: id,
                record: hash(&received),
            },
            &server,
        );
        let client_receipt: Auth<Receipt> =
            meter.send("receipt", "server", &role("client", id), true, &receipt)?;
        verify(&client_receipt, d.ctx(), "receipt", 0, &d.server)?;
        let anchored: Auth<Receipt> =
            meter.send("receipt_anchor", "server", "log", true, &receipt)?;
        entries.push(Entry {
            tick: id as u64 + 1,
            event: Event::Receipt(anchored),
        });
        records.push(received);
        meter.time("server", "record_verify_receipt", start);
        // Publication is explicit: server uploads the complete available record once.
        let _: SignedRecord = meter.send("record_publication", "server", "log", true, &record)?;
    }
    let start = Instant::now();
    let receipt_cp = checkpoint(&d, &entries, cfg.receipt_cutoff, &log_key);
    let appeal_cp = checkpoint(&d, &entries, cfg.appeal_cutoff, &log_key);
    let trust = Trust {
        descriptor,
        receipt_checkpoint: hash(&receipt_cp),
        appeal_checkpoint: hash(&appeal_cp),
    };
    let log = Log {
        entries,
        receipt: receipt_cp,
        appeal: appeal_cp,
    };
    meter.time("log", "checkpoint", start);
    let _: Auth<Checkpoint> =
        meter.send("receipt_checkpoint", "log", "server", true, &log.receipt)?;
    let _: Auth<Checkpoint> =
        meter.send("appeal_checkpoint", "log", "server", true, &log.appeal)?;
    let start = Instant::now();
    let slots = records.iter().map(|r| Some(hash(r))).collect();
    let map = map_make(&d, slots, &server);
    let decisions: Vec<_> = records
        .iter()
        .map(|r| {
            sign(
                d.ctx(),
                "decision",
                0,
                Decision {
                    client: r.id,
                    record: Some(hash(r)),
                    status: "accept".into(),
                    reason: String::new(),
                    evidence: hash(r),
                },
                &server,
            )
        })
        .collect();
    let finalization = Finalization {
        map,
        admitted: (0..cfg.n).collect(),
        decisions: hash(&decisions),
        appeals: hash(&log.entries),
        checkpoint: hash(&log.appeal),
    };
    let mut public = Public {
        records,
        log,
        decisions,
        finalization,
        endorsements: vec![],
    };
    policy_verify(&d, &g, &public, &trust)?;
    meter.time("server", "decisions_finalization", start);
    let _: Auth<Map> = meter.send(
        "map_publication",
        "server",
        "log",
        true,
        &public.finalization.map,
    )?;
    let _: Vec<Auth<Decision>> = meter.send(
        "decisions_publication",
        "server",
        "log",
        true,
        &public.decisions,
    )?;
    let _: Finalization = meter.send(
        "finalization_publication",
        "server",
        "log",
        true,
        &public.finalization,
    )?;
    // Send each published object independently; record/setup nesting is counted as actually encoded.
    for r in 0..cfg.m {
        let start = Instant::now();
        let view = deliver_public(&mut meter, &public, &trust, &role("holder", r))?;
        let endorsement = holders[r].endorse(&d, &g, &view.0, &view.1)?;
        let endorsement = meter.send(
            "endorsement",
            &role("holder", r),
            "server",
            true,
            &endorsement,
        )?;
        public.endorsements.push(endorsement);
        meter.time("holder", "finalize_full_replay", start);
    }
    let start = Instant::now();
    let request = sign(
        d.ctx(),
        "request",
        0,
        Request {
            kappa: hash(&public.finalization),
            operation: "aggregate".into(),
        },
        &server,
    );
    meter.time("server", "request_sign", start);
    let mut releases = Vec::new();
    for r in 0..cfg.t {
        let start = Instant::now();
        let request = meter.send("request", "server", &role("holder", r), true, &request)?;
        let endorsements = meter.send(
            "endorsement_certificate",
            "server",
            &role("holder", r),
            true,
            &public.endorsements,
        )?;
        let mut view = public.clone();
        view.endorsements = endorsements;
        let release = holders[r].release(&d, &g, &view, &trust, &request)?;
        let release = meter.send(
            "aggregate_release",
            &role("holder", r),
            "server",
            true,
            &release,
        )?;
        releases.push(release);
        meter.time("holder", "release_full_replay_persist", start);
    }
    let start = Instant::now();
    final_verify(&d, &g, &public, &trust)?;
    let opening = reconstruct(&d, &g, &public, &releases)?;
    let mask = sign(
        d.ctx(),
        "mask-certificate",
        0,
        MaskCertificate {
            kappa: hash(&public.finalization),
            records: public.records.iter().map(hash).collect(),
            releases,
            opening,
        },
        &server,
    );
    meter.time("server", "reconstruct_certificate", start);
    let start = Instant::now();
    let values = aggregate(&d, &g, &public, &mask.body.opening)?;
    meter.time("server", "aggregate_decode", start);
    let start = Instant::now();
    let output = sign(
        d.ctx(),
        "output",
        0,
        Output {
            kappa: hash(&public.finalization),
            mask: hash(&mask),
            decisions: hash(&public.decisions),
            values,
        },
        &server,
    );
    meter.time("server", "output_sign", start);
    let start = Instant::now();
    let (public, trust) = deliver_public(&mut meter, &public, &trust, "auditor")?;
    let request = meter.send("request", "server", "auditor", true, &request)?;
    let mask = meter.send("mask_certificate", "server", "auditor", true, &mask)?;
    let output = meter.send("output", "server", "auditor", true, &output)?;
    let bundle = AuditBundle {
        public,
        request,
        mask,
        output,
    };
    audit(&trust, &bundle)?;
    meter.time("auditor", "complete_public_audit", start);
    require(bundle.output.body.values == oracle, "oracle mismatch")?;
    let total_ms = total.elapsed().as_secs_f64() * 1000.;
    // Regression guard: no individual holder evaluation may enter the public audit bundle.
    if cfg.n <= 8 && cfg.dim <= 64 {
        let visible = wire(&bundle);
        for holder in &holders {
            for (_, share) in holder.shares.values() {
                let private = wire(share);
                require(
                    !visible
                        .windows(private.len())
                        .any(|window| window == private),
                    "individual private share in public bundle",
                )?;
            }
        }
    }
    save_public(&path.join("public.bin"), &trust, &bundle)?;
    Ok(Run {
        trust,
        bundle,
        holders,
        server,
        clients,
        log_key,
        meter,
        oracle,
        total_ms,
    })
}
fn deliver_public(m: &mut Meter, p: &Public, t: &Trust, to: &str) -> Result<(Public, Trust)> {
    let trust = m.send("trust_checkpoints", "log", to, true, t)?;
    let records = p
        .records
        .iter()
        .map(|r| m.send("record_download", "log", to, true, r))
        .collect::<Result<Vec<_>>>()?;
    let log = m.send("log_prefix", "log", to, true, &p.log)?;
    let decisions = m.send("decisions", "server", to, true, &p.decisions)?;
    let finalization = m.send("finalization", "server", to, true, &p.finalization)?;
    let endorsements = m.send("endorsements", "server", to, true, &p.endorsements)?;
    Ok((
        Public {
            records,
            log,
            decisions,
            finalization,
            endorsements,
        },
        trust,
    ))
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Attack {
    pub name: String,
    pub expected_label: String,
    pub actual_label: String,
    pub passed: bool,
    pub detected: bool,
    pub evidence: bool,
    pub new_valid_releases: usize,
    pub time_ms: f64,
    pub bytes: usize,
    pub detail: String,
}
fn outcome(
    name: &str,
    expected: &str,
    result: Result<String>,
    start: Instant,
    evidence: bool,
    new_valid_releases: usize,
    bytes: usize,
) -> Attack {
    let (actual, detail) = match result {
        Ok(label) => (label, String::new()),
        Err(e) => ("blocked".into(), e),
    };
    Attack {
        name: name.into(),
        expected_label: expected.into(),
        passed: actual == expected && new_valid_releases == 0,
        detected: actual == "blocked" || actual.starts_with("serverFault"),
        actual_label: actual,
        evidence,
        new_valid_releases,
        time_ms: start.elapsed().as_secs_f64() * 1000.,
        bytes,
        detail,
    }
}
pub fn attacks(run: &Run) -> Result<Vec<Attack>> {
    let d = &run.trust.descriptor.body;
    let g = Bases::new(d.config.dim);
    let mut out = Vec::new();
    let p = &run.bundle.public;
    let start = Instant::now();
    out.push(outcome(
        "honest_control",
        "accepted",
        audit(&run.trust, &run.bundle).map(|_| "accepted".into()),
        start,
        false,
        0,
        wire(&run.bundle).len(),
    ));
    for name in [
        "tampered_input",
        "tampered_link",
        "tampered_range",
        "tampered_square",
        "forged_client_signature",
        "missing_holder_ack",
        "coefficient_substitution",
        "old_round_record",
    ] {
        if name == "tampered_square" && d.config.norm.is_none() {
            continue;
        }
        let start = Instant::now();
        let mut r = p.records[0].clone();
        match name {
            "tampered_input" => r.body.commitments[0] += g.g,
            "tampered_link" => r.body.link.zx[0] += Scalar::ONE,
            "tampered_range" => r.body.predicate.range[0] ^= 1,
            "tampered_square" => r.body.predicate.square.as_mut().unwrap().e[0] += g.g,
            "forged_client_signature" => r.signature[0] ^= 1,
            "missing_holder_ack" => {
                r.body.setup.acknowledgments.pop();
            }
            "coefficient_substitution" => r.body.setup.coefficients.body.points[0] += g.g,
            "old_round_record" => r.ctx[0] ^= 1,
            _ => unreachable!(),
        }
        if !["forged_client_signature", "old_round_record"].contains(&name) {
            r = sign(d.ctx(), "record", 0, r.body, &run.clients[0]);
        }
        let result = record_verify(d, &g, &r);
        let evidence = verify(&r, d.ctx(), "record", 0, &d.clients[0]).is_ok() && result.is_err();
        out.push(outcome(
            name,
            "blocked",
            result.map(|_| "accepted".into()),
            start,
            evidence,
            0,
            wire(&r).len(),
        ));
    }
    let start = Instant::now();
    let coeff = &p.records[0].body.setup.coefficients;
    let mut packet = encrypt(
        d,
        coeff,
        0,
        run.holders[0].shares[&0].1.clone(),
        &run.clients[0],
    )?;
    packet.ciphertext[0] ^= 1;
    out.push(outcome(
        "tampered_private_setup_ciphertext",
        "blocked",
        decrypt(d, &g, coeff, 0, &packet, &run.holders[0].encryption).map(|_| "accepted".into()),
        start,
        false,
        0,
        wire(&packet).len(),
    ));
    for name in [
        "early_release",
        "individual_secret",
        "arbitrary_coefficients",
        "replacement_set",
        "old_round_request",
        "wrong_kappa",
    ] {
        let start = Instant::now();
        let mut view = p.clone();
        let mut request = run.bundle.request.clone();
        match name {
            "early_release" => view.endorsements.clear(),
            "individual_secret" => request.body.operation = "client:0".into(),
            "arbitrary_coefficients" => request.body.operation = "coefficients:1,-1".into(),
            "replacement_set" => {
                view.finalization.admitted.pop();
                request.body.kappa = hash(&view.finalization);
            }
            "wrong_kappa" => request.body.kappa[0] ^= 1,
            "old_round_request" => request.ctx[0] ^= 1,
            _ => unreachable!(),
        }
        if name != "old_round_request" {
            request = sign(d.ctx(), "request", 0, request.body, &run.server);
        }
        let result = run.holders[0].release(d, &g, &view, &run.trust, &request);
        let new_valid = result
            .as_ref()
            .map(|r| {
                usize::from(
                    release_verify(d, &g, &view, r).is_ok()
                        && !run.bundle.mask.body.releases.contains(r),
                )
            })
            .unwrap_or(0);
        out.push(outcome(
            name,
            "blocked",
            result.map(|_| "released".into()),
            start,
            false,
            new_valid,
            wire(&request).len(),
        ));
    }
    for name in [
        "duplicate_holder",
        "bad_signed_share",
        "insufficient_threshold",
    ] {
        let start = Instant::now();
        let mut shares = run.bundle.mask.body.releases.clone();
        match name {
            "duplicate_holder" => shares[1] = shares[0].clone(),
            "bad_signed_share" => {
                shares[0].body.share.v[0] += Scalar::ONE;
                shares[0] = sign(
                    d.ctx(),
                    "release",
                    0,
                    shares[0].body.clone(),
                    &run.holders[0].signing,
                );
            }
            _ => {
                shares.pop();
            }
        }
        let result = reconstruct(d, &g, p, &shares);
        let evidence = name == "bad_signed_share"
            && verify(&shares[0], d.ctx(), "release", 0, &d.holders[0]).is_ok()
            && release_verify(d, &g, p, &shares[0]).is_err();
        out.push(outcome(
            name,
            "blocked",
            result.map(|_| "accepted".into()),
            start,
            evidence,
            0,
            wire(&shares).len(),
        ));
    }
    for name in [
        "tampered_output",
        "certificate_reference",
        "tampered_mask_opening",
        "truncated_checkpoint",
        "duplicate_endorser",
    ] {
        let start = Instant::now();
        let mut b = run.bundle.clone();
        match name {
            "tampered_output" => b.output.body.values[0] += 1,
            "certificate_reference" => b.output.body.mask[0] ^= 1,
            "truncated_checkpoint" => {
                b.public.log.entries.pop();
            }
            _ => b.public.endorsements[1] = b.public.endorsements[0].clone(),
        }
        if name == "tampered_mask_opening" {
            b = run.bundle.clone();
            b.mask.body.opening.v[0] += Scalar::ONE;
            b.mask = sign(d.ctx(), "mask-certificate", 0, b.mask.body, &run.server);
            b.output.body.mask = hash(&b.mask);
            b.output = sign(d.ctx(), "output", 0, b.output.body, &run.server);
        }
        if name == "tampered_output" || name == "certificate_reference" {
            b.output = sign(d.ctx(), "output", 0, b.output.body, &run.server);
        }
        out.push(outcome(
            name,
            "blocked",
            audit(&run.trust, &b).map(|_| "accepted".into()),
            start,
            false,
            0,
            wire(&b).len(),
        ));
    }
    // Both appeals execute proof replay. A signed full map supplies the path independently.
    for omission in [true, false] {
        let start = Instant::now();
        let r = p.records[0].clone();
        let receipt = match &p.log.entries[0].event {
            Event::Receipt(r) => r.clone(),
            _ => unreachable!(),
        };
        let mut slots = p.finalization.map.body.slots.clone();
        if omission {
            slots[0] = None;
        }
        let witness = map_witness(d.ctx(), &slots, 0);
        let map = map_make(d, slots, &run.server);
        let mut decision = p.decisions[0].body.clone();
        decision.status = "invalid".into();
        decision.reason = "unsupported dropout".into();
        let decision = sign(d.ctx(), "decision", 0, decision, &run.server);
        let appeal = sign(
            d.ctx(),
            "appeal",
            0,
            Appeal {
                record: r,
                receipt,
                proposed_map: map,
                witness,
                decision,
            },
            &run.clients[0],
        );
        let receipts = log_verify(d, &p.log, &run.trust)?;
        let result = appeal_verify(d, &g, &appeal, &receipts);
        let evidence = result.is_ok();
        let expected = if omission {
            "serverFault(omission)"
        } else {
            "serverFault(falseReject)"
        };
        out.push(outcome(
            if omission {
                "omission_appeal"
            } else {
                "false_reject_appeal"
            },
            expected,
            result,
            start,
            evidence,
            0,
            wire(&appeal).len(),
        ));
        let start = Instant::now();
        let mut bad = appeal.clone();
        bad.body.witness.siblings[0][0] ^= 1;
        bad = sign(d.ctx(), "appeal", 0, bad.body, &run.clients[0]);
        out.push(outcome(
            "tampered_map_path",
            "blocked",
            appeal_verify(d, &g, &bad, &receipts).map(|_| "accepted".into()),
            start,
            false,
            0,
            wire(&bad).len(),
        ));
        let start = Instant::now();
        let mut wrong = p.clone();
        wrong.finalization.admitted.remove(0);
        let rejected = run.holders[0].endorse(d, &g, &wrong, &run.trust);
        out.push(outcome(
            if omission {
                "omission_finalization"
            } else {
                "false_rejection_finalization"
            },
            "blocked",
            rejected.map(|_| "endorsed".into()),
            start,
            false,
            0,
            wire(&wrong.finalization).len(),
        ));
        // New common checkpoint includes the appeal; corrected membership is independently replayed.
        let start = Instant::now();
        let mut corrected = p.clone();
        corrected.log.entries.push(Entry {
            tick: d.config.receipt_cutoff + 1,
            event: Event::Appeal(Box::new(appeal)),
        });
        corrected.log.appeal = checkpoint(
            d,
            &corrected.log.entries,
            d.config.appeal_cutoff,
            &run.log_key,
        );
        let mut trust = run.trust.clone();
        trust.appeal_checkpoint = hash(&corrected.log.appeal);
        corrected.finalization.appeals = hash(&corrected.log.entries);
        corrected.finalization.checkpoint = hash(&corrected.log.appeal);
        let serialized = wire(&corrected);
        let replay = (0..d.config.m).try_for_each(|_| {
            let view: Public = parse(&serialized)?;
            policy_verify(d, &g, &view, &trust)
        });
        out.push(outcome(
            "appeal_resolution_full_replay",
            "accepted",
            replay.map(|_| "accepted".into()),
            start,
            false,
            0,
            serialized.len() * d.config.m,
        ));
    }
    let start = Instant::now();
    let holder = &run.holders[0];
    let repeated = holder.release(d, &g, p, &run.trust, &run.bundle.request)?;
    require(
        repeated == run.bundle.mask.body.releases[0],
        "repeat release differs",
    )?;
    let restarted = Holder {
        id: holder.id,
        signing: holder.signing.clone(),
        encryption: holder.encryption.clone(),
        shares: holder.shares.clone(),
        directory: holder.directory.clone(),
    };
    let cached = restarted.release(d, &g, p, &run.trust, &run.bundle.request)?;
    out.push(outcome(
        "restart_idempotent_release",
        "accepted",
        require(cached == repeated, "restart mismatch").map(|_| "accepted".into()),
        start,
        false,
        0,
        wire(&cached).len(),
    ));
    // Valid policy but different finalization digest: re-sign same map with a different metadata-free
    // choice is impossible with deterministic signatures, so alter an equivalent accepted log by
    // adding a genuine appeal above; this reaches the durable conflict check after policy replay.
    let start = Instant::now();
    let r = p.records[0].clone();
    let receipt = match &p.log.entries[0].event {
        Event::Receipt(r) => r.clone(),
        _ => unreachable!(),
    };
    let mut slots = p.finalization.map.body.slots.clone();
    slots[0] = None;
    let witness = map_witness(d.ctx(), &slots, 0);
    let proposed_map = map_make(d, slots, &run.server);
    let mut dec = p.decisions[0].body.clone();
    dec.status = "invalid".into();
    dec.reason = "unsupported dropout".into();
    let decision = sign(d.ctx(), "decision", 0, dec, &run.server);
    let appeal = sign(
        d.ctx(),
        "appeal",
        0,
        Appeal {
            record: r,
            receipt,
            proposed_map,
            witness,
            decision,
        },
        &run.clients[0],
    );
    let mut conflict = p.clone();
    conflict.log.entries.push(Entry {
        tick: d.config.receipt_cutoff + 1,
        event: Event::Appeal(Box::new(appeal)),
    });
    conflict.log.appeal = checkpoint(
        d,
        &conflict.log.entries,
        d.config.appeal_cutoff,
        &run.log_key,
    );
    let mut alternative_trust = run.trust.clone();
    alternative_trust.appeal_checkpoint = hash(&conflict.log.appeal);
    conflict.finalization.appeals = hash(&conflict.log.entries);
    conflict.finalization.checkpoint = hash(&conflict.log.appeal);
    let policy_ok = policy_verify(d, &g, &conflict, &alternative_trust).is_ok();
    let result = restarted.endorse(d, &g, &conflict, &alternative_trust);
    out.push(outcome(
        "restart_conflicting_finalization",
        "blocked",
        result.map(|_| "endorsed".into()),
        start,
        policy_ok,
        0,
        wire(&conflict.finalization).len(),
    ));
    let start = Instant::now();
    let race_dir = holder
        .directory
        .parent()
        .ok_or("holder directory")?
        .join("concurrent-choice-0");
    let make_racer = || Holder {
        id: holder.id,
        signing: holder.signing.clone(),
        encryption: holder.encryption.clone(),
        shares: holder.shares.clone(),
        directory: race_dir.clone(),
    };
    let (first, second) = (make_racer(), make_racer());
    let (d1, d2) = (d.clone(), d.clone());
    let (g1, g2) = (g.clone(), g.clone());
    let (p1, p2) = (p.clone(), conflict.clone());
    let (t1, t2) = (run.trust.clone(), alternative_trust.clone());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let b1 = barrier.clone();
    let b2 = barrier.clone();
    let left = std::thread::spawn(move || {
        b1.wait();
        first.endorse(&d1, &g1, &p1, &t1)
    });
    let right = std::thread::spawn(move || {
        b2.wait();
        second.endorse(&d2, &g2, &p2, &t2)
    });
    barrier.wait();
    let left = left
        .join()
        .map_err(|_| "first concurrent holder panicked")?;
    let right = right
        .join()
        .map_err(|_| "second concurrent holder panicked")?;
    let one_choice = left.is_ok() ^ right.is_ok();
    out.push(outcome(
        "concurrent_conflicting_finalizations",
        "blocked",
        if one_choice {
            Err("exactly one policy-valid finalization endorsed".into())
        } else {
            Ok("two or zero endorsed".into())
        },
        start,
        one_choice,
        0,
        wire(&p.finalization).len() + wire(&conflict.finalization).len(),
    ));
    let start = Instant::now();
    let bounded = decode(
        &[g.g * signed((d.config.n as u64 * d.config.bound + 1) as i64)],
        (d.config.n as u64 * d.config.bound) as i64,
        g.g,
    );
    out.push(outcome(
        "decode_out_of_interval",
        "blocked",
        bounded.map(|_| "accepted".into()),
        start,
        false,
        0,
        32,
    ));
    let unique: BTreeSet<_> = run.bundle.mask.body.releases.iter().map(|r| r.id).collect();
    require(unique.len() == d.config.t, "honest release trace")?;
    Ok(out)
}
