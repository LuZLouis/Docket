use super::{hash, parse, require, wire, Hash, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::RistrettoPoint as Point, scalar::Scalar, traits::Identity};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub fn random() -> Scalar {
    let mut b = [0; 64];
    OsRng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}
pub fn signed(x: i64) -> Scalar {
    if x < 0 {
        -Scalar::from(x.unsigned_abs())
    } else {
        Scalar::from(x as u64)
    }
}
pub fn base(label: &str, j: usize) -> Point {
    for counter in 0u64.. {
        let b: [u8; 64] =
            Sha512::digest(wire(&("Docket-base-v1", label, j as u64, counter))).into();
        let p = Point::from_uniform_bytes(&b);
        if p != Point::identity() {
            return p;
        }
    }
    unreachable!()
}
pub fn challenge<T: Serialize>(domain: &str, value: &T) -> Scalar {
    for counter in 0u64.. {
        let b: [u8; 64] = Sha512::digest(wire(&(domain, value, counter))).into();
        let s = Scalar::from_bytes_mod_order_wide(&b);
        if s != Scalar::ZERO {
            return s;
        }
    }
    unreachable!()
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Auth<T> {
    pub ctx: Hash,
    pub tag: String,
    pub id: usize,
    pub body: T,
    pub signature: Vec<u8>,
}
pub fn sign<T: Serialize>(ctx: Hash, tag: &str, id: usize, body: T, key: &SigningKey) -> Auth<T> {
    let signature = key
        .sign(&wire(&(ctx, tag, id as u64, &body)))
        .to_bytes()
        .to_vec();
    Auth {
        ctx,
        tag: tag.into(),
        id,
        body,
        signature,
    }
}
pub fn verify<T: Serialize>(
    a: &Auth<T>,
    ctx: Hash,
    tag: &str,
    id: usize,
    key: &[u8; 32],
) -> Result<()> {
    require(
        a.ctx == ctx && a.tag == tag && a.id == id,
        "signature context/type/identity",
    )?;
    let vk = VerifyingKey::from_bytes(key).map_err(|_| "public key")?;
    let sig = Signature::from_slice(&a.signature).map_err(|_| "signature encoding")?;
    vk.verify_strict(&wire(&(a.ctx, a.tag.as_str(), a.id as u64, &a.body)), &sig)
        .map_err(|_| "signature invalid".into())
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Profile {
    Native,
    Additive,
}
#[derive(Clone)]
pub struct Bases {
    pub g: Point,
    pub h: Point,
    pub k: Point,
    pub hs: Vec<Point>,
    pub ks: Vec<Point>,
}
impl Bases {
    pub fn new(dim: usize) -> Self {
        Self {
            g: base("g", 0),
            h: base("h", 0),
            k: base("k", 0),
            hs: (0..dim).map(|j| base("H", j)).collect(),
            ks: (0..dim).map(|j| base("k-coordinate", j)).collect(),
        }
    }
    pub fn tag(&self, p: Profile, v: &[Scalar]) -> Point {
        match p {
            Profile::Native => self.k * v[0],
            Profile::Additive => v.iter().zip(&self.ks).map(|(s, k)| s * k).sum(),
        }
    }
    pub fn com(&self, p: Profile, v: &[Scalar], b: Scalar) -> Point {
        self.tag(p, v) + self.h * b
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Encoding {
    Native { k: Point, y: Vec<Point> },
    Additive(Vec<Scalar>),
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Square {
    pub e: Vec<Point>,
    pub u: Vec<Point>,
    pub w: Vec<Point>,
    pub p: Vec<Scalar>,
    pub r: Vec<Scalar>,
    pub s: Vec<Scalar>,
    pub range: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Predicate {
    pub range: Vec<u8>,
    pub square: Option<Square>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Link {
    pub a: Vec<Point>,
    pub b: Vec<Point>,
    pub bk: Option<Point>,
    pub ad: Point,
    pub zx: Vec<Scalar>,
    pub zr: Vec<Scalar>,
    pub zs: Option<Scalar>,
    pub zb: Scalar,
}
pub struct Statement<'a> {
    pub ctx: Hash,
    pub id: usize,
    pub profile: Profile,
    pub c: &'a [Point],
    pub enc: &'a Encoding,
    pub d: Point,
    pub meta: Hash,
}
fn link_challenge(st: &Statement<'_>, pred: &Predicate, l: &Link) -> Scalar {
    challenge(
        "Docket-link-v1",
        &(
            st.ctx,
            st.id as u64,
            st.profile,
            st.c,
            st.enc,
            st.d,
            st.meta,
            hash(pred),
            &l.a,
            &l.b,
            l.bk,
            l.ad,
        ),
    )
}
pub fn link_prove(
    st: &Statement<'_>,
    pred: &Predicate,
    x: &[i64],
    rho: &[Scalar],
    mask: &[Scalar],
    beta: Scalar,
    g: &Bases,
) -> Link {
    let a: Vec<_> = x.iter().map(|_| random()).collect();
    let b: Vec<_> = x.iter().map(|_| random()).collect();
    let d = random();
    let r = random();
    let native = st.profile == Profile::Native;
    let mut l = Link {
        a: a.iter().zip(&b).map(|(a, b)| g.g * a + g.h * b).collect(),
        b: if native {
            a.iter().zip(&g.hs).map(|(a, h)| g.g * a + h * r).collect()
        } else {
            vec![]
        },
        bk: if native { Some(g.g * r) } else { None },
        ad: if native {
            g.k * r + g.h * d
        } else {
            g.tag(Profile::Additive, &a) - g.h * d
        },
        zx: vec![],
        zr: vec![],
        zs: None,
        zb: Scalar::ZERO,
    };
    let c = link_challenge(st, pred, &l);
    l.zx = a.iter().zip(x).map(|(a, x)| a + c * signed(*x)).collect();
    l.zr = b.iter().zip(rho).map(|(b, rho)| b + c * rho).collect();
    l.zb = d + c * beta;
    if native {
        l.zs = Some(r + c * mask[0]);
    }
    l
}
pub fn link_verify(st: &Statement<'_>, pred: &Predicate, l: &Link, g: &Bases) -> Result<()> {
    let dim = g.hs.len();
    require(
        st.c.len() == dim && l.a.len() == dim && l.zx.len() == dim && l.zr.len() == dim,
        "link dimensions",
    )?;
    let c = link_challenge(st, pred, l);
    for j in 0..dim {
        require(
            g.g * l.zx[j] + g.h * l.zr[j] == l.a[j] + st.c[j] * c,
            "link input",
        )?;
    }
    match (st.profile, st.enc) {
        (Profile::Native, Encoding::Native { k, y }) => {
            require(y.len() == dim && l.b.len() == dim, "encoding dimensions")?;
            let zs = l.zs.ok_or("missing mask response")?;
            let bk = l.bk.ok_or("missing mask first message")?;
            for j in 0..dim {
                require(
                    g.g * l.zx[j] + g.hs[j] * zs == l.b[j] + y[j] * c,
                    "link encoding",
                )?;
            }
            require(
                g.g * zs == bk + k * c && g.k * zs + g.h * l.zb == l.ad + st.d * c,
                "link mask",
            )
        }
        (Profile::Additive, Encoding::Additive(u)) => {
            require(
                u.len() == dim && l.b.is_empty() && l.bk.is_none() && l.zs.is_none(),
                "additive dimensions/extra fields",
            )?;
            require(
                g.tag(Profile::Additive, &l.zx) - g.h * l.zb
                    == l.ad + (g.tag(Profile::Additive, u) - st.d) * c,
                "additive link",
            )
        }
        _ => Err("mixed profile".into()),
    }
}
fn bits(bound: u64) -> Result<usize> {
    [8, 16, 32, 64]
        .into_iter()
        .find(|b| (bound as u128) < (1u128 << b))
        .ok_or("range width".into())
}
fn transcript(ctx: Hash, id: usize, role: &str, bound: u64, cs: &[Point]) -> Transcript {
    let mut t = Transcript::new(b"Docket-Bulletproofs-v1");
    t.append_message(b"statement", &wire(&(ctx, id as u64, role, bound, cs)));
    t
}
const RANGE_CHUNK_VALUES: usize = 1024;
const RANGE_CHUNK_MAGIC: &[u8] = b"Docket-BP-CHUNK-v1";
const RANGE_MAX_WORKERS: usize = 8;

pub fn range_workers(values: usize) -> usize {
    values
        .div_ceil(RANGE_CHUNK_VALUES)
        .min(RANGE_MAX_WORKERS)
        .max(1)
}

fn range_prove_single(
    ctx: Hash,
    id: usize,
    role: &str,
    bound: u64,
    values: &[u64],
    blind: &[Scalar],
    g: &Bases,
    generators: &BulletproofGens,
) -> Result<Vec<u8>> {
    let mut v = values.to_vec();
    let mut b = blind.to_vec();
    let m = v.len().next_power_of_two();
    v.resize(m, 0);
    b.resize(m, Scalar::ZERO);
    let cs: Vec<_> = v
        .iter()
        .zip(&b)
        .map(|(v, b)| g.g * Scalar::from(*v) + g.h * b)
        .collect();
    let w = bits(bound)?;
    let mut t = transcript(ctx, id, role, bound, &cs);
    let (proof, _) = RangeProof::prove_multiple(
        generators,
        &PedersenGens {
            B: g.g,
            B_blinding: g.h,
        },
        &mut t,
        &v,
        &b,
        w,
    )
    .map_err(|e| format!("range prove: {e}"))?;
    Ok(proof.to_bytes())
}
fn range_verify_single(
    ctx: Hash,
    id: usize,
    role: &str,
    bound: u64,
    cs: &[Point],
    proof: &[u8],
    g: &Bases,
    generators: &BulletproofGens,
) -> Result<()> {
    let mut cs = cs.to_vec();
    let m = cs.len().next_power_of_two();
    cs.resize(m, Point::identity());
    let w = bits(bound)?;
    let mut t = transcript(ctx, id, role, bound, &cs);
    let proof = RangeProof::from_bytes(proof).map_err(|_| "range encoding")?;
    proof
        .verify_multiple(
            generators,
            &PedersenGens {
                B: g.g,
                B_blinding: g.h,
            },
            &mut t,
            &cs.iter().map(|p| p.compress()).collect::<Vec<_>>(),
            w,
        )
        .map_err(|_| "range verification".into())
}
fn range_prove(
    ctx: Hash,
    id: usize,
    role: &str,
    bound: u64,
    values: &[u64],
    blind: &[Scalar],
    g: &Bases,
) -> Result<Vec<u8>> {
    require(
        values.len() == blind.len() && !values.is_empty(),
        "range dimensions",
    )?;
    if values.len() <= RANGE_CHUNK_VALUES {
        let generators = BulletproofGens::new(bits(bound)?, values.len().next_power_of_two());
        return range_prove_single(ctx, id, role, bound, values, blind, g, &generators);
    }
    let generators = BulletproofGens::new(bits(bound)?, RANGE_CHUNK_VALUES);
    let count = values.len().div_ceil(RANGE_CHUNK_VALUES);
    let workers = range_workers(values.len());
    let proofs = std::thread::scope(|scope| -> Result<Vec<Vec<u8>>> {
        let mut handles = Vec::new();
        for worker in 0..workers {
            let generators = &generators;
            handles.push(scope.spawn(move || {
                (worker..count)
                    .step_by(workers)
                    .map(|index| {
                        let from = index * RANGE_CHUNK_VALUES;
                        let to = (from + RANGE_CHUNK_VALUES).min(values.len());
                        (
                            index,
                            range_prove_single(
                                ctx,
                                id,
                                &format!("{role}/chunk/{index}"),
                                bound,
                                &values[from..to],
                                &blind[from..to],
                                g,
                                generators,
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            }));
        }
        let mut ordered = vec![None; count];
        for handle in handles {
            for (index, proof) in handle.join().map_err(|_| "range proof worker panicked")? {
                ordered[index] = Some(proof?);
            }
        }
        ordered
            .into_iter()
            .map(|proof| proof.ok_or_else(|| "missing range chunk".into()))
            .collect()
    })?;
    let mut encoded = RANGE_CHUNK_MAGIC.to_vec();
    encoded.extend_from_slice(&wire(&proofs));
    Ok(encoded)
}
fn range_verify(
    ctx: Hash,
    id: usize,
    role: &str,
    bound: u64,
    cs: &[Point],
    proof: &[u8],
    g: &Bases,
) -> Result<()> {
    require(!cs.is_empty(), "range dimensions")?;
    if cs.len() <= RANGE_CHUNK_VALUES {
        require(
            !proof.starts_with(RANGE_CHUNK_MAGIC),
            "unexpected chunk proof",
        )?;
        let generators = BulletproofGens::new(bits(bound)?, cs.len().next_power_of_two());
        return range_verify_single(ctx, id, role, bound, cs, proof, g, &generators);
    }
    let encoded = proof
        .strip_prefix(RANGE_CHUNK_MAGIC)
        .ok_or("missing chunk proof header")?;
    let count = cs.len().div_ceil(RANGE_CHUNK_VALUES);
    require(encoded.len() <= count * 10_000, "oversized chunk proof")?;
    let proofs: Vec<Vec<u8>> = parse(encoded)?;
    require(proofs.len() == count, "chunk proof count")?;
    let generators = BulletproofGens::new(bits(bound)?, RANGE_CHUNK_VALUES);
    let workers = range_workers(cs.len());
    std::thread::scope(|scope| -> Result<()> {
        let mut handles = Vec::new();
        for worker in 0..workers {
            let proofs = &proofs;
            let generators = &generators;
            handles.push(scope.spawn(move || -> Result<()> {
                for index in (worker..count).step_by(workers) {
                    let from = index * RANGE_CHUNK_VALUES;
                    let to = (from + RANGE_CHUNK_VALUES).min(cs.len());
                    range_verify_single(
                        ctx,
                        id,
                        &format!("{role}/chunk/{index}"),
                        bound,
                        &cs[from..to],
                        &proofs[index],
                        g,
                        generators,
                    )?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| "range verification worker panicked")??;
        }
        Ok(())
    })?;
    Ok(())
}
pub fn predicate_prove(
    ctx: Hash,
    id: usize,
    x: &[i64],
    rho: &[Scalar],
    cs: &[Point],
    bound: u64,
    norm: Option<u64>,
    g: &Bases,
) -> Result<Predicate> {
    require(x.iter().all(|x| x.unsigned_abs() <= bound), "input range")?;
    let vals: Vec<_> = x
        .iter()
        .flat_map(|x| [(bound as i64 + x) as u64, (bound as i64 - x) as u64])
        .collect();
    let blind: Vec<_> = rho.iter().flat_map(|r| [*r, -r]).collect();
    let range = range_prove(ctx, id, "coordinate", 2 * bound, &vals, &blind, g)?;
    let square = if let Some(b2) = norm {
        let n: u64 = x.iter().map(|x| x.unsigned_abs().pow(2)).sum();
        require(n <= b2, "input norm")?;
        let nu: Vec<_> = x.iter().map(|_| random()).collect();
        let a: Vec<_> = x.iter().map(|_| random()).collect();
        let b: Vec<_> = x.iter().map(|_| random()).collect();
        let d: Vec<_> = x.iter().map(|_| random()).collect();
        let mut sq = Square {
            e: x.iter()
                .zip(&nu)
                .map(|(x, n)| g.g * Scalar::from(x.unsigned_abs().pow(2)) + g.h * n)
                .collect(),
            u: a.iter().zip(&b).map(|(a, b)| g.g * a + g.h * b).collect(),
            w: a.iter()
                .zip(cs)
                .zip(&d)
                .map(|((a, c), d)| c * a + g.h * d)
                .collect(),
            p: vec![],
            r: vec![],
            s: vec![],
            range: vec![],
        };
        let c = challenge(
            "Docket-square-v1",
            &(ctx, id as u64, cs, &sq.e, &sq.u, &sq.w),
        );
        for j in 0..x.len() {
            sq.p.push(a[j] + c * signed(x[j]));
            sq.r.push(b[j] + c * rho[j]);
            sq.s.push(d[j] + c * (nu[j] - signed(x[j]) * rho[j]));
        }
        let v: Scalar = nu.iter().sum();
        sq.range = range_prove(ctx, id, "norm", b2, &[n, b2 - n], &[v, -v], g)?;
        Some(sq)
    } else {
        None
    };
    Ok(Predicate { range, square })
}
pub fn predicate_verify(
    ctx: Hash,
    id: usize,
    cs: &[Point],
    pred: &Predicate,
    bound: u64,
    norm: Option<u64>,
    g: &Bases,
) -> Result<()> {
    require(cs.len() == g.hs.len(), "predicate dimensions")?;
    let shifted: Vec<_> = cs
        .iter()
        .flat_map(|c| [g.g * Scalar::from(bound) + c, g.g * Scalar::from(bound) - c])
        .collect();
    range_verify(ctx, id, "coordinate", 2 * bound, &shifted, &pred.range, g)?;
    match (norm, &pred.square) {
        (None, None) => Ok(()),
        (Some(b2), Some(sq)) => {
            let dim = cs.len();
            require(
                [
                    sq.e.len(),
                    sq.u.len(),
                    sq.w.len(),
                    sq.p.len(),
                    sq.r.len(),
                    sq.s.len(),
                ]
                .iter()
                .all(|l| *l == dim),
                "square dimensions",
            )?;
            let c = challenge(
                "Docket-square-v1",
                &(ctx, id as u64, cs, &sq.e, &sq.u, &sq.w),
            );
            for j in 0..dim {
                require(
                    g.g * sq.p[j] + g.h * sq.r[j] == sq.u[j] + cs[j] * c
                        && cs[j] * sq.p[j] + g.h * sq.s[j] == sq.w[j] + sq.e[j] * c,
                    "square relation",
                )?;
            }
            let sum: Point = sq.e.iter().sum();
            range_verify(
                ctx,
                id,
                "norm",
                b2,
                &[sum, g.g * Scalar::from(b2) - sum],
                &sq.range,
                g,
            )
        }
        _ => Err("predicate profile".into()),
    }
}
pub fn decode(points: &[Point], bound: i64, g: Point) -> Result<Vec<i64>> {
    require(bound >= 0 && bound <= 10_000_000, "decode resource bound")?;
    let width = 2 * bound + 1;
    let mut a = 1i64;
    while a * a < width {
        a += 1;
    }
    let mut table = std::collections::HashMap::new();
    let mut p = Point::identity();
    for r in 0..a {
        table.insert(p.compress().to_bytes(), r);
        p += g;
    }
    points
        .iter()
        .map(|z| {
            let mut p = z + g * signed(bound);
            for v in 0..=(2 * bound / a) {
                if let Some(r) = table.get(&p.compress().to_bytes()) {
                    let y = v * a + r;
                    if y <= 2 * bound && g * signed(y - bound) == *z {
                        return Ok(y - bound);
                    }
                }
                p -= g * signed(a);
            }
            Err("bounded decode failed".into())
        })
        .collect()
}

#[cfg(test)]
mod chunk_tests {
    use super::*;

    #[test]
    fn chunked_range_proof_verifies_and_rejects_tampering() {
        let dim = RANGE_CHUNK_VALUES / 2 + 1;
        let bases = Bases::new(dim);
        let x = vec![1; dim];
        let rho: Vec<_> = (0..dim).map(|_| random()).collect();
        let commitments: Vec<_> = rho.iter().map(|r| bases.g + bases.h * r).collect();
        let ctx = [42; 32];
        let proof = predicate_prove(ctx, 0, &x, &rho, &commitments, 7, None, &bases).unwrap();
        assert!(proof.range.starts_with(RANGE_CHUNK_MAGIC));
        predicate_verify(ctx, 0, &commitments, &proof, 7, None, &bases).unwrap();
        let mut tampered = proof.clone();
        let last = tampered.range.len() - 1;
        tampered.range[last] ^= 1;
        assert!(predicate_verify(ctx, 0, &commitments, &tampered, 7, None, &bases).is_err());
    }
}
