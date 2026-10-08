//! Real single-record cryptographic component measurement; not a full round.
use docket_rs::{
    crypto::{
        link_prove, link_verify, predicate_prove, predicate_verify, random, signed, Bases,
        Encoding, Profile, Statement,
    },
    wire,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, ExitCode},
    time::Instant,
};

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|v| v[0] == name)
        .map(|v| v[1].clone())
        .unwrap_or_else(|| default.into())
}
fn count(args: &[String], name: &str, default: &str) -> Result<usize, String> {
    arg(args, name, default)
        .parse()
        .map_err(|_| format!("invalid {name}"))
}
fn measure() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.iter().any(|v| v == "--help") {
        println!("docket_component --dim 19000 --profile native|additive --predicate range|norm --warmup 0 --repetitions 1 --out NEW_DIR\nReal one-client proof and verification only; not a full Docket round.");
        return Ok(());
    }
    let dim = count(&args, "--dim", "19000")?;
    let repetitions = count(&args, "--repetitions", "1")?;
    let warmup = count(&args, "--warmup", "0")?;
    if dim == 0 || dim > 818_000 || repetitions == 0 {
        return Err("unsupported dimensions/repetitions".into());
    }
    let profile = match arg(&args, "--profile", "native").as_str() {
        "native" => Profile::Native,
        "additive" => Profile::Additive,
        _ => return Err("profile must be native|additive".into()),
    };
    let predicate_name = arg(&args, "--predicate", "range");
    let norm = match predicate_name.as_str() {
        "range" => None,
        "norm" => Some(dim as u64 * 9),
        _ => return Err("predicate must be range|norm".into()),
    };
    let out = PathBuf::from(arg(&args, "--out", "results/component"));
    if out.exists() {
        return Err(format!("output already exists: {}", out.display()));
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let source = [
        include_bytes!("../crypto.rs").as_slice(),
        include_bytes!("../protocol.rs").as_slice(),
        include_bytes!("../harness.rs").as_slice(),
    ]
    .concat();
    let lock = fs::read("Cargo.lock").map_err(|e| e.to_string())?;
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".into());
    fs::write(out.join("scope.json"), serde_json::to_vec_pretty(&json!({
        "source":"measured", "input_source":"synthetic_fixture", "scope":"one client: public bases, input encoding, real predicate proof, shared-response binding proof, both verifications; excludes VSS, HPKE, signatures, finalization, recovery, audit and network", "cryptographic_randomness":"fresh OsRng per repetition", "execution_threads":"one record with up to 8 workers for independent Bulletproof chunks", "time_unit":"ms", "communication_unit":"canonical serialized bytes", "profile":profile, "predicate":predicate_name, "dim":dim, "warmup":warmup, "repetitions":repetitions, "target":env::consts::OS, "arch":env::consts::ARCH, "cpu":env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_|"unavailable".into()), "rustc":rustc, "build":"cargo --release, Bulletproofs backend", "source_sha256":format!("{:x}",Sha256::digest(source)), "cargo_lock_sha256":format!("{:x}",Sha256::digest(&lock))
    })).unwrap()).map_err(|e|e.to_string())?;
    for index in 0..warmup + repetitions {
        let measured = index >= warmup;
        let result = (|| -> Result<serde_json::Value, String> {
            let overall = Instant::now();
            let start = Instant::now();
            let bases = Bases::new(dim);
            let bases_ms = start.elapsed().as_secs_f64() * 1000.;
            let x: Vec<i64> = (0..dim).map(|j| ((j * 7) % 7) as i64 - 3).collect();
            let rho: Vec<_> = (0..dim).map(|_| random()).collect();
            let mask: Vec<_> = (0..if profile == Profile::Native { 1 } else { dim })
                .map(|_| random())
                .collect();
            let beta = random();
            let mut ctx = [0u8; 32];
            OsRng.fill_bytes(&mut ctx);
            let start = Instant::now();
            let commitments: Vec<_> = x
                .iter()
                .zip(&rho)
                .map(|(x, r)| bases.g * signed(*x) + bases.h * r)
                .collect();
            let encoding = match profile {
                Profile::Native => Encoding::Native {
                    k: bases.g * mask[0],
                    y: x.iter()
                        .zip(&bases.hs)
                        .map(|(x, h)| bases.g * signed(*x) + h * mask[0])
                        .collect(),
                },
                Profile::Additive => {
                    Encoding::Additive(x.iter().zip(&mask).map(|(x, s)| signed(*x) + s).collect())
                }
            };
            let d = bases.com(profile, &mask, beta);
            let encoding_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            let predicate = predicate_prove(ctx, 0, &x, &rho, &commitments, 7, norm, &bases)?;
            let predicate_prove_ms = start.elapsed().as_secs_f64() * 1000.;
            let statement = Statement {
                ctx,
                id: 0,
                profile,
                c: &commitments,
                enc: &encoding,
                d,
                meta: [7; 32],
            };
            let start = Instant::now();
            let link = link_prove(&statement, &predicate, &x, &rho, &mask, beta, &bases);
            let link_prove_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            predicate_verify(ctx, 0, &commitments, &predicate, 7, norm, &bases)?;
            let predicate_verify_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            link_verify(&statement, &predicate, &link, &bases)?;
            let link_verify_ms = start.elapsed().as_secs_f64() * 1000.;
            let bytes = json!({"commitments":wire(&commitments).len(), "encoding":wire(&encoding).len(), "predicate":wire(&predicate).len(), "link":wire(&link).len(), "combined":wire(&(&commitments,&encoding,&predicate,&link)).len()});
            Ok(
                json!({"status":"success", "source":"measured", "input_source":"synthetic_fixture", "sample":index - warmup, "warmup":!measured, "dim":dim, "profile":profile, "predicate_name":predicate_name, "total_sequential_ms":overall.elapsed().as_secs_f64()*1000., "phase_ms":{"public_bases":bases_ms,"encoding":encoding_ms,"predicate_prove":predicate_prove_ms,"link_prove":link_prove_ms,"predicate_verify":predicate_verify_ms,"link_verify":link_verify_ms},"serialized_bytes":bytes}),
            )
        })();
        let row = result.unwrap_or_else(|error| json!({"status":"failed","error":error,"dim":dim,"profile":profile,"predicate_name":predicate_name,"sample":index.saturating_sub(warmup),"warmup":!measured}));
        let file = out.join(if measured {
            "raw.jsonl"
        } else {
            "warmup.jsonl"
        });
        writeln!(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file)
                .map_err(|e| e.to_string())?,
            "{row}"
        )
        .map_err(|e| e.to_string())?;
        println!(
            "{} dim={} {:?} {} {:.3} ms",
            row["status"],
            dim,
            profile,
            predicate_name,
            row["total_sequential_ms"].as_f64().unwrap_or(0.)
        );
        if row["status"] != "success" {
            return Err(format!("component sample failed: {}", row["error"]));
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    match measure() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("docket_component: {error}");
            ExitCode::FAILURE
        }
    }
}
