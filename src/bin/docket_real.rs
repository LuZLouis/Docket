use docket_rs::{
    crypto::Profile,
    harness::{attacks, run},
    protocol::Config,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

fn arg(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|v| v[0] == name)
        .map(|v| v[1].clone())
        .unwrap_or_else(|| default.into())
}
fn number(args: &[String], name: &str, default: &str) -> Result<usize, String> {
    arg(args, name, default)
        .parse()
        .map_err(|_| format!("invalid {name}"))
}
fn append(path: &PathBuf, row: &serde_json::Value) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{}", row).map_err(|e| e.to_string())
}
fn command(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".into())
}
fn execute() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.iter().any(|v| v == "--help") {
        println!("docket_real --n 4 --dim 8 --profile native|additive --predicate range|norm --repetitions 5 --warmup 1 --attacks each|once|none --out DIR\nReal Ristretto, Bulletproofs, Ed25519 and HPKE; synthetic signed vectors. Never runs training.");
        return Ok(());
    }
    let n = number(&args, "--n", "4")?;
    let dim = number(&args, "--dim", "8")?;
    let m = number(&args, "--m", "4")?;
    let t = number(&args, "--t", "3")?;
    let f_r = number(&args, "--f-r", "1")?;
    let f_c = number(&args, "--f-c", "1")?;
    let repetitions = number(&args, "--repetitions", "1")?;
    let warmup = number(&args, "--warmup", "1")?;
    let attack_mode = arg(&args, "--attacks", "each");
    if !matches!(attack_mode.as_str(), "each" | "once" | "none") {
        return Err("--attacks must be each|once|none".into());
    }
    let profile = match arg(&args, "--profile", "native").as_str() {
        "native" => Profile::Native,
        "additive" => Profile::Additive,
        _ => return Err("profile must be native|additive".into()),
    };
    let predicate = arg(&args, "--predicate", "range");
    let norm = match predicate.as_str() {
        "range" => None,
        "norm" => Some((dim * 9) as u64),
        _ => return Err("predicate must be range|norm".into()),
    };
    let out = PathBuf::from(arg(&args, "--out", "results/docket-small"));
    if out.exists() {
        return Err(format!("output already exists: {}", out.display()));
    }
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let cargo_lock = fs::read("Cargo.lock").map_err(|e| e.to_string())?;
    let source = [
        include_bytes!("../crypto.rs").as_slice(),
        include_bytes!("../protocol.rs").as_slice(),
        include_bytes!("../harness.rs").as_slice(),
    ]
    .concat();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let git = command("git", &["status", "--porcelain"]);
    let environment = json!({"source":"measured","input_source":"synthetic_fixture","cryptographic_randomness":"fresh OsRng per run; no fixed secret seed","utc_unix_seconds":now,"target":env::consts::OS,"arch":env::consts::ARCH,"cpu":env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_|"unavailable".into()),"logical_threads":std::thread::available_parallelism().map(|v|v.get()).unwrap_or(1),"execution_threads":"role phases serial; chunked Bulletproof proof or verification uses up to 8 workers; 2 competing holder threads in concurrency fault test","build":"cargo --release, Bulletproofs backend","rustc":command("rustc",&["--version"]),"git_head":command("git",&["rev-parse","HEAD"]),"git_status":git,"source_sha256":format!("{:x}",Sha256::digest(source)),"cargo_lock_sha256":format!("{:x}",Sha256::digest(&cargo_lock)),"cargo_lock_file":"Cargo.lock","repetitions":repetitions,"warmup":warmup,"attacks":attack_mode,"time_scope":"single-process sequential role operations; not network latency; fault suite excluded from normal-path timer","bytes_scope":"canonical bincode fixed-width messages including repeated sends; unique public object storage separate"});
    fs::write(
        out.join("environment.json"),
        serde_json::to_vec_pretty(&environment).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(out.join("Cargo.lock"), &cargo_lock).map_err(|e| e.to_string())?;
    let mut failures = 0;
    for index in 0..(warmup + repetitions) {
        let measured = index >= warmup;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let round = format!(
            "accept-{}-{}-{}-{}-{}",
            now,
            profile as u8,
            dim,
            index,
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let cfg = Config {
            round,
            n,
            m,
            t,
            f_r,
            f_c,
            unavailable: 0,
            dim,
            profile,
            bound: 7,
            norm,
            receipt_cutoff: n as u64 + 1,
            appeal_cutoff: n as u64 + 100,
        };
        cfg.validate()?;
        let directory = out.join(if measured {
            format!("run-{}", index - warmup)
        } else {
            format!("warmup-{index}")
        });
        let outcome = run(cfg.clone(), &directory);
        match outcome {
            Ok(result) => {
                let do_attacks =
                    attack_mode == "each" || (attack_mode == "once" && measured && index == warmup);
                let attack_results = if do_attacks {
                    attacks(&result)
                } else {
                    Ok(Vec::new())
                };
                let attacks = match attack_results {
                    Ok(attacks) => attacks,
                    Err(error) => {
                        failures += 1;
                        let row = json!({"status":"attack_error","error":error,"config":cfg,"run_directory":directory.display().to_string(),"warmup":!measured});
                        fs::write(
                            directory.join("run.json"),
                            serde_json::to_vec_pretty(&row).unwrap(),
                        )
                        .map_err(|e| e.to_string())?;
                        if measured {
                            append(&out.join("raw.jsonl"), &row)?;
                        }
                        println!("{}: ATTACK ERROR: {}", directory.display(), error);
                        continue;
                    }
                };
                let passed = attacks.iter().all(|a| a.passed);
                if !passed {
                    failures += 1;
                }
                let row = json!({"status":if passed{"success"}else{"attack_failure"},"source":"measured","input_source":"synthetic_fixture","config":cfg,"run_directory":directory.display().to_string(),"warmup":!measured,"total_sequential_ms":result.total_ms,"role_phase_ms":result.meter.times_ms,"wire_transmission_bytes":result.meter.transmission_bytes(),"unique_public_storage_bytes":result.meter.public_storage_bytes(),"oracle_equal":result.bundle.output.body.values==result.oracle,"attack_status":if do_attacks {if passed {"passed"} else {"failed"}} else {"not_run"},"attack_passed":if do_attacks {Some(passed)} else {None}});
                fs::write(
                    directory.join("run.json"),
                    serde_json::to_vec_pretty(&row).unwrap(),
                )
                .map_err(|e| e.to_string())?;
                fs::write(
                    directory.join("traffic.json"),
                    serde_json::to_vec_pretty(&result.meter.messages).unwrap(),
                )
                .map_err(|e| e.to_string())?;
                fs::write(
                    directory.join("attacks.json"),
                    serde_json::to_vec_pretty(&attacks).unwrap(),
                )
                .map_err(|e| e.to_string())?;
                if measured {
                    append(&out.join("raw.jsonl"), &row)?;
                    for attack in &attacks {
                        append(
                            &out.join("attacks.jsonl"),
                            &serde_json::to_value(attack).unwrap(),
                        )?;
                    }
                }
                println!(
                    "{}: {} n={} dim={} {:?} {:.3} ms, {} transmitted bytes, {} attacks",
                    directory.display(),
                    if passed { "PASS" } else { "FAIL" },
                    n,
                    dim,
                    profile,
                    result.total_ms,
                    result.meter.transmission_bytes(),
                    attacks.len()
                );
            }
            Err(e) => {
                failures += 1;
                let row = json!({"status":"failed","error":e,"config":cfg,"run_directory":directory.display().to_string(),"warmup":!measured});
                if measured {
                    append(&out.join("raw.jsonl"), &row)?;
                }
                println!("{}: FAILED: {}", directory.display(), e);
            }
        }
    }
    if failures > 0 {
        Err(format!(
            "{failures} runs/checks failed; see {}",
            out.display()
        ))
    } else {
        Ok(())
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("docket_real: {e}");
            ExitCode::FAILURE
        }
    }
}
