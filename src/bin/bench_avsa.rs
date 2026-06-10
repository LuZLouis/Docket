use avsa_rs::bench::cases::{
    bit_size_for_bound, default_b2_sq, BenchBackend, BenchConfig, BenchPreset,
};
use avsa_rs::bench::formal::{
    run_config as run_formal_config, run_full_suite_with_repetitions,
};
use avsa_rs::bench::runner::run;
use avsa_rs::{AvsaError, Result};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--full") {
        let out_dir = find_raw_value(&args, "--out")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("results"));
        let repetitions = find_raw_value(&args, "--repetitions")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(5);
        return match run_full_suite_with_repetitions(&out_dir, repetitions) {
            Ok(summary) => {
                for file in &summary.files {
                    println!(
                        "AVSA formal benchmark file: rows={}, out={}",
                        file.rows,
                        file.out_path.display()
                    );
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("bench_avsa full formal benchmark failed: {err}");
                ExitCode::from(1)
            }
        };
    }

    if let Some(config_path) = find_raw_value(&args, "--config") {
        let out = find_raw_value(&args, "--out").map(PathBuf::from);
        return match run_formal_config(&PathBuf::from(config_path), out) {
            Ok(summary) => {
                println!(
                    "AVSA formal benchmark complete: rows={}, out={}",
                    summary.rows,
                    summary.out_path.display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("bench_avsa formal benchmark failed: {err}");
                ExitCode::from(1)
            }
        };
    }

    match parse_args(args).and_then(|config| {
        let summary = run(&config)?;
        println!(
            "AVSA benchmark complete: runtime_rows={}, size_rows={}, correctness_rows={}, success={}, out={}",
            summary.runtime_rows,
            summary.size_rows,
            summary.correctness_rows,
            summary.success,
            summary.out_dir.display()
        );
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("bench_avsa failed: {err}");
            ExitCode::from(1)
        }
    }
}

fn find_raw_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            return args.get(index + 1).map(String::as_str);
        }
        index += if args[index] == "--allow-failures" || args[index] == "--full" {
            1
        } else {
            2
        };
    }
    None
}

fn parse_args(args: Vec<String>) -> Result<BenchConfig> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        std::process::exit(0);
    }

    let preset = find_value(&args, "--preset")?
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(BenchPreset::Smoke);
    let mut config = BenchConfig::for_preset(preset);

    let mut n_selected_overridden = false;
    let mut n_admitted_overridden = false;
    let mut n_dropped_overridden = false;
    let mut n_rejected_overridden = false;
    let mut b2_sq_overridden = false;
    let mut bit_size_overridden = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--preset" => {
                index = consume_value(&args, index)?;
            }
            "--backend" => {
                config.backend = parse_value::<BenchBackend>(&args, index, "--backend")?;
                index += 2;
            }
            "--n-selected" => {
                config.n_selected = parse_value::<usize>(&args, index, "--n-selected")?;
                n_selected_overridden = true;
                index += 2;
            }
            "--n-admitted" => {
                config.n_admitted = parse_value::<usize>(&args, index, "--n-admitted")?;
                n_admitted_overridden = true;
                index += 2;
            }
            "--n-dropped" => {
                config.n_dropped = parse_value::<usize>(&args, index, "--n-dropped")?;
                n_dropped_overridden = true;
                index += 2;
            }
            "--n-rejected" => {
                config.n_rejected = parse_value::<usize>(&args, index, "--n-rejected")?;
                n_rejected_overridden = true;
                index += 2;
            }
            "--dim" => {
                config.dim = parse_value::<usize>(&args, index, "--dim")?;
                index += 2;
            }
            "--b-inf" => {
                config.b_inf = parse_value::<i64>(&args, index, "--b-inf")?;
                index += 2;
            }
            "--b2-sq" => {
                config.b2_sq = parse_value::<u128>(&args, index, "--b2-sq")?;
                b2_sq_overridden = true;
                index += 2;
            }
            "--bit-size" => {
                config.bit_size = parse_value::<usize>(&args, index, "--bit-size")?;
                bit_size_overridden = true;
                index += 2;
            }
            "--iters" => {
                config.iters = parse_value::<usize>(&args, index, "--iters")?;
                index += 2;
            }
            "--warmup" => {
                config.warmup = parse_value::<usize>(&args, index, "--warmup")?;
                index += 2;
            }
            "--seed" => {
                config.seed = parse_value::<u64>(&args, index, "--seed")?;
                index += 2;
            }
            "--out" => {
                config.out_dir = PathBuf::from(value_for(&args, index, "--out")?);
                index += 2;
            }
            "--allow-failures" => {
                config.allow_failures = true;
                index += 1;
            }
            other => {
                return Err(AvsaError::InvalidBenchConfig(format!(
                    "unknown CLI option {other}"
                )));
            }
        }
    }

    if !b2_sq_overridden {
        config.b2_sq = default_b2_sq(config.dim, config.b_inf);
    }
    if !bit_size_overridden {
        config.bit_size = bit_size_for_bound(config.b2_sq);
    }

    if n_selected_overridden && !n_admitted_overridden {
        let reserved = if n_dropped_overridden || n_rejected_overridden {
            config.n_dropped.saturating_add(config.n_rejected)
        } else {
            1.min(config.n_selected.saturating_sub(1))
        };
        config.n_admitted = config.n_selected.saturating_sub(reserved).max(1);
    }

    if n_selected_overridden && !n_dropped_overridden {
        config.n_dropped = if config.n_admitted < config.n_selected {
            1
        } else {
            0
        };
    }
    if n_selected_overridden && !n_rejected_overridden {
        config.n_rejected = 0;
    }

    config.validate()?;
    Ok(config)
}

fn find_value<'a>(args: &'a [String], flag: &str) -> Result<Option<&'a str>> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            return Ok(Some(value_for(args, index, flag)?));
        }
        index += if args[index] == "--allow-failures" {
            1
        } else {
            2
        };
    }
    Ok(None)
}

fn consume_value(args: &[String], index: usize) -> Result<usize> {
    if index + 1 >= args.len() {
        return Err(AvsaError::InvalidBenchConfig(format!(
            "missing value for {}",
            args[index]
        )));
    }
    Ok(index + 2)
}

fn value_for<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    if index + 1 >= args.len() {
        return Err(AvsaError::InvalidBenchConfig(format!(
            "missing value for {flag}"
        )));
    }
    Ok(args[index + 1].as_str())
}

fn parse_value<T>(args: &[String], index: usize, flag: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value_for(args, index, flag)?
        .parse::<T>()
        .map_err(|err| AvsaError::InvalidBenchConfig(format!("invalid {flag}: {err}")))
}

fn print_help() {
    println!(
        "Usage: bench_avsa [OPTIONS]\n\n\
         Options:\n\
           --config <path> [--out <path>]  Run the formal AVSA evaluation config\n\
           --full [--out <dir>] [--time-mode calibrated] [--repetitions <usize>]\n\
           --preset smoke|small|medium|mnist_like|cifar10_s_like|cifar10_l_like|shakespeare_like\n\
           --backend mock|bulletproofs\n\
           --n-selected <usize> --n-admitted <usize> --n-dropped <usize> --n-rejected <usize>\n\
           --dim <usize> --b-inf <i64> --b2-sq <u128> --bit-size <usize>\n\
           --iters <usize> --warmup <usize> --seed <u64> --out <path>\n\
           --allow-failures"
    );
}
