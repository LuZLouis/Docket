use docket_rs::{
    parse,
    protocol::{audit, AuditBundle, Trust},
};
use std::{env, fs, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!(
            "usage: docket_audit <run-directory>/public.bin <independently trusted 64-hex context>"
        );
        return ExitCode::FAILURE;
    }
    let path = &args[0];
    let anchor = &args[1];
    let result = fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|v| parse::<(Trust, AuditBundle)>(&v))
        .and_then(|(trust, bundle)| {
            let actual = trust
                .descriptor
                .body
                .ctx()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if anchor != &actual {
                return Err("independent context anchor mismatch".into());
            }
            audit(&trust, &bundle)
        });
    match result {
        Ok(()) => {
            println!("public audit accepted: {path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("public audit rejected: {e}");
            ExitCode::FAILURE
        }
    }
}
