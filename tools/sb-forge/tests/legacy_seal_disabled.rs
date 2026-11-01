use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after UNIX_EPOCH")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("sb-forge-{label}-{}-{unique}", std::process::id()));
    fs::create_dir(&path).expect("create isolated test directory");
    path
}

fn run_forge(directory: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sb-forge"))
        .current_dir(directory)
        .env("SB_FORGE_NESTED", "1")
        .args(args)
        .output()
        .expect("run sb-forge process")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn env_seal_fails_without_creating_an_artifact() {
    let directory = scratch_dir("seal-command");
    let output_path = directory.join("must-not-exist.sealed");
    let output = run_forge(
        &directory,
        &[
            "env",
            "seal",
            "prod",
            "--output",
            output_path.to_str().expect("UTF-8 test path"),
        ],
    );

    assert!(!output.status.success());
    assert!(combined_output(&output).contains("SB_FORGE_SEALED_V1-Format ist deaktiviert"));
    assert!(
        !output_path.exists(),
        "disabled sealing must not write an artifact"
    );

    fs::remove_dir_all(directory).expect("remove isolated test directory");
}

#[test]
fn exec_rejects_explicit_legacy_sealed_file() {
    let directory = scratch_dir("explicit-sealed");
    let sealed_path = directory.join("env.sealed");
    fs::write(&sealed_path, "arbitrary legacy content").expect("create legacy marker file");
    let output = run_forge(
        &directory,
        &[
            "exec",
            "--sealed",
            sealed_path.to_str().expect("UTF-8 test path"),
            "--",
            "command-must-not-run",
        ],
    );

    assert!(!output.status.success());
    assert!(combined_output(&output).contains("--sealed ist deaktiviert"));

    fs::remove_dir_all(directory).expect("remove isolated test directory");
}

#[test]
fn exec_rejects_auto_discovered_legacy_sealed_file() {
    let directory = scratch_dir("auto-sealed");
    fs::write(directory.join("env.sealed"), "arbitrary legacy content")
        .expect("create legacy marker file");
    let output = run_forge(&directory, &["exec", "--", "command-must-not-run"]);

    assert!(!output.status.success());
    assert!(combined_output(&output).contains("SB_FORGE_SEALED_V1-Format ist deaktiviert"));

    fs::remove_dir_all(directory).expect("remove isolated test directory");
}
