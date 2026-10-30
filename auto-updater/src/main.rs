mod config;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use config::{Artifact, CommandSpec, Config, HealthCheck, Package, Source};
use fs2::FileExt;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use ureq::{Agent, ResponseExt};

const DEFAULT_CONFIG: &str = "/etc/random-utils/update.toml";

#[derive(Debug)]
struct Cli {
    config: PathBuf,
    packages: BTreeSet<String>,
    dry_run: bool,
    force: bool,
    list: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageState {
    tag: Option<String>,
    #[serde(default)]
    artifacts: BTreeMap<String, String>,
    #[serde(default)]
    last_checked_unix: u64,
}

#[derive(Debug)]
struct CandidateArtifact<'a> {
    config: &'a Artifact,
    path: PathBuf,
    digest: String,
}

#[derive(Debug)]
struct Backup {
    destination: PathBuf,
    copy: Option<PathBuf>,
    mode: u32,
    uid: u32,
    gid: u32,
}

struct Runtime<'a> {
    state_dir: &'a Path,
    max_download_bytes: u64,
    download_agent: &'a Agent,
    health_agent: &'a Agent,
    cli: &'a Cli,
}

struct TransactionContext<'a> {
    package: &'a Package,
    tag: &'a str,
    state_path: &'a Path,
    now: u64,
    health_agent: &'a Agent,
    env: &'a [(String, String)],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CommandOutcome {
    Success,
    Deferred,
}

fn main() -> Result<()> {
    let cli = parse_cli()?;
    let config = Config::load(&cli.config)?;

    if cli.list {
        for package in config.package.iter().filter(|package| package.enabled) {
            println!("{}", package.name);
        }
        return Ok(());
    }

    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("create state directory {}", config.state_dir.display()))?;
    let lock = acquire_lock(&config.state_dir)?;

    let download_agent: Agent = Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(600)))
        .user_agent("random-utils-update/0.1")
        .build()
        .into();
    let health_agent: Agent = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .user_agent("random-utils-update-health/0.1")
        .build()
        .into();

    let runtime = Runtime {
        state_dir: &config.state_dir,
        max_download_bytes: config.max_download_bytes,
        download_agent: &download_agent,
        health_agent: &health_agent,
        cli: &cli,
    };

    let mut seen = BTreeSet::new();
    let mut failures = 0_u32;
    for package in config.package.iter().filter(|package| package.enabled) {
        if !cli.packages.is_empty() && !cli.packages.contains(&package.name) {
            continue;
        }
        seen.insert(package.name.clone());
        match update_package(package, &runtime) {
            Ok(()) => {}
            Err(error) => {
                failures = failures.saturating_add(1);
                eprintln!("{}: update failed: {error:#}", package.name);
            }
        }
    }

    for requested in cli.packages.difference(&seen) {
        eprintln!("unknown or disabled package {requested}");
        failures = failures.saturating_add(1);
    }

    drop(lock);
    if failures > 0 {
        bail!("{failures} package(s) failed");
    }
    Ok(())
}

fn parse_cli() -> Result<Cli> {
    let mut args = std::env::args_os().skip(1);
    let mut cli = Cli {
        config: PathBuf::from(DEFAULT_CONFIG),
        packages: BTreeSet::new(),
        dry_run: false,
        force: false,
        list: false,
    };
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") => {
                cli.config = PathBuf::from(args.next().context("--config requires a path")?);
            }
            Some("--package") => {
                let value = args.next().context("--package requires a name")?;
                cli.packages.insert(
                    value
                        .into_string()
                        .map_err(|_| anyhow!("package name is not UTF-8"))?,
                );
            }
            Some("--dry-run") => cli.dry_run = true,
            Some("--force") => cli.force = true,
            Some("--list") => cli.list = true,
            Some("-h" | "--help") => {
                println!(
                    "usage: random-utils-update [--config PATH] [--package NAME]... [--dry-run] [--force] [--list]"
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument {}", arg.to_string_lossy()),
        }
    }
    Ok(cli)
}

fn acquire_lock(state_dir: &Path) -> Result<File> {
    let path = state_dir.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open updater lock {}", path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            bail!("another random-utils-update process is already running")
        }
        Err(error) => Err(error).with_context(|| format!("lock {}", path.display())),
    }
}

fn update_package(package: &Package, runtime: &Runtime<'_>) -> Result<()> {
    let state_path = state_path(runtime.state_dir, &package.name);
    let mut state = load_state(&state_path)?;
    let now = unix_now()?;
    if !is_check_due(
        state.last_checked_unix,
        now,
        package.min_interval_seconds,
        runtime.cli.force,
    ) {
        println!("{}: skipped (check interval not elapsed)", package.name);
        return Ok(());
    }

    match &package.source {
        Source::GithubRelease { repo } => {
            update_github_package(package, repo, &state_path, &mut state, now, runtime)
        }
        Source::Command(spec) => {
            update_command_package(package, spec, &state_path, state, now, runtime.cli)
        }
    }
}

fn update_command_package(
    package: &Package,
    spec: &CommandSpec,
    state_path: &Path,
    mut state: PackageState,
    now: u64,
    cli: &Cli,
) -> Result<()> {
    if cli.dry_run {
        println!(
            "{}: dry-run would execute {}",
            package.name,
            spec.program.display()
        );
        return Ok(());
    }
    let env = command_env(package, None);
    match run_command(spec, &env)? {
        CommandOutcome::Success => {
            state.last_checked_unix = now;
            save_state(state_path, &state)?;
            println!("{}: delegated updater completed", package.name);
        }
        CommandOutcome::Deferred => {
            println!(
                "{}: delegated updater deferred; will retry on the next manager run",
                package.name
            );
        }
    }
    Ok(())
}

fn update_github_package(
    package: &Package,
    repo: &str,
    state_path: &Path,
    state: &mut PackageState,
    now: u64,
    runtime: &Runtime<'_>,
) -> Result<()> {
    let tag = latest_github_tag(runtime.download_agent, repo)
        .with_context(|| format!("{}: resolve latest GitHub release", package.name))?;

    if state.tag.as_deref() == Some(&tag) && installed_matches_state(package, state)? {
        state.last_checked_unix = now;
        if !runtime.cli.dry_run {
            save_state(state_path, state)?;
        }
        println!("{}: current at {tag}", package.name);
        return Ok(());
    }

    let work = Builder::new()
        .prefix(&format!(".{}-", package.name))
        .tempdir_in(state_path.parent().context("state file has no parent")?)
        .with_context(|| format!("{}: create update staging directory", package.name))?;
    let candidates = download_candidates(
        package,
        repo,
        &tag,
        work.path(),
        runtime.max_download_bytes,
        runtime.download_agent,
    )?;

    if installed_matches_candidates(&candidates)? {
        state.tag = Some(tag.clone());
        state.artifacts = candidate_state(&candidates);
        state.last_checked_unix = now;
        if runtime.cli.dry_run {
            println!(
                "{}: installed files already match {tag}; dry-run would refresh state",
                package.name
            );
        } else {
            save_state(state_path, state)?;
            println!(
                "{}: installed files already match {tag}; state refreshed",
                package.name
            );
        }
        return Ok(());
    }

    if runtime.cli.dry_run {
        println!("{}: dry-run would update to {tag}", package.name);
        return Ok(());
    }

    let env = command_env(package, Some(&tag));
    for hook in &package.pre_update {
        if run_command(hook, &env)? == CommandOutcome::Deferred {
            println!("{}: pre-update hook deferred {tag}", package.name);
            return Ok(());
        }
    }

    let backups = back_up_destinations(&candidates, work.path())?;
    let transaction = TransactionContext {
        package,
        tag: &tag,
        state_path,
        now,
        health_agent: runtime.health_agent,
        env: &env,
    };
    let result = apply_transaction(&transaction, &candidates, state);
    if let Err(error) = result {
        let rollback_result = rollback_transaction(package, &backups, &env);
        return match rollback_result {
            Ok(()) => Err(error.context("update rolled back successfully")),
            Err(rollback_error) => {
                Err(error.context(format!("rollback also failed: {rollback_error:#}")))
            }
        };
    }

    println!("{}: updated to {tag}", package.name);
    Ok(())
}

fn apply_transaction(
    transaction: &TransactionContext<'_>,
    candidates: &[CandidateArtifact<'_>],
    state: &mut PackageState,
) -> Result<()> {
    for candidate in candidates {
        install_artifact(candidate)?;
    }
    restart_units(&transaction.package.restart_units)?;
    for hook in &transaction.package.post_update {
        match run_command(hook, transaction.env)? {
            CommandOutcome::Success => {}
            CommandOutcome::Deferred => {
                bail!("post-update hook returned a defer exit code after files were installed")
            }
        }
    }
    for health in &transaction.package.health {
        run_health_check(health, transaction.health_agent, transaction.env)?;
    }
    state.tag = Some(transaction.tag.to_owned());
    state.artifacts = candidate_state(candidates);
    state.last_checked_unix = transaction.now;
    save_state(transaction.state_path, state)?;
    Ok(())
}

fn rollback_transaction(
    package: &Package,
    backups: &[Backup],
    env: &[(String, String)],
) -> Result<()> {
    let mut errors = Vec::new();
    for backup in backups.iter().rev() {
        if let Err(error) = restore_backup(backup) {
            errors.push(format!(
                "restore {}: {error:#}",
                backup.destination.display()
            ));
        }
    }
    if let Err(error) = restart_units(&package.restart_units) {
        errors.push(format!("restart units after rollback: {error:#}"));
    }
    for hook in &package.rollback {
        if let Err(error) = run_command(hook, env) {
            errors.push(format!(
                "rollback hook {}: {error:#}",
                hook.program.display()
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

fn latest_github_tag(agent: &Agent, repo: &str) -> Result<String> {
    let url = format!("https://github.com/{repo}/releases/latest");
    let response = agent
        .get(&url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let path = response.get_uri().path();
    let marker = "/releases/tag/";
    let encoded = path
        .find(marker)
        .map(|offset| &path[offset + marker.len()..])
        .filter(|value| !value.is_empty())
        .context("GitHub latest release did not redirect to /releases/tag/<tag>")?;
    let tag = percent_decode_str(encoded)
        .decode_utf8()
        .context("release tag is not valid UTF-8")?
        .into_owned();
    if tag.contains('\0') || tag.is_empty() {
        bail!("invalid release tag returned by GitHub");
    }
    Ok(tag)
}

fn release_asset_url(repo: &str, tag: &str, asset: &str) -> String {
    let tag = utf8_percent_encode(tag, NON_ALPHANUMERIC);
    let asset = utf8_percent_encode(asset, NON_ALPHANUMERIC);
    format!("https://github.com/{repo}/releases/download/{tag}/{asset}")
}

fn download_candidates<'a>(
    package: &'a Package,
    repo: &str,
    tag: &str,
    work_dir: &Path,
    max_download_bytes: u64,
    agent: &Agent,
) -> Result<Vec<CandidateArtifact<'a>>> {
    let mut checksum_cache = HashMap::<String, String>::new();
    let mut result = Vec::with_capacity(package.artifact.len());
    for (index, artifact) in package.artifact.iter().enumerate() {
        let asset = expand_template(&artifact.asset, &package.name, tag, None);
        let checksum_asset =
            expand_template(&artifact.checksum_asset, &package.name, tag, Some(&asset));
        if !checksum_cache.contains_key(&checksum_asset) {
            let text = download_text(
                agent,
                &release_asset_url(repo, tag, &checksum_asset),
                4 * 1024 * 1024,
            )?;
            checksum_cache.insert(checksum_asset.clone(), text);
        }
        let checksum_text = checksum_cache
            .get(&checksum_asset)
            .context("checksum cache entry disappeared")?;
        let expected = parse_sha256_manifest(checksum_text, &asset)?;
        let path = work_dir.join(format!("artifact-{index}"));
        download_file(
            agent,
            &release_asset_url(repo, tag, &asset),
            &path,
            max_download_bytes,
        )?;
        let digest = sha256_file(&path)?;
        if digest != expected {
            bail!(
                "{}: checksum mismatch for {asset}: expected {expected}, got {digest}",
                package.name
            );
        }
        result.push(CandidateArtifact {
            config: artifact,
            path,
            digest,
        });
    }
    Ok(result)
}

fn download_text(agent: &Agent, url: &str, limit: u64) -> Result<String> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .with_context(|| format!("read {url}"))
}

fn download_file(agent: &Agent, url: &str, path: &Path, limit: u64) -> Result<()> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    if response
        .body()
        .content_length()
        .is_some_and(|length| length > limit)
    {
        bail!("download {url} exceeds configured limit of {limit} bytes");
    }
    let mut input = response
        .body_mut()
        .as_reader()
        .take(limit.saturating_add(1));
    let mut output = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let written = std::io::copy(&mut input, &mut output)
        .with_context(|| format!("download {url} to {}", path.display()))?;
    if written > limit {
        bail!("download {url} exceeded configured limit of {limit} bytes");
    }
    output
        .sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    Ok(())
}

fn parse_sha256_manifest(text: &str, asset: &str) -> Result<String> {
    let mut unnamed = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else { continue };
        if !is_sha256(hash) {
            continue;
        }
        if let Some(name) = fields.next() {
            if name.trim_start_matches('*') == asset {
                return Ok(hash.to_ascii_lowercase());
            }
        } else {
            unnamed.push(hash.to_ascii_lowercase());
        }
    }
    if unnamed.len() == 1 {
        return Ok(unnamed.remove(0));
    }
    bail!("checksum manifest does not contain an unambiguous SHA-256 for {asset}")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn installed_matches_state(package: &Package, state: &PackageState) -> Result<bool> {
    if package.artifact.len() != state.artifacts.len() {
        return Ok(false);
    }
    for artifact in &package.artifact {
        let key = artifact.destination.to_string_lossy();
        let Some(expected) = state.artifacts.get(key.as_ref()) else {
            return Ok(false);
        };
        if !artifact.destination.is_file() || sha256_file(&artifact.destination)? != *expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn installed_matches_candidates(candidates: &[CandidateArtifact<'_>]) -> Result<bool> {
    for candidate in candidates {
        let destination = &candidate.config.destination;
        if !destination.is_file() || sha256_file(destination)? != candidate.digest {
            return Ok(false);
        }
    }
    Ok(true)
}

fn candidate_state(candidates: &[CandidateArtifact<'_>]) -> BTreeMap<String, String> {
    candidates
        .iter()
        .map(|candidate| {
            (
                candidate.config.destination.to_string_lossy().into_owned(),
                candidate.digest.clone(),
            )
        })
        .collect()
}

fn back_up_destinations(
    candidates: &[CandidateArtifact<'_>],
    work_dir: &Path,
) -> Result<Vec<Backup>> {
    let backup_dir = work_dir.join("backup");
    fs::create_dir(&backup_dir).with_context(|| format!("create {}", backup_dir.display()))?;
    let mut backups = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        let destination = &candidate.config.destination;
        match fs::symlink_metadata(destination) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!(
                        "refusing to replace non-regular destination {}",
                        destination.display()
                    );
                }
                let copy = backup_dir.join(format!("artifact-{index}"));
                fs::copy(destination, &copy)
                    .with_context(|| format!("back up {}", destination.display()))?;
                backups.push(Backup {
                    destination: destination.clone(),
                    copy: Some(copy),
                    mode: metadata.permissions().mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => backups.push(Backup {
                destination: destination.clone(),
                copy: None,
                mode: 0,
                uid: 0,
                gid: 0,
            }),
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", destination.display()));
            }
        }
    }
    Ok(backups)
}

fn install_artifact(candidate: &CandidateArtifact<'_>) -> Result<()> {
    let artifact = candidate.config;
    let parent = artifact
        .destination
        .parent()
        .context("artifact destination has no parent")?;
    if !parent.is_dir() {
        bail!("destination parent does not exist: {}", parent.display());
    }
    let previous = fs::metadata(&artifact.destination).ok();
    let file_name = artifact
        .destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("destination filename is not valid UTF-8")?;
    let temporary = parent.join(format!(
        ".{file_name}.random-utils-update-{}.new",
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    fs::copy(&candidate.path, &temporary)
        .with_context(|| format!("stage {}", artifact.destination.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(artifact.mode))
        .with_context(|| format!("chmod {}", temporary.display()))?;
    File::open(&temporary)?.sync_all()?;
    fs::rename(&temporary, &artifact.destination)
        .with_context(|| format!("atomically replace {}", artifact.destination.display()))?;

    let ownership = if artifact.owner.is_some() || artifact.group.is_some() {
        Some(chown_spec(
            artifact.owner.as_deref(),
            artifact.group.as_deref(),
        ))
    } else {
        previous.map(|metadata| format!("{}:{}", metadata.uid(), metadata.gid()))
    };
    if let Some(spec) = ownership {
        run_chown(&spec, &artifact.destination)?;
    }
    sync_parent(parent)?;
    Ok(())
}

fn restore_backup(backup: &Backup) -> Result<()> {
    if let Some(copy) = &backup.copy {
        let parent = backup
            .destination
            .parent()
            .context("backup destination has no parent")?;
        let file_name = backup
            .destination
            .file_name()
            .and_then(|name| name.to_str())
            .context("backup destination filename is not valid UTF-8")?;
        let temporary = parent.join(format!(
            ".{file_name}.random-utils-rollback-{}.new",
            std::process::id()
        ));
        let _ = fs::remove_file(&temporary);
        fs::copy(copy, &temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(backup.mode))?;
        File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, &backup.destination)?;
        run_chown(
            &format!("{}:{}", backup.uid, backup.gid),
            &backup.destination,
        )?;
        sync_parent(parent)?;
    } else if backup.destination.exists() {
        fs::remove_file(&backup.destination)
            .with_context(|| format!("remove newly installed {}", backup.destination.display()))?;
        if let Some(parent) = backup.destination.parent() {
            sync_parent(parent)?;
        }
    }
    Ok(())
}

fn chown_spec(owner: Option<&str>, group: Option<&str>) -> String {
    match (owner, group) {
        (Some(owner), Some(group)) => format!("{owner}:{group}"),
        (Some(owner), None) => owner.to_owned(),
        (None, Some(group)) => format!(":{group}"),
        (None, None) => String::new(),
    }
}

fn run_chown(spec: &str, path: &Path) -> Result<()> {
    let status = Command::new("chown")
        .arg("--")
        .arg(spec)
        .arg(path)
        .status()
        .with_context(|| format!("run chown on {}", path.display()))?;
    if !status.success() {
        bail!("chown {spec} {} failed with {status}", path.display());
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("open directory {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", parent.display()))
}

fn restart_units(units: &[String]) -> Result<()> {
    for unit in units {
        let status = Command::new("systemctl")
            .args(["restart", "--", unit])
            .status()
            .with_context(|| format!("restart systemd unit {unit}"))?;
        if !status.success() {
            bail!("systemctl restart {unit} failed with {status}");
        }
    }
    Ok(())
}

fn run_health_check(check: &HealthCheck, agent: &Agent, env: &[(String, String)]) -> Result<()> {
    match check {
        HealthCheck::Http {
            url,
            statuses,
            attempts,
            interval_ms,
            timeout_seconds,
        } => {
            for attempt in 0..*attempts {
                let response = agent
                    .get(url)
                    .config()
                    .timeout_global(Some(Duration::from_secs(*timeout_seconds)))
                    .http_status_as_error(false)
                    .build()
                    .call();
                if let Ok(response) = response {
                    let status = response.status().as_u16();
                    if statuses.is_empty() || statuses.contains(&status) {
                        return Ok(());
                    }
                }
                if attempt + 1 < *attempts {
                    thread::sleep(Duration::from_millis(*interval_ms));
                }
            }
            bail!("HTTP health check {url} did not reach an accepted status");
        }
        HealthCheck::SystemdActive {
            unit,
            attempts,
            interval_ms,
        } => {
            for attempt in 0..*attempts {
                let status = Command::new("systemctl")
                    .args(["is-active", "--quiet", "--", unit])
                    .status()
                    .with_context(|| format!("check systemd unit {unit}"))?;
                if status.success() {
                    return Ok(());
                }
                if attempt + 1 < *attempts {
                    thread::sleep(Duration::from_millis(*interval_ms));
                }
            }
            bail!("systemd unit {unit} did not become active");
        }
        HealthCheck::Command(spec) => match run_command(spec, env)? {
            CommandOutcome::Success => Ok(()),
            CommandOutcome::Deferred => bail!("health command returned a defer exit code"),
        },
    }
}

fn run_command(spec: &CommandSpec, env: &[(String, String)]) -> Result<CommandOutcome> {
    let package = env
        .iter()
        .find(|(name, _)| name == "RANDOM_UTILS_UPDATE_PACKAGE")
        .map_or("", |(_, value)| value.as_str());
    let tag = env
        .iter()
        .find(|(name, _)| name == "RANDOM_UTILS_UPDATE_TAG")
        .map_or("", |(_, value)| value.as_str());
    let mut command = Command::new(&spec.program);
    command.args(
        spec.args
            .iter()
            .map(|arg| expand_template(arg, package, tag, None)),
    );
    command.envs(env.iter().cloned());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", spec.program.display()))?;
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("wait for {}", spec.program.display()))?
        {
            return classify_exit(spec, status);
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .with_context(|| format!("kill timed out {}", spec.program.display()))?;
            let _ = child.wait();
            bail!(
                "command {} timed out after {} seconds",
                spec.program.display(),
                spec.timeout_seconds
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn classify_exit(spec: &CommandSpec, status: ExitStatus) -> Result<CommandOutcome> {
    let code = status.code().context("command terminated by signal")?;
    if spec.success_exit_codes.contains(&code) {
        Ok(CommandOutcome::Success)
    } else if spec.defer_exit_codes.contains(&code) {
        Ok(CommandOutcome::Deferred)
    } else {
        bail!("command {} exited with {code}", spec.program.display())
    }
}

fn command_env(package: &Package, tag: Option<&str>) -> Vec<(String, String)> {
    vec![
        (
            "RANDOM_UTILS_UPDATE_PACKAGE".to_owned(),
            package.name.clone(),
        ),
        (
            "RANDOM_UTILS_UPDATE_TAG".to_owned(),
            tag.unwrap_or_default().to_owned(),
        ),
    ]
}

fn expand_template(value: &str, package: &str, tag: &str, asset: Option<&str>) -> String {
    const PACKAGE_TOKEN: &str = concat!("{", "package", "}");
    const TAG_TOKEN: &str = concat!("{", "tag", "}");
    const ASSET_TOKEN: &str = concat!("{", "asset", "}");

    value
        .replace(PACKAGE_TOKEN, package)
        .replace(TAG_TOKEN, tag)
        .replace(ASSET_TOKEN, asset.unwrap_or_default())
}

fn state_path(state_dir: &Path, package: &str) -> PathBuf {
    state_dir.join(format!("{package}.json"))
}

fn load_state(path: &Path) -> Result<PackageState> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse state {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PackageState::default()),
        Err(error) => Err(error).with_context(|| format!("read state {}", path.display())),
    }
}

fn save_state(path: &Path, state: &PackageState) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("state filename is not UTF-8")?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let data = serde_json::to_vec_pretty(state)?;
    {
        let mut file = File::create(&temporary)?;
        file.write_all(&data)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    sync_parent(parent)?;
    Ok(())
}

const fn is_check_due(last_checked: u64, now: u64, min_interval: u64, force: bool) -> bool {
    force || last_checked == 0 || last_checked > now || now - last_checked >= min_interval
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::{expand_template, is_check_due, parse_sha256_manifest};

    #[test]
    fn parses_named_and_raw_sha256() -> anyhow::Result<()> {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_sha256_manifest(&format!("{hash}  thing\n"), "thing")?,
            hash
        );
        assert_eq!(parse_sha256_manifest(&format!("{hash}\n"), "thing")?, hash);
        Ok(())
    }

    #[test]
    fn scheduling_handles_clock_reversal_and_force() {
        assert!(is_check_due(0, 100, 60, false));
        assert!(!is_check_due(90, 100, 60, false));
        assert!(is_check_due(40, 100, 60, false));
        assert!(is_check_due(110, 100, 60, false));
        assert!(is_check_due(99, 100, 60, true));
    }

    #[test]
    fn expands_templates() {
        assert_eq!(
            expand_template("{package}-{tag}-{asset}", "p", "v1", Some("bin")),
            "p-v1-bin"
        );
    }
}
