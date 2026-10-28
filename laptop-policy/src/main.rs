//! Laptop policy daemon for ZFS-backed Linux build nodes.

use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use random_utils_observability::{
    Metrics, init_logging,
    tracing::{error, info},
};
use serde::{Deserialize, Serialize};

const DEFAULT_CONFIG_PATH: &str = "/etc/random-utils/laptop-policy.toml";
const METRICS_SPOOL: &str = "/var/lib/random-utils/laptop-policy-metrics-spool";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    poll_interval_seconds: u64,
    sync_disable_above_percent: u8,
    sync_restore_value: String,
    plugged_limit_after_hours: u64,
    unplugged_reset_after_minutes: u64,
    charge_limit_percent: u8,
    full_charge_percent: u8,
    hibernate_grace_seconds: u64,
    charge_reapply_seconds: u64,
    state_path: PathBuf,
    zfs_pools: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_seconds: 10,
            sync_disable_above_percent: 40,
            sync_restore_value: "standard".to_owned(),
            plugged_limit_after_hours: 48,
            unplugged_reset_after_minutes: 60,
            charge_limit_percent: 80,
            full_charge_percent: 100,
            hibernate_grace_seconds: 10,
            charge_reapply_seconds: 300,
            state_path: PathBuf::from("/var/lib/random-utils/laptop-policy-state.json"),
            zfs_pools: Vec::new(),
        }
    }
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.poll_interval_seconds == 0 {
            bail!("poll_interval_seconds must be greater than zero");
        }
        if self.sync_disable_above_percent > 100 {
            bail!("sync_disable_above_percent must be at most 100");
        }
        if self.charge_limit_percent > 100 || self.full_charge_percent > 100 {
            bail!("charge limits must be at most 100");
        }
        if self.charge_limit_percent >= self.full_charge_percent {
            bail!("charge_limit_percent must be below full_charge_percent");
        }
        if !matches!(self.sync_restore_value.as_str(), "standard" | "always") {
            bail!("sync_restore_value must be standard or always");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum PowerSource {
    External,
    Battery,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistentState {
    last_power_source: Option<PowerSource>,
    plugged_since_unix: Option<u64>,
    unplugged_since_unix: Option<u64>,
    charge_limited: bool,
    last_charge_write_unix: Option<u64>,
    last_observed_unix: Option<u64>,
}

impl PersistentState {
    fn observe_power(&mut self, source: PowerSource, now: u64) {
        if self
            .last_observed_unix
            .is_some_and(|previous| now < previous)
        {
            self.plugged_since_unix = None;
            self.unplugged_since_unix = None;
        }

        if self.last_power_source == Some(source) {
            match source {
                PowerSource::External if self.plugged_since_unix.is_none() => {
                    self.plugged_since_unix = Some(now);
                }
                PowerSource::Battery if self.unplugged_since_unix.is_none() => {
                    self.unplugged_since_unix = Some(now);
                }
                _ => {}
            }
        } else {
            match source {
                PowerSource::External => {
                    self.plugged_since_unix = Some(now);
                    self.unplugged_since_unix = None;
                }
                PowerSource::Battery => {
                    self.unplugged_since_unix = Some(now);
                    self.plugged_since_unix = None;
                }
            }
        }

        self.last_power_source = Some(source);
        self.last_observed_unix = Some(now);
    }

    fn desired_charge_limited(&self, config: &Config, now: u64) -> bool {
        let current = self.charge_limited;
        match self.last_power_source {
            Some(PowerSource::External) => {
                self.plugged_since_unix.is_some_and(|since| {
                    elapsed_at_least(
                        now,
                        since,
                        config.plugged_limit_after_hours.saturating_mul(3600),
                    )
                }) || current
            }
            Some(PowerSource::Battery) => {
                if self.unplugged_since_unix.is_some_and(|since| {
                    elapsed_at_least(
                        now,
                        since,
                        config.unplugged_reset_after_minutes.saturating_mul(60),
                    )
                }) {
                    false
                } else {
                    current
                }
            }
            None => current,
        }
    }
}

#[derive(Debug)]
struct Snapshot {
    battery_percent: Option<u8>,
    external_power: Option<bool>,
    lid_closed: Option<bool>,
    external_display_connected: bool,
}

#[derive(Debug, Clone)]
enum ChargeBackend {
    Generic(Vec<PathBuf>),
    AcerHealthMode(PathBuf),
}

impl ChargeBackend {
    fn detect() -> Option<Self> {
        let generic = battery_dirs()
            .unwrap_or_default()
            .into_iter()
            .map(|path| path.join("charge_control_end_threshold"))
            .filter(|path| path.exists())
            .collect::<Vec<_>>();
        if !generic.is_empty() {
            return Some(Self::Generic(generic));
        }

        let acer = PathBuf::from("/sys/bus/wmi/drivers/acer-wmi-battery/health_mode");
        acer.exists().then_some(Self::AcerHealthMode(acer))
    }

    fn matches_desired(&self, limited: bool, config: &Config) -> Option<bool> {
        match self {
            Self::Generic(paths) => {
                let target = if limited {
                    config.charge_limit_percent
                } else {
                    config.full_charge_percent
                };
                let values = paths
                    .iter()
                    .map(|path| read_trim(path).ok()?.parse::<u8>().ok())
                    .collect::<Option<Vec<_>>>()?;
                (!values.is_empty()).then(|| values.iter().all(|value| *value == target))
            }
            Self::AcerHealthMode(path) => read_trim(path)
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
                .map(|value| (value != 0) == limited),
        }
    }

    fn write_limit(&self, limited: bool, config: &Config, dry_run: bool) -> Result<()> {
        match self {
            Self::Generic(paths) => {
                let target = if limited {
                    config.charge_limit_percent
                } else {
                    config.full_charge_percent
                };
                for path in paths {
                    if dry_run {
                        log(format!("dry-run: write {target} to {}", path.display()));
                    } else {
                        fs::write(path, format!("{target}\n")).with_context(|| {
                            format!("writing charge limit to {}", path.display())
                        })?;
                    }
                }
            }
            Self::AcerHealthMode(path) => {
                let target = i32::from(limited);
                if dry_run {
                    log(format!("dry-run: write {target} to {}", path.display()));
                } else {
                    fs::write(path, format!("{target}\n")).with_context(|| {
                        format!("writing Acer health mode to {}", path.display())
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Args {
    config_path: PathBuf,
    once: bool,
    dry_run: bool,
}

fn main() -> ExitCode {
    init_logging();
    match run_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = ?error, "laptop-policy failed");
            ExitCode::FAILURE
        }
    }
}

fn run_main() -> Result<()> {
    let args = parse_args()?;
    let config = load_config(&args.config_path)?;
    config.validate()?;
    let mut state = load_state(&config.state_path).unwrap_or_default();
    let mut backend = ChargeBackend::detect();

    let pools = resolve_zfs_pools(&config)?;
    let mut metrics = Metrics::from_env("laptop-policy", "laptop_policy", Path::new(METRICS_SPOOL));
    if pools.is_empty() {
        log("no ZFS pool selected; sync policy is disabled".to_owned());
    } else {
        log(format!("managing ZFS pools: {}", pools.join(", ")));
    }

    if backend.is_none() {
        log("no supported battery charge-limit backend detected; charge-limit policy will be skipped".to_owned());
    }

    let mut hibernate_candidate_since: Option<Instant> = None;
    let mut hibernate_latched = false;

    loop {
        if backend.is_none() {
            backend = ChargeBackend::detect();
        }

        let now = unix_now()?;
        let snapshot = read_snapshot();
        apply_sync_policy(&snapshot, &config, &pools, args.dry_run)?;
        apply_charge_policy(
            &snapshot,
            &config,
            &mut state,
            backend.as_ref(),
            now,
            args.dry_run,
        )?;
        apply_hibernate_policy(
            &snapshot,
            &config,
            &mut hibernate_candidate_since,
            &mut hibernate_latched,
            args.dry_run,
        )?;
        save_state(&config.state_path, &state, args.dry_run)?;
        metrics.publish_snapshot(render_metrics(MetricContext {
            snapshot: &snapshot,
            state: &state,
            pools: &pools,
            hibernate_candidate_since,
            config: &config,
            dry_run: args.dry_run,
        }));

        if args.once {
            metrics.flush();
            break;
        }
        thread::sleep(Duration::from_secs(config.poll_interval_seconds));
    }

    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut once = false;
    let mut dry_run = false;
    let mut args = env::args_os().skip(1);

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--config requires a path"))?;
                config_path = PathBuf::from(value);
            }
            "--once" => once = true,
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                println!(
                    "Usage: laptop-policy [--config PATH] [--once] [--dry-run]\n\
                     Defaults to {DEFAULT_CONFIG_PATH}."
                );
                std::process::exit(0);
            }
            unknown => bail!("unknown argument: {unknown}"),
        }
    }

    Ok(Args {
        config_path,
        once,
        dry_run,
    })
}

fn load_config(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading configuration from {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing configuration from {}", path.display()))
}

fn read_snapshot() -> Snapshot {
    Snapshot {
        battery_percent: aggregate_battery_percent().ok().flatten(),
        external_power: external_power_online().ok().flatten(),
        lid_closed: lid_closed().ok().flatten(),
        external_display_connected: external_display_connected().unwrap_or(false),
    }
}

fn battery_dirs() -> Result<Vec<PathBuf>> {
    let root = Path::new("/sys/class/power_supply");
    let mut batteries = Vec::new();
    for entry in fs::read_dir(root).context("reading /sys/class/power_supply")? {
        let entry = entry.context("reading power-supply directory entry")?;
        let path = entry.path();
        if matches!(read_trim(&path.join("type")).as_deref(), Ok("Battery"))
            && read_trim(&path.join("present")).map_or(true, |value| value != "0")
        {
            batteries.push(path);
        }
    }
    Ok(batteries)
}

fn aggregate_battery_percent() -> Result<Option<u8>> {
    let batteries = battery_dirs()?;
    if batteries.is_empty() {
        return Ok(None);
    }

    for (now_name, full_name) in [("energy_now", "energy_full"), ("charge_now", "charge_full")] {
        let mut total_now = 0_u128;
        let mut total_full = 0_u128;
        let mut complete = true;
        for battery in &batteries {
            match (
                read_u64(&battery.join(now_name)),
                read_u64(&battery.join(full_name)),
            ) {
                (Ok(now), Ok(full)) if full > 0 => {
                    total_now = total_now.saturating_add(u128::from(now));
                    total_full = total_full.saturating_add(u128::from(full));
                }
                _ => {
                    complete = false;
                    break;
                }
            }
        }
        if complete && total_full > 0 {
            let percent = total_now.saturating_mul(100).saturating_add(total_full / 2) / total_full;
            return Ok(Some(
                u8::try_from(percent.min(100)).context("battery percentage conversion")?,
            ));
        }
    }

    let percentages = batteries
        .iter()
        .filter_map(|path| battery_percent(path).ok().flatten())
        .map(u32::from)
        .collect::<Vec<_>>();
    if percentages.is_empty() {
        return Ok(None);
    }
    let sum = percentages.iter().sum::<u32>();
    let count = u32::try_from(percentages.len()).context("too many battery devices")?;
    let rounded = (sum + count / 2) / count;
    Ok(Some(
        u8::try_from(rounded).context("battery percentage out of range")?,
    ))
}

fn battery_percent(path: &Path) -> Result<Option<u8>> {
    if let Ok(capacity) = read_trim(&path.join("capacity")) {
        return capacity
            .parse::<u8>()
            .map(Some)
            .context("parsing battery capacity");
    }

    for (now_name, full_name) in [("energy_now", "energy_full"), ("charge_now", "charge_full")] {
        let now = read_u64(&path.join(now_name));
        let full = read_u64(&path.join(full_name));
        if let (Ok(now), Ok(full)) = (now, full)
            && full > 0
        {
            let percent = now.saturating_mul(100).saturating_add(full / 2) / full;
            return Ok(Some(
                u8::try_from(percent.min(100)).context("battery percentage conversion")?,
            ));
        }
    }
    Ok(None)
}

fn external_power_online() -> Result<Option<bool>> {
    let root = Path::new("/sys/class/power_supply");
    let mut mains = Vec::new();
    let mut fallback = Vec::new();
    for entry in fs::read_dir(root).context("reading /sys/class/power_supply")? {
        let entry = entry.context("reading power-supply directory entry")?;
        let path = entry.path();
        let supply_type = read_trim(&path.join("type")).unwrap_or_default();
        let online = read_trim(&path.join("online"))
            .ok()
            .map(|value| value == "1");
        let Some(online) = online else { continue };
        if supply_type == "Mains" {
            mains.push(online);
        } else if matches!(supply_type.as_str(), "USB" | "USB_C" | "USB_PD") {
            fallback.push(online);
        }
    }
    if !mains.is_empty() {
        Ok(Some(mains.into_iter().any(|online| online)))
    } else if !fallback.is_empty() {
        Ok(Some(fallback.into_iter().any(|online| online)))
    } else {
        Ok(None)
    }
}

fn lid_closed() -> Result<Option<bool>> {
    let root = Path::new("/proc/acpi/button/lid");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("reading ACPI lid directory"),
    };
    let mut states = Vec::new();
    for entry in entries {
        let entry = entry.context("reading lid directory entry")?;
        let state_path = entry.path().join("state");
        if let Ok(state) = read_trim(&state_path) {
            if state.contains("closed") {
                states.push(true);
            } else if state.contains("open") {
                states.push(false);
            }
        }
    }
    Ok((!states.is_empty()).then(|| states.into_iter().all(|closed| closed)))
}

fn external_display_connected() -> Result<bool> {
    let root = Path::new("/sys/class/drm");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reading DRM connector directory"),
    };
    for entry in entries {
        let entry = entry.context("reading DRM directory entry")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let status_path = entry.path().join("status");
        if !status_path.exists() || is_internal_connector(&name) || name.contains("Writeback") {
            continue;
        }
        if matches!(read_trim(&status_path).as_deref(), Ok("connected")) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_internal_connector(name: &str) -> bool {
    let uppercase = name.to_ascii_uppercase();
    ["-EDP-", "-LVDS-", "-DSI-"]
        .iter()
        .any(|marker| uppercase.contains(marker))
}

fn apply_sync_policy(
    snapshot: &Snapshot,
    config: &Config,
    pools: &[String],
    dry_run: bool,
) -> Result<()> {
    let Some(percent) = snapshot.battery_percent else {
        log("battery capacity unavailable; leaving ZFS sync policy unchanged".to_owned());
        return Ok(());
    };
    let desired = if percent > config.sync_disable_above_percent {
        "disabled"
    } else {
        config.sync_restore_value.as_str()
    };
    for pool in pools {
        let current = command_stdout("zfs", ["get", "-H", "-o", "value", "sync", pool])?;
        if current.trim() == desired {
            continue;
        }
        if dry_run {
            log(format!(
                "dry-run: zfs set sync={desired} {pool} (battery {percent}%)"
            ));
        } else {
            command_success("zfs", ["set", &format!("sync={desired}"), pool])?;
            log(format!("set {pool} sync={desired} at battery {percent}%"));
        }
    }
    Ok(())
}

fn apply_charge_policy(
    snapshot: &Snapshot,
    config: &Config,
    state: &mut PersistentState,
    backend: Option<&ChargeBackend>,
    now: u64,
    dry_run: bool,
) -> Result<()> {
    let Some(external_power) = snapshot.external_power else {
        log("external-power state unavailable; charge timer paused".to_owned());
        return Ok(());
    };
    let source = if external_power {
        PowerSource::External
    } else {
        PowerSource::Battery
    };
    state.observe_power(source, now);

    let Some(backend) = backend else {
        return Ok(());
    };
    let desired_limited = state.desired_charge_limited(config, now);
    let matches_desired = backend.matches_desired(desired_limited, config);
    let due_for_reapply = state
        .last_charge_write_unix
        .is_none_or(|last| elapsed_at_least(now, last, config.charge_reapply_seconds));
    let needs_write = matches_desired.map_or(due_for_reapply, |matches| !matches);

    if needs_write {
        backend.write_limit(desired_limited, config, dry_run)?;
        if !dry_run {
            state.last_charge_write_unix = Some(now);
            log(format!(
                "set battery charge mode to {}",
                if desired_limited { "limited" } else { "full" }
            ));
        }
    }
    state.charge_limited = desired_limited;
    Ok(())
}

fn apply_hibernate_policy(
    snapshot: &Snapshot,
    config: &Config,
    candidate_since: &mut Option<Instant>,
    latched: &mut bool,
    dry_run: bool,
) -> Result<()> {
    let condition = snapshot.external_power == Some(false)
        && snapshot.lid_closed == Some(true)
        && !snapshot.external_display_connected;

    if !condition {
        *candidate_since = None;
        *latched = false;
        return Ok(());
    }
    if *latched {
        return Ok(());
    }
    let since = candidate_since.get_or_insert_with(Instant::now);
    if since.elapsed() < Duration::from_secs(config.hibernate_grace_seconds) {
        return Ok(());
    }
    if !hibernate_supported() {
        log(
            "hibernate condition met, but resume is not configured; refusing to hibernate"
                .to_owned(),
        );
        *latched = true;
        return Ok(());
    }

    *latched = true;
    if dry_run {
        log(
            "dry-run: would hibernate (battery power + closed lid + no external display)"
                .to_owned(),
        );
        return Ok(());
    }
    log("hibernating: battery power + closed lid + no external display".to_owned());
    command_success("systemctl", ["hibernate"])
}

fn hibernate_supported() -> bool {
    let states = read_trim(Path::new("/sys/power/state")).unwrap_or_default();
    if !states.split_whitespace().any(|state| state == "disk") {
        return false;
    }
    let resume = read_trim(Path::new("/sys/power/resume")).unwrap_or_default();
    if resume.is_empty() || resume == "0:0" {
        return false;
    }

    Command::new("busctl")
        .args([
            "call",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "CanHibernate",
        ])
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "s \"yes\""
        })
}

fn resolve_zfs_pools(config: &Config) -> Result<Vec<String>> {
    if !config.zfs_pools.is_empty() {
        return Ok(config.zfs_pools.clone());
    }
    let source = command_stdout("findmnt", ["-n", "-o", "SOURCE", "/"])?;
    let source = source.trim();
    let Some((pool, _)) = source.split_once('/') else {
        return Ok(Vec::new());
    };
    Ok(vec![pool.to_owned()])
}

fn load_state(path: &Path) -> Result<PersistentState> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("parsing state file {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PersistentState::default()),
        Err(error) => Err(error).with_context(|| format!("reading state file {}", path.display())),
    }
}

fn save_state(path: &Path, state: &PersistentState, dry_run: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating state directory {}", parent.display()))?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(OsString::from(".tmp"));
    let temporary = PathBuf::from(temporary);
    let data = serde_json::to_vec_pretty(state).context("serializing persistent state")?;
    fs::write(&temporary, data)
        .with_context(|| format!("writing temporary state file {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("committing state file {}", path.display()))?;
    Ok(())
}

fn read_trim(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .with_context(|| format!("reading {}", path.display()))
}

fn read_u64(path: &Path) -> Result<u64> {
    read_trim(path)?
        .parse::<u64>()
        .with_context(|| format!("parsing integer from {}", path.display()))
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

const fn elapsed_at_least(now: u64, since: u64, required: u64) -> bool {
    now.saturating_sub(since) >= required
}

fn command_stdout<const N: usize>(program: &str, args: [&str; N]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    output_to_stdout(program, output)
}

fn command_success<const N: usize>(program: &str, args: [&str; N]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{program} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

fn output_to_stdout(program: &str, output: Output) -> Result<String> {
    if !output.status.success() {
        bail!(
            "{program} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("{program} emitted non-UTF-8 stdout"))
}

fn log(message: impl std::fmt::Display) {
    info!(event = %message, "policy event");
}

#[derive(Clone, Copy)]
struct MetricContext<'a> {
    snapshot: &'a Snapshot,
    state: &'a PersistentState,
    pools: &'a [String],
    hibernate_candidate_since: Option<Instant>,
    config: &'a Config,
    dry_run: bool,
}

fn render_metrics(context: MetricContext<'_>) -> String {
    let MetricContext {
        snapshot,
        state,
        pools,
        hibernate_candidate_since,
        config,
        dry_run,
    } = context;
    let charge_limit_desired = if state.charge_limited {
        config.charge_limit_percent
    } else {
        config.full_charge_percent
    };
    let mut text = format!(
        concat!(
            "laptop_policy_charge_limit_desired_percent {}\n",
            "laptop_policy_hibernate_candidate {}\n",
            "laptop_policy_dry_run {}\n"
        ),
        charge_limit_desired,
        u8::from(hibernate_candidate_since.is_some()),
        u8::from(dry_run),
    );
    if !pools.is_empty()
        && let Some(percent) = snapshot.battery_percent
    {
        let _ = writeln!(
            text,
            "laptop_policy_zfs_sync_disabled_desired {}",
            u8::from(percent > config.sync_disable_above_percent)
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{
        Config, MetricContext, PersistentState, PowerSource, Snapshot, elapsed_at_least,
        is_internal_connector, render_metrics,
    };

    #[test]
    fn charge_limit_requires_full_plugged_window() {
        let config = Config::default();
        let mut state = PersistentState::default();
        state.observe_power(PowerSource::External, 1_000);
        assert!(!state.desired_charge_limited(&config, 1_000 + 47 * 3600));
        assert!(state.desired_charge_limited(&config, 1_000 + 48 * 3600));
    }

    #[test]
    fn one_hour_unplugged_clears_existing_limit() {
        let config = Config::default();
        let mut state = PersistentState {
            charge_limited: true,
            ..PersistentState::default()
        };
        state.observe_power(PowerSource::Battery, 50_000);
        assert!(state.desired_charge_limited(&config, 50_000 + 3599));
        assert!(!state.desired_charge_limited(&config, 50_000 + 3600));
    }

    #[test]
    fn brief_unplug_does_not_preserve_continuous_plug_timer() {
        let config = Config::default();
        let mut state = PersistentState::default();
        state.observe_power(PowerSource::External, 0);
        state.observe_power(PowerSource::Battery, 10_000);
        state.observe_power(PowerSource::External, 10_100);
        assert!(!state.desired_charge_limited(&config, 10_100 + 47 * 3600));
    }

    #[test]
    fn established_limit_survives_brief_unplug_until_reset_window() {
        let config = Config::default();
        let mut state = PersistentState {
            charge_limited: true,
            ..PersistentState::default()
        };
        state.observe_power(PowerSource::Battery, 20_000);
        assert!(state.desired_charge_limited(&config, 20_000 + 3599));
        state.observe_power(PowerSource::External, 23_500);
        assert!(state.desired_charge_limited(&config, 23_500));
    }

    #[test]
    fn drm_internal_connector_detection_is_case_insensitive() {
        assert!(is_internal_connector("card1-eDP-1"));
        assert!(is_internal_connector("card0-LVDS-1"));
        assert!(!is_internal_connector("card1-HDMI-A-1"));
        assert!(!is_internal_connector("card0-DP-2"));
    }

    #[test]
    fn elapsed_handles_clock_reversal_safely() {
        assert!(!elapsed_at_least(10, 20, 1));
        assert!(elapsed_at_least(20, 10, 10));
    }

    #[test]
    fn metrics_snapshot_is_stable_for_unchanged_policy_state() {
        let config = Config::default();
        let snapshot = Snapshot {
            battery_percent: Some(80),
            external_power: Some(true),
            lid_closed: Some(false),
            external_display_connected: false,
        };
        let state = PersistentState {
            last_power_source: Some(PowerSource::External),
            plugged_since_unix: Some(1_234),
            ..PersistentState::default()
        };
        let pools = vec!["rpool".to_owned()];
        let rendered = render_metrics(MetricContext {
            snapshot: &snapshot,
            state: &state,
            pools: &pools,
            hibernate_candidate_since: None,
            config: &config,
            dry_run: false,
        });
        assert!(rendered.contains("laptop_policy_charge_limit_desired_percent 100\n"));
        assert!(rendered.contains("laptop_policy_zfs_sync_disabled_desired 1\n"));
        assert!(rendered.contains("laptop_policy_hibernate_candidate 0\n"));
        assert!(!rendered.contains("battery_percent"));
        assert!(!rendered.contains("external_power"));
        assert!(!rendered.contains("lid_closed"));
        assert!(!rendered.contains("external_display"));
        assert!(!rendered.contains("power_source_since"));
        assert!(!rendered.contains("laptop_policy_up"));
    }
}
