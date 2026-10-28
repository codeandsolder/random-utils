use anyhow::{Context, Result, bail};
use nix::{
    errno::Errno,
    sys::signal::{Signal, kill},
    unistd::{Pid, SysconfVar, sysconf},
};
use random_utils_observability::{
    Metrics, init_logging,
    tracing::{debug, error, info, warn},
};
use std::{
    collections::BTreeSet,
    env, fs, io,
    path::Path,
    process::{self, ExitCode},
    time::{Duration, Instant},
};

const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);
const DEFAULT_NAMES: &[&str] = &[
    "ack", "ag", "bfs", "du", "fd", "fdfind", "fgrep", "find", "grep", "rgrep", "rg", "ripgrep",
    "tree",
];
const CMDLINE_LOG_LIMIT: usize = 400;
const METRICS_SPOOL: &str = "/var/lib/random-utils/crawl-killer-metrics-spool";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    max_age: Duration,
    names: BTreeSet<String>,
    dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Run(Config),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcIdentity {
    comm: String,
    start_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct ScanStats {
    matched: u64,
    killed: u64,
    failures: u64,
    oldest_match_age: Duration,
    scan_duration: Duration,
}

impl ScanStats {
    fn prometheus(self, dry_run: bool) -> String {
        format!(
            concat!(
                "crawl_killer_matched {}\n",
                "crawl_killer_killed {}\n",
                "crawl_killer_failures {}\n",
                "crawl_killer_oldest_match_age_seconds {}\n",
                "crawl_killer_scan_duration_seconds {}\n",
                "crawl_killer_dry_run {}\n"
            ),
            self.matched,
            self.killed,
            self.failures,
            self.oldest_match_age.as_secs_f64(),
            self.scan_duration.as_secs_f64(),
            u8::from(dry_run),
        )
    }
}

fn main() -> ExitCode {
    init_logging();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = ?error, "crawl-killer failed");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<()> {
    match parse_args(env::args().skip(1))? {
        Action::Help => {
            print_help();
            Ok(())
        }
        Action::Run(config) => {
            let metrics =
                Metrics::from_env("crawl-killer", "crawl_killer", Path::new(METRICS_SPOOL));
            let stats = run(&config)?;
            metrics.publish_now(&stats.prometheus(config.dry_run));
            metrics.flush();
            if stats.failures > 0 {
                bail!(
                    "failed to inspect or kill {} matching process(es)",
                    stats.failures
                );
            }
            Ok(())
        }
    }
}

fn parse_args<I>(args: I) -> Result<Action>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut max_age = DEFAULT_MAX_AGE;
    let mut custom_names = BTreeSet::new();
    let mut dry_run = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Action::Help),
            "--dry-run" => dry_run = true,
            "--max-age-seconds" => {
                let raw = args
                    .next()
                    .context("--max-age-seconds requires an integer value")?;
                let seconds = raw
                    .parse::<u64>()
                    .with_context(|| format!("invalid --max-age-seconds value: {raw}"))?;
                if seconds == 0 {
                    bail!("--max-age-seconds must be greater than zero");
                }
                max_age = Duration::from_secs(seconds);
            }
            "--name" => {
                let name = args.next().context("--name requires a process name")?;
                if name.is_empty() {
                    bail!("--name cannot be empty");
                }
                custom_names.insert(name);
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }

    let names = if custom_names.is_empty() {
        DEFAULT_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        custom_names
    };

    Ok(Action::Run(Config {
        max_age,
        names,
        dry_run,
    }))
}

fn print_help() {
    println!(
        "crawl-killer — kill accidentally long-running filesystem crawlers\n\
         \n\
         Usage: crawl-killer [OPTIONS]\n\
         \n\
         Options:\n\
           --max-age-seconds N  Kill matching processes at least N seconds old [default: 300]\n\
           --name NAME          Replace the default target set with repeated explicit names\n\
           --dry-run            Report matching processes without signalling them\n\
           -h, --help           Show this help\n\
         \n\
         Default targets: {}",
        DEFAULT_NAMES.join(", ")
    );
}

fn run(config: &Config) -> Result<ScanStats> {
    let started = Instant::now();
    let uptime = read_uptime()?;
    let clock_ticks = clock_ticks_per_second()?;
    let own_pid = i32::try_from(process::id()).context("own PID does not fit in i32")?;
    let mut stats = ScanStats {
        matched: 0,
        killed: 0,
        failures: 0,
        oldest_match_age: Duration::ZERO,
        scan_duration: Duration::ZERO,
    };

    for entry in fs::read_dir("/proc").context("failed to read /proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, "failed to read a /proc entry");
                continue;
            }
        };
        let Some(pid) = numeric_pid(&entry.file_name()) else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let outcome = inspect_process(config, pid, uptime, clock_ticks);
        if outcome.matched {
            stats.matched += 1;
            stats.oldest_match_age = stats.oldest_match_age.max(outcome.age);
        }
        stats.killed += u64::from(outcome.killed);
        stats.failures += u64::from(outcome.failed);
    }

    stats.scan_duration = started.elapsed();
    if stats.matched > 0 || stats.failures > 0 || config.dry_run {
        info!(
            matched = stats.matched,
            killed = stats.killed,
            failures = stats.failures,
            dry_run = config.dry_run,
            scan_duration_seconds = stats.scan_duration.as_secs_f64(),
            "scan complete"
        );
    } else {
        debug!(
            scan_duration_seconds = stats.scan_duration.as_secs_f64(),
            "clean scan complete"
        );
    }
    Ok(stats)
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessOutcome {
    matched: bool,
    killed: bool,
    failed: bool,
    age: Duration,
}

fn inspect_process(
    config: &Config,
    pid: i32,
    uptime: Duration,
    clock_ticks: u64,
) -> ProcessOutcome {
    let identity = match read_identity(pid) {
        Ok(identity) => identity,
        Err(error) if transient_proc_error(&error) => return ProcessOutcome::default(),
        Err(error) => {
            warn!(pid, %error, "cannot inspect process");
            return ProcessOutcome::default();
        }
    };
    if !config.names.contains(&identity.comm) {
        return ProcessOutcome::default();
    }

    let started_at = duration_from_ticks(identity.start_ticks, clock_ticks);
    let age = uptime.saturating_sub(started_at);
    if age < config.max_age {
        return ProcessOutcome::default();
    }

    let mut outcome = ProcessOutcome {
        matched: true,
        age,
        ..ProcessOutcome::default()
    };
    let cmdline = read_cmdline(pid);
    if config.dry_run {
        info!(
            pid,
            age_seconds = age.as_secs(),
            comm = identity.comm,
            cmdline,
            action = "would_kill",
            "stale crawler matched"
        );
        return outcome;
    }

    match read_identity(pid) {
        Ok(current) if current == identity => {}
        Ok(_) => {
            info!(pid, "process identity changed during scan; skipping");
            return outcome;
        }
        Err(error) if transient_proc_error(&error) => return outcome,
        Err(error) => {
            warn!(pid, %error, "cannot re-check process identity");
            outcome.failed = true;
            return outcome;
        }
    }

    match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) => {
            outcome.killed = true;
            info!(
                pid,
                age_seconds = age.as_secs(),
                comm = identity.comm,
                cmdline,
                action = "killed",
                "stale crawler killed"
            );
        }
        Err(Errno::ESRCH) => {}
        Err(error) => {
            outcome.failed = true;
            warn!(
                pid,
                age_seconds = age.as_secs(),
                comm = identity.comm,
                %error,
                "failed to kill stale crawler"
            );
        }
    }
    outcome
}

fn numeric_pid(name: &std::ffi::OsStr) -> Option<i32> {
    name.to_str()?.parse::<i32>().ok().filter(|pid| *pid > 0)
}

fn read_identity(pid: i32) -> io::Result<ProcIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_stat(&stat).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed /proc/{pid}/stat"),
        )
    })
}

fn parse_proc_stat(stat: &str) -> Option<ProcIdentity> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }

    let comm = stat.get(open + 1..close)?.to_owned();
    let start_ticks = stat
        .get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()?;

    Some(ProcIdentity { comm, start_ticks })
}

fn transient_proc_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn read_uptime() -> Result<Duration> {
    let raw = fs::read_to_string("/proc/uptime").context("failed to read /proc/uptime")?;
    let uptime = raw
        .split_whitespace()
        .next()
        .context("/proc/uptime is empty")?;
    parse_decimal_duration(uptime).context("invalid uptime in /proc/uptime")
}

fn parse_decimal_duration(value: &str) -> Result<Duration> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds = whole
        .parse::<u64>()
        .with_context(|| format!("invalid whole seconds: {value}"))?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid fractional seconds: {value}");
    }

    let mut nanos = 0_u64;
    let mut place = 100_000_000_u64;
    for digit in fraction.bytes().take(9) {
        nanos += u64::from(digit - b'0') * place;
        place /= 10;
    }

    Ok(Duration::from_secs(seconds) + Duration::from_nanos(nanos))
}

fn clock_ticks_per_second() -> Result<u64> {
    let ticks = sysconf(SysconfVar::CLK_TCK)
        .context("sysconf(_SC_CLK_TCK) failed")?
        .context("sysconf(_SC_CLK_TCK) returned no value")?;
    let ticks = u64::try_from(ticks).context("_SC_CLK_TCK is negative")?;
    if ticks == 0 {
        bail!("_SC_CLK_TCK is zero");
    }
    Ok(ticks)
}

fn duration_from_ticks(ticks: u64, ticks_per_second: u64) -> Duration {
    let seconds = ticks / ticks_per_second;
    let remainder = ticks % ticks_per_second;
    let nanos = remainder.saturating_mul(1_000_000_000) / ticks_per_second;
    Duration::from_secs(seconds) + Duration::from_nanos(nanos)
}

fn read_cmdline(pid: i32) -> String {
    let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return "<unavailable>".to_owned();
    };

    let normalized: String = String::from_utf8_lossy(&raw)
        .chars()
        .map(|character| {
            if character == '\0' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return "<empty>".to_owned();
    }

    let mut chars = normalized.chars();
    let mut result: String = chars.by_ref().take(CMDLINE_LOG_LIMIT).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_comm() -> Result<()> {
        let stat = "123 (strange ) process) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20";
        let parsed = parse_proc_stat(stat).context("failed to parse fixture")?;
        assert_eq!(
            parsed,
            ProcIdentity {
                comm: "strange ) process".to_owned(),
                start_ticks: 4242,
            }
        );
        Ok(())
    }

    #[test]
    fn decimal_duration_parses_fraction_without_float_rounding() -> Result<()> {
        assert_eq!(
            parse_decimal_duration("123.45")?,
            Duration::from_secs(123) + Duration::from_millis(450)
        );
        assert_eq!(
            parse_decimal_duration("0.000000001")?,
            Duration::from_nanos(1)
        );
        Ok(())
    }

    #[test]
    fn ticks_convert_to_duration() {
        assert_eq!(
            duration_from_ticks(12_345, 100),
            Duration::from_secs(123) + Duration::from_millis(450)
        );
    }

    #[test]
    fn explicit_names_replace_the_default_set() -> Result<()> {
        let action = parse_args([
            "--max-age-seconds".to_owned(),
            "42".to_owned(),
            "--name".to_owned(),
            "sleep".to_owned(),
            "--name".to_owned(),
            "bash".to_owned(),
            "--dry-run".to_owned(),
        ])?;
        assert_eq!(
            action,
            Action::Run(Config {
                max_age: Duration::from_secs(42),
                names: BTreeSet::from(["bash".to_owned(), "sleep".to_owned()]),
                dry_run: true,
            })
        );
        Ok(())
    }

    #[test]
    fn metrics_snapshot_contains_scan_state() {
        let text = ScanStats {
            matched: 2,
            killed: 1,
            failures: 0,
            oldest_match_age: Duration::from_secs(600),
            scan_duration: Duration::from_millis(250),
        }
        .prometheus(false);
        assert!(text.contains("crawl_killer_matched 2\n"));
        assert!(text.contains("crawl_killer_killed 1\n"));
        assert!(text.contains("crawl_killer_oldest_match_age_seconds 600\n"));
        assert!(!text.contains("last_run_unixtime"));
        assert!(text.contains("crawl_killer_dry_run 0\n"));
    }
}
