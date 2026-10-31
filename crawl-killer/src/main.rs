use anyhow::{Context, Result, bail};
use nix::{
    errno::Errno,
    sys::signal::{Signal, killpg},
    unistd::{Pid, SysconfVar, sysconf},
};
use random_utils_observability::{
    Metrics, init_logging,
    tracing::{debug, error, info, warn},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
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
const JOB_STATE_PATH: &str = "/var/lib/random-utils/crawl-killer-jobs-v1";

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
    process_group: i32,
    session: i32,
    start_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSnapshot {
    pid: i32,
    identity: ProcIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct JobKey {
    process_group: i32,
    session: i32,
    leader_start_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveJob {
    key: JobKey,
    oldest_crawler_start_ticks: u64,
    representative: ProcessSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrawlJob {
    active: ActiveJob,
    first_seen_seconds: u64,
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
                    "failed to inspect or kill {} crawler job(s)",
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
        "crawl-killer — kill accidentally long-running filesystem crawl jobs\n\
         \n\
         Usage: crawl-killer [OPTIONS]\n\
         \n\
         Options:\n\
           --max-age-seconds N  Kill crawl jobs continuously containing a target for N seconds [default: 300]\n\
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
    let boot_id = read_boot_id()?;
    let own_pid = i32::try_from(process::id()).context("own PID does not fit in i32")?;
    let mut processes = Vec::new();
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
        match read_identity(pid) {
            Ok(identity) if identity.process_group > 0 && identity.session > 0 => {
                processes.push(ProcessSnapshot { pid, identity });
            }
            Ok(_) => {}
            Err(error) if transient_proc_error(&error) => {}
            Err(error) => warn!(pid, %error, "cannot inspect process"),
        }
    }

    let active_jobs = find_active_jobs(config, &processes);
    let state_path = job_state_path(config);
    let previous_state = match load_job_state(&state_path, &boot_id) {
        Ok(job_state) => job_state,
        Err(error) => {
            warn!(%error, "cannot load crawler job state; starting fresh");
            stats.failures += 1;
            BTreeMap::new()
        }
    };
    let (stale_jobs, next_state) =
        update_job_state(config, &active_jobs, &previous_state, uptime, clock_ticks);

    if !config.dry_run
        && let Err(error) = write_job_state(&state_path, &boot_id, &next_state)
    {
        warn!(%error, "cannot persist crawler job state");
        stats.failures += 1;
    }

    for job in stale_jobs {
        let outcome = inspect_job(config, &job, uptime, clock_ticks);
        stats.matched += u64::from(outcome.matched);
        stats.killed += u64::from(outcome.killed);
        stats.failures += u64::from(outcome.failed);
        stats.oldest_match_age = stats.oldest_match_age.max(outcome.age);
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

fn find_active_jobs(config: &Config, processes: &[ProcessSnapshot]) -> Vec<ActiveJob> {
    let mut groups = BTreeMap::<(i32, i32), (u64, Option<u64>)>::new();
    for process in processes {
        let group = (process.identity.process_group, process.identity.session);
        groups
            .entry(group)
            .and_modify(|(oldest, leader)| {
                *oldest = (*oldest).min(process.identity.start_ticks);
                if process.pid == process.identity.process_group {
                    *leader = Some(process.identity.start_ticks);
                }
            })
            .or_insert_with(|| {
                (
                    process.identity.start_ticks,
                    (process.pid == process.identity.process_group)
                        .then_some(process.identity.start_ticks),
                )
            });
    }

    let mut jobs = BTreeMap::<JobKey, ActiveJob>::new();
    for process in processes {
        if !config.names.contains(&process.identity.comm) {
            continue;
        }
        let group = (process.identity.process_group, process.identity.session);
        let Some((oldest_start_ticks, leader_start_ticks)) = groups.get(&group).copied() else {
            continue;
        };
        let key = JobKey {
            process_group: process.identity.process_group,
            session: process.identity.session,
            leader_start_ticks: leader_start_ticks.unwrap_or(oldest_start_ticks),
        };
        jobs.entry(key)
            .and_modify(|job| {
                if process.identity.start_ticks < job.oldest_crawler_start_ticks {
                    job.oldest_crawler_start_ticks = process.identity.start_ticks;
                    job.representative = process.clone();
                }
            })
            .or_insert_with(|| ActiveJob {
                key,
                oldest_crawler_start_ticks: process.identity.start_ticks,
                representative: process.clone(),
            });
    }
    jobs.into_values().collect()
}

fn update_job_state(
    config: &Config,
    active_jobs: &[ActiveJob],
    previous_state: &BTreeMap<JobKey, u64>,
    uptime: Duration,
    clock_ticks: u64,
) -> (Vec<CrawlJob>, BTreeMap<JobKey, u64>) {
    let now_seconds = uptime.as_secs();
    let mut stale_jobs = Vec::new();
    let mut next_state = BTreeMap::new();

    for active in active_jobs {
        let crawler_started_seconds =
            duration_from_ticks(active.oldest_crawler_start_ticks, clock_ticks).as_secs();
        let first_seen_seconds = previous_state
            .get(&active.key)
            .copied()
            .unwrap_or(crawler_started_seconds)
            .min(crawler_started_seconds);
        next_state.insert(active.key, first_seen_seconds);

        if now_seconds.saturating_sub(first_seen_seconds) >= config.max_age.as_secs() {
            stale_jobs.push(CrawlJob {
                active: active.clone(),
                first_seen_seconds,
            });
        }
    }

    (stale_jobs, next_state)
}

fn inspect_job(
    config: &Config,
    job: &CrawlJob,
    uptime: Duration,
    clock_ticks: u64,
) -> ProcessOutcome {
    let pid = job.active.representative.pid;
    let identity = &job.active.representative.identity;
    let age = Duration::from_secs(uptime.as_secs().saturating_sub(job.first_seen_seconds));
    let crawler_started_at = duration_from_ticks(identity.start_ticks, clock_ticks);
    let crawler_age = uptime.saturating_sub(crawler_started_at);
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
            crawler_age_seconds = crawler_age.as_secs(),
            process_group = job.active.key.process_group,
            session = job.active.key.session,
            comm = identity.comm.as_str(),
            cmdline,
            action = "would_kill",
            "stale crawler job matched"
        );
        return outcome;
    }

    match read_identity(pid) {
        Ok(current) if current == *identity => {}
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

    match killpg(Pid::from_raw(job.active.key.process_group), Signal::SIGKILL) {
        Ok(()) => {
            outcome.killed = true;
            info!(
                pid,
                age_seconds = age.as_secs(),
                crawler_age_seconds = crawler_age.as_secs(),
                process_group = job.active.key.process_group,
                session = job.active.key.session,
                comm = identity.comm.as_str(),
                cmdline,
                action = "killed",
                "stale crawler job killed"
            );
        }
        Err(Errno::ESRCH) => {}
        Err(error) => {
            outcome.failed = true;
            warn!(
                pid,
                age_seconds = age.as_secs(),
                crawler_age_seconds = crawler_age.as_secs(),
                process_group = job.active.key.process_group,
                session = job.active.key.session,
                comm = identity.comm.as_str(),
                %error,
                "failed to kill stale crawler job"
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
    let mut fields = stat.get(close + 1..)?.split_whitespace();
    let _state = fields.next()?;
    let _parent_pid = fields.next()?.parse::<i32>().ok()?;
    let process_group = fields.next()?.parse::<i32>().ok()?;
    let session = fields.next()?.parse::<i32>().ok()?;
    let start_ticks = fields.nth(15)?.parse::<u64>().ok()?;
    Some(ProcIdentity {
        comm,
        process_group,
        session,
        start_ticks,
    })
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

fn job_state_path(config: &Config) -> PathBuf {
    let default_names = DEFAULT_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if config.max_age == DEFAULT_MAX_AGE && config.names == default_names {
        return PathBuf::from(JOB_STATE_PATH);
    }

    // Stable FNV-1a: policy state must survive binary upgrades, so avoid a
    // std hasher whose algorithm is intentionally unspecified.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in config.max_age.as_secs().to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for name in &config.names {
        for &byte in name.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    PathBuf::from(format!("{JOB_STATE_PATH}-{hash:016x}"))
}

fn read_boot_id() -> Result<String> {
    let boot_id =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").context("failed to read boot ID")?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() {
        bail!("boot ID is empty");
    }
    Ok(boot_id.to_owned())
}

fn load_job_state(path: &Path, boot_id: &str) -> io::Result<BTreeMap<JobKey, u64>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error),
    };
    parse_job_state(&raw, boot_id)
}

fn parse_job_state(raw: &str, boot_id: &str) -> io::Result<BTreeMap<JobKey, u64>> {
    let mut lines = raw.lines();
    let Some(header) = lines.next() else {
        return Ok(BTreeMap::new());
    };
    let Some(saved_boot_id) = header.strip_prefix("v1\t") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported crawler state format",
        ));
    };
    if saved_boot_id != boot_id {
        return Ok(BTreeMap::new());
    }

    let mut state = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let mut fields = line.split('\t');
        let process_group = parse_state_field(fields.next(), "process group")?;
        let session = parse_state_field(fields.next(), "session")?;
        let leader_start_ticks = parse_state_field(fields.next(), "leader start ticks")?;
        let first_seen_seconds = parse_state_field(fields.next(), "first seen seconds")?;
        if fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many crawler state fields",
            ));
        }
        let process_group = i32::try_from(process_group).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "process group does not fit i32")
        })?;
        let session = i32::try_from(session)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "session does not fit i32"))?;
        if process_group <= 0 || session <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-positive crawler job identity",
            ));
        }
        state.insert(
            JobKey {
                process_group,
                session,
                leader_start_ticks,
            },
            first_seen_seconds,
        );
    }
    Ok(state)
}

fn parse_state_field(field: Option<&str>, name: &str) -> io::Result<u64> {
    field
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {name}")))?
        .parse::<u64>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {name}: {error}"),
            )
        })
}

fn serialize_job_state(boot_id: &str, state: &BTreeMap<JobKey, u64>) -> String {
    let mut result = format!("v1\t{boot_id}\n");
    for (key, first_seen_seconds) in state {
        let process_group = key.process_group;
        let session = key.session;
        let leader_start_ticks = key.leader_start_ticks;
        let _ = writeln!(
            result,
            "{process_group}\t{session}\t{leader_start_ticks}\t{first_seen_seconds}",
        );
    }
    result
}

fn write_job_state(path: &Path, boot_id: &str, state: &BTreeMap<JobKey, u64>) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", process::id()));
    fs::write(&temporary, serialize_job_state(boot_id, state))?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
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
                process_group: 2,
                session: 3,
                start_ticks: 4242,
            }
        );
        Ok(())
    }

    #[test]
    fn proc_stat_parser_accepts_kernel_thread_job_ids_for_quiet_skip() -> Result<()> {
        let stat = "2 (kthreadd) S 0 0 0 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0";
        let parsed = parse_proc_stat(stat).context("failed to parse kernel-thread fixture")?;
        assert_eq!(parsed.process_group, 0);
        assert_eq!(parsed.session, 0);
        assert_eq!(parsed.start_ticks, 12345);
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

    fn process(
        pid: i32,
        comm: &str,
        process_group: i32,
        session: i32,
        start_ticks: u64,
    ) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            identity: ProcIdentity {
                comm: comm.to_owned(),
                process_group,
                session,
                start_ticks,
            },
        }
    }

    fn rg_config() -> Config {
        Config {
            max_age: Duration::from_secs(300),
            names: BTreeSet::from(["rg".to_owned()]),
            dry_run: false,
        }
    }

    #[test]
    fn fresh_crawler_in_old_job_starts_a_fresh_job_timer() {
        let processes = vec![
            process(100, "bash", 100, 100, 10_000),
            process(101, "xargs", 100, 100, 11_000),
            process(102, "rg", 100, 100, 49_000),
        ];
        let active = find_active_jobs(&rg_config(), &processes);
        assert_eq!(active.len(), 1);

        let (stale_jobs, next_state) = update_job_state(
            &rg_config(),
            &active,
            &BTreeMap::new(),
            Duration::from_secs(500),
            100,
        );
        assert_eq!(stale_jobs, Vec::new());
        assert_eq!(next_state.get(&active[0].key), Some(&490));
    }

    #[test]
    fn respawned_crawler_keeps_continuous_job_timer() {
        let processes = vec![
            process(100, "bash", 100, 100, 10_000),
            process(101, "xargs", 100, 100, 11_000),
            process(202, "rg", 100, 100, 49_000),
        ];
        let active = find_active_jobs(&rg_config(), &processes);
        let previous = BTreeMap::from([(active[0].key, 100)]);

        let (stale_jobs, next_state) = update_job_state(
            &rg_config(),
            &active,
            &previous,
            Duration::from_secs(500),
            100,
        );
        assert_eq!(stale_jobs.len(), 1);
        assert_eq!(stale_jobs[0].active.representative.pid, 202);
        assert_eq!(stale_jobs[0].first_seen_seconds, 100);
        assert_eq!(next_state.get(&active[0].key), Some(&100));
    }

    #[test]
    fn old_interactive_shell_does_not_age_separate_foreground_job() {
        let processes = vec![
            process(100, "bash", 100, 100, 10_000),
            process(102, "rg", 102, 100, 49_000),
        ];
        let active = find_active_jobs(&rg_config(), &processes);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key.process_group, 102);

        let (stale_jobs, next_state) = update_job_state(
            &rg_config(),
            &active,
            &BTreeMap::new(),
            Duration::from_secs(500),
            100,
        );
        assert_eq!(stale_jobs, Vec::new());
        assert_eq!(next_state.get(&active[0].key), Some(&490));
    }

    #[test]
    fn multiple_crawlers_in_one_job_are_deduplicated() {
        let processes = vec![
            process(100, "bash", 100, 100, 10_000),
            process(101, "rg", 100, 100, 20_000),
            process(102, "rg", 100, 100, 30_000),
        ];
        let active = find_active_jobs(&rg_config(), &processes);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].oldest_crawler_start_ticks, 20_000);
        assert_eq!(active[0].representative.pid, 101);
    }

    #[test]
    fn state_round_trip_and_boot_change() -> Result<()> {
        let key = JobKey {
            process_group: 10,
            session: 20,
            leader_start_ticks: 30,
        };
        let state = BTreeMap::from([(key, 40)]);
        let encoded = serialize_job_state("boot-a", &state);
        assert_eq!(parse_job_state(&encoded, "boot-a")?, state);
        assert_eq!(parse_job_state(&encoded, "boot-b")?, BTreeMap::new());
        Ok(())
    }

    #[test]
    fn custom_policy_uses_separate_state_file() {
        let default = Config {
            max_age: DEFAULT_MAX_AGE,
            names: DEFAULT_NAMES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            dry_run: false,
        };
        assert_eq!(job_state_path(&default), PathBuf::from(JOB_STATE_PATH));

        let mut custom = default;
        custom.max_age = Duration::from_secs(1);
        let custom_path = job_state_path(&custom);
        assert_ne!(custom_path, PathBuf::from(JOB_STATE_PATH));
        assert!(custom_path.to_string_lossy().starts_with(JOB_STATE_PATH));

        custom.max_age = DEFAULT_MAX_AGE;
        custom.names = BTreeSet::from(["rg".to_owned()]);
        assert_ne!(job_state_path(&custom), PathBuf::from(JOB_STATE_PATH));
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
