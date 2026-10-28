//! Shared logging and direct-push metrics for random-utils binaries.

use std::{
    env, fs,
    path::Path,
    time::{Duration, Instant},
};

use lurkmoar::{Client, ClientBuilder};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::{Layer as _, SubscriberExt as _},
    util::SubscriberInitExt as _,
};

pub use tracing;

const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(60);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_SPOOL_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Install a native journald tracing layer when available, falling back to compact stderr.
pub fn init_logging() {
    let under_systemd = env::var_os("INVOCATION_ID").is_some();
    if under_systemd && let Ok(layer) = tracing_journald::layer() {
        let _ = tracing_subscriber::registry()
            .with(layer.with_filter(log_targets()))
            .try_init();
        return;
    }
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact()
                .with_filter(log_targets()),
        )
        .try_init();
}

fn log_targets() -> Targets {
    Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("crawl_killer", LevelFilter::INFO)
        .with_target("laptop_policy", LevelFilter::INFO)
        .with_target("random_utils_observability", LevelFilter::INFO)
}

/// Optional direct-push metrics client configured from `RANDOM_UTILS_METRICS_URL`.
#[derive(Debug)]
pub struct Metrics {
    client: Option<Client>,
    metric_prefix: String,
    heartbeat: Duration,
    last_payload: Option<String>,
    last_submit: Option<Instant>,
}

impl Metrics {
    #[must_use]
    pub fn from_env(job: &str, metric_prefix: &str, spool_dir: &Path) -> Self {
        let Ok(endpoint) = env::var("RANDOM_UTILS_METRICS_URL") else {
            tracing::debug!(job, "metrics disabled: RANDOM_UTILS_METRICS_URL is not set");
            return Self::disabled(metric_prefix);
        };
        let instance = env::var("RANDOM_UTILS_METRICS_INSTANCE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(hostname);
        let heartbeat =
            env_duration("RANDOM_UTILS_METRICS_HEARTBEAT_SECONDS").unwrap_or(DEFAULT_HEARTBEAT);
        let timeout =
            env_duration_millis("RANDOM_UTILS_METRICS_TIMEOUT_MS").unwrap_or(DEFAULT_TIMEOUT);

        let client = ClientBuilder::new(endpoint)
            .static_label("job", job)
            .static_label("instance", &instance)
            .static_label("resolution", "raw")
            .timeout(timeout)
            .spool(spool_dir, DEFAULT_SPOOL_MAX_BYTES)
            .build();

        match client {
            Ok(client) => {
                tracing::debug!(job, instance, ?heartbeat, ?timeout, "metrics enabled");
                Self {
                    client: Some(client),
                    metric_prefix: metric_prefix.to_owned(),
                    heartbeat,
                    last_payload: None,
                    last_submit: None,
                }
            }
            Err(error) => {
                tracing::warn!(job, %error, "metrics initialization failed; continuing without telemetry");
                Self::disabled(metric_prefix)
            }
        }
    }

    #[must_use]
    fn disabled(metric_prefix: &str) -> Self {
        Self {
            client: None,
            metric_prefix: metric_prefix.to_owned(),
            heartbeat: DEFAULT_HEARTBEAT,
            last_payload: None,
            last_submit: None,
        }
    }

    /// Publish when the application snapshot changes, plus a periodic heartbeat.
    pub fn publish_snapshot(&mut self, payload: String) {
        let changed = self.last_payload.as_deref() != Some(payload.as_str());
        let heartbeat_due = self
            .last_submit
            .is_none_or(|last| last.elapsed() >= self.heartbeat);
        if !changed && !heartbeat_due {
            return;
        }
        if self.submit(&payload) {
            self.last_payload = Some(payload);
            self.last_submit = Some(Instant::now());
        }
    }

    /// Publish immediately, regardless of change detection.
    pub fn publish_now(&self, payload: &str) {
        let _ = self.submit(payload);
    }

    /// Flush pending delivery. Errors are logged and never propagated to utility behavior.
    pub fn flush(&self) {
        let Some(client) = &self.client else {
            return;
        };
        if let Err(error) = client.flush() {
            tracing::warn!(%error, "metrics flush failed");
        }
    }

    fn submit(&self, payload: &str) -> bool {
        let Some(client) = &self.client else {
            return false;
        };
        let mut body = String::with_capacity(payload.len() + 1024);
        body.push_str(payload);
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&client.health_prometheus(&format!("{}_lurkmoar", self.metric_prefix)));
        match client.submit_prometheus_text(body) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "metrics submission failed");
                false
            }
        }
    }
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn env_duration(name: &str) -> Option<Duration> {
    env::var(name)
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
}

fn env_duration_millis(name: &str) -> Option<Duration> {
    env::var(name)
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
}
