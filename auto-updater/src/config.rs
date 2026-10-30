use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_STATE_DIR: &str = "/var/lib/random-utils/updater";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_max_download_bytes")]
    pub max_download_bytes: u64,
    #[serde(default)]
    pub package: Vec<Package>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_interval_seconds")]
    pub min_interval_seconds: u64,
    pub source: Source,
    #[serde(default)]
    pub artifact: Vec<Artifact>,
    #[serde(default)]
    pub pre_update: Vec<CommandSpec>,
    #[serde(default)]
    pub restart_units: Vec<String>,
    #[serde(default)]
    pub post_update: Vec<CommandSpec>,
    #[serde(default)]
    pub health: Vec<HealthCheck>,
    #[serde(default)]
    pub rollback: Vec<CommandSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    GithubRelease { repo: String },
    Command(CommandSpec),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub asset: String,
    pub checksum_asset: String,
    pub destination: PathBuf,
    #[serde(default = "default_mode")]
    pub mode: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_success_exit_codes")]
    pub success_exit_codes: Vec<i32>,
    #[serde(default)]
    pub defer_exit_codes: Vec<i32>,
    #[serde(default = "default_command_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HealthCheck {
    Http {
        url: String,
        #[serde(default = "default_http_statuses")]
        statuses: Vec<u16>,
        #[serde(default = "default_health_attempts")]
        attempts: u32,
        #[serde(default = "default_health_interval_ms")]
        interval_ms: u64,
        #[serde(default = "default_health_timeout_seconds")]
        timeout_seconds: u64,
    },
    SystemdActive {
        unit: String,
        #[serde(default = "default_health_attempts")]
        attempts: u32,
        #[serde(default = "default_health_interval_ms")]
        interval_ms: u64,
    },
    Command(CommandSpec),
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read updater config {}", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("parse updater config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.max_download_bytes == 0 {
            bail!("max_download_bytes must be greater than zero");
        }
        let mut names = std::collections::BTreeSet::new();
        for package in &self.package {
            package.validate()?;
            if !names.insert(&package.name) {
                bail!("duplicate package name {}", package.name);
            }
        }
        Ok(())
    }
}

impl Package {
    fn validate(&self) -> Result<()> {
        if !is_safe_name(&self.name) {
            bail!(
                "invalid package name {:?}; use ASCII letters, digits, '.', '_' or '-'",
                self.name
            );
        }
        match &self.source {
            Source::GithubRelease { repo } => {
                validate_repo(repo)?;
                if self.artifact.is_empty() {
                    bail!(
                        "GitHub package {} must declare at least one artifact",
                        self.name
                    );
                }
            }
            Source::Command(_) => {
                if !self.artifact.is_empty()
                    || !self.pre_update.is_empty()
                    || !self.restart_units.is_empty()
                    || !self.post_update.is_empty()
                    || !self.health.is_empty()
                    || !self.rollback.is_empty()
                {
                    bail!(
                        "command package {} delegates the complete update and cannot declare artifacts, hooks, restarts, or health checks",
                        self.name
                    );
                }
            }
        }
        let mut destinations = std::collections::BTreeSet::new();
        for artifact in &self.artifact {
            if artifact.asset.is_empty() || artifact.asset.contains('/') {
                bail!(
                    "package {} has invalid asset name {:?}",
                    self.name,
                    artifact.asset
                );
            }
            if artifact.checksum_asset.is_empty() || artifact.checksum_asset.contains('/') {
                bail!(
                    "package {} has invalid checksum asset {:?}",
                    self.name,
                    artifact.checksum_asset
                );
            }
            if !artifact.destination.is_absolute() {
                bail!(
                    "package {} destination must be absolute: {}",
                    self.name,
                    artifact.destination.display()
                );
            }
            if !destinations.insert(&artifact.destination) {
                bail!(
                    "package {} declares destination {} more than once",
                    self.name,
                    artifact.destination.display()
                );
            }
            if artifact.mode & !0o7777 != 0 {
                bail!("package {} has invalid mode {:o}", self.name, artifact.mode);
            }
        }
        Ok(())
    }
}

fn validate_repo(repo: &str) -> Result<()> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some() || !is_safe_name(owner) || !is_safe_name(name) {
        bail!("invalid GitHub repository {repo:?}; expected owner/repo");
    }
    Ok(())
}

fn is_safe_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn default_state_dir() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR)
}

const fn default_max_download_bytes() -> u64 {
    512 * 1024 * 1024
}

const fn default_true() -> bool {
    true
}

const fn default_min_interval_seconds() -> u64 {
    3600
}

const fn default_mode() -> u32 {
    0o755
}

fn default_success_exit_codes() -> Vec<i32> {
    vec![0]
}

const fn default_command_timeout_seconds() -> u64 {
    300
}

fn default_http_statuses() -> Vec<u16> {
    vec![200]
}

const fn default_health_attempts() -> u32 {
    20
}

const fn default_health_interval_ms() -> u64 {
    500
}

const fn default_health_timeout_seconds() -> u64 {
    3
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn rejects_unknown_fields() {
        let text = r#"
            wat = true
            [[package]]
            name = "x"
            [package.source]
            type = "command"
            program = "/bin/true"
        "#;
        let parsed = toml::from_str::<Config>(text);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_command_package_transaction_fields() -> anyhow::Result<()> {
        let text = r#"
            [[package]]
            name = "delegated"
            restart_units = ["ignored.service"]
            [package.source]
            type = "command"
            program = "/bin/true"
        "#;
        let config: Config = toml::from_str(text)?;
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn parses_github_package() -> anyhow::Result<()> {
        let text = r#"
            [[package]]
            name = "thing"
            min_interval_seconds = 900
            [package.source]
            type = "github-release"
            repo = "owner/repo"
            [[package.artifact]]
            asset = "thing-{tag}"
            checksum_asset = "SHA256SUMS"
            destination = "/usr/local/bin/thing"
            mode = 0o755
        "#;
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        assert_eq!(config.package.len(), 1);
        Ok(())
    }
}
