use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_STATE_DIR: &str = "/var/lib/random-utils/updater";

#[derive(Debug)]
pub struct Config {
    pub state_dir: PathBuf,
    pub max_download_bytes: u64,
    pub package: Vec<Package>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootConfig {
    #[serde(default = "default_state_dir")]
    state_dir: PathBuf,
    #[serde(default = "default_max_download_bytes")]
    max_download_bytes: u64,
    include_dir: Option<PathBuf>,
    #[serde(default)]
    package: Vec<Package>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFragment {
    #[serde(default)]
    package: Vec<Package>,
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
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read updater config {}", path.display()))?;
        let root: RootConfig = toml::from_str(&text)
            .with_context(|| format!("parse updater config {}", path.display()))?;

        let mut config = Self {
            state_dir: root.state_dir,
            max_download_bytes: root.max_download_bytes,
            package: root.package,
        };
        if let Some(include_dir) = root.include_dir {
            config.load_fragments(&include_dir)?;
        }
        config.validate()?;
        Ok(config)
    }

    fn load_fragments(&mut self, include_dir: &Path) -> Result<()> {
        if !include_dir.is_absolute() {
            bail!("include_dir must be absolute: {}", include_dir.display());
        }
        let entries = std::fs::read_dir(include_dir)
            .with_context(|| format!("read config fragment directory {}", include_dir.display()))?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry =
                entry.with_context(|| format!("read entry in {}", include_dir.display()))?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "toml") {
                continue;
            }
            let file_type = entry
                .file_type()
                .with_context(|| format!("read file type for {}", path.display()))?;
            if !file_type.is_file() {
                bail!("config fragment must be a regular file: {}", path.display());
            }
            paths.push(path);
        }
        paths.sort();

        for path in paths {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read updater config fragment {}", path.display()))?;
            let fragment: ConfigFragment = toml::from_str(&text)
                .with_context(|| format!("parse updater config fragment {}", path.display()))?;
            self.package.extend(fragment.package);
        }
        Ok(())
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
    use std::fs;

    use tempfile::tempdir;

    use super::Config;

    fn load_text(text: &str) -> anyhow::Result<Config> {
        let dir = tempdir()?;
        let path = dir.path().join("update.toml");
        fs::write(&path, text)?;
        Config::load(&path)
    }

    #[test]
    fn rejects_unknown_fields() {
        let result = load_text(
            r#"
                wat = true
                [[package]]
                name = "x"
                [package.source]
                type = "command"
                program = "/bin/true"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_command_package_transaction_fields() {
        let result = load_text(
            r#"
                [[package]]
                name = "delegated"
                restart_units = ["ignored.service"]
                [package.source]
                type = "command"
                program = "/bin/true"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parses_github_package() -> anyhow::Result<()> {
        let config = load_text(
            r#"
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
            "#,
        )?;
        assert_eq!(config.package.len(), 1);
        Ok(())
    }

    #[test]
    fn loads_fragments_in_filename_order() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments)?;
        fs::write(
            fragments.join("20-second.toml"),
            r#"
                [[package]]
                name = "second"
                [package.source]
                type = "command"
                program = "/bin/true"
            "#,
        )?;
        fs::write(
            fragments.join("10-first.toml"),
            r#"
                [[package]]
                name = "first"
                [package.source]
                type = "command"
                program = "/bin/true"
            "#,
        )?;
        let root = format!(
            "include_dir = {:?}\n",
            fragments.to_string_lossy().into_owned()
        );
        let path = dir.path().join("update.toml");
        fs::write(&path, root)?;

        let config = Config::load(&path)?;
        let names: Vec<_> = config
            .package
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, ["first", "second"]);
        Ok(())
    }

    #[test]
    fn fragments_cannot_override_global_settings() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let fragments = dir.path().join("fragments");
        fs::create_dir(&fragments)?;
        fs::write(fragments.join("10-bad.toml"), "max_download_bytes = 1\n")?;
        let root = format!(
            "include_dir = {:?}\n",
            fragments.to_string_lossy().into_owned()
        );
        let path = dir.path().join("update.toml");
        fs::write(&path, root)?;

        assert!(Config::load(&path).is_err());
        Ok(())
    }
}
