//! Launch explicitly evictable work through systemd resource controls.

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SLICE: &str = "evictable.slice";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    detach: bool,
    user: Option<OsString>,
    unit: Option<OsString>,
    cwd: Option<PathBuf>,
    command: Vec<OsString>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("evictable-run: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, String> {
    let raw_args: Vec<_> = env::args_os().skip(1).collect();
    if matches!(
        raw_args.first().and_then(|arg| arg.to_str()),
        Some("-h" | "--help")
    ) {
        println!("{}", usage());
        return Ok(0);
    }
    let args = parse_args(raw_args)?;
    let cwd = if let Some(cwd) = &args.cwd {
        cwd.clone()
    } else {
        env::current_dir().map_err(|error| format!("read current directory: {error}"))?
    };
    let user = args.user.clone().or_else(default_payload_user);
    let mut command = build_systemd_run(&args, &cwd, user.as_deref());
    let status = command
        .status()
        .map_err(|error| format!("execute {SYSTEMD_RUN}: {error}"))?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut detach = false;
    let mut user = None;
    let mut unit = None;
    let mut cwd = None;
    let mut command = Vec::new();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if !command.is_empty() {
            command.push(arg);
            continue;
        }

        match arg.to_str() {
            Some("--detach") => detach = true,
            Some("--user") => {
                user = Some(
                    args.next()
                        .ok_or_else(|| "--user requires a user name or uid".to_owned())?,
                );
            }
            Some("--unit") => {
                unit = Some(
                    args.next()
                        .ok_or_else(|| "--unit requires a unit name".to_owned())?,
                );
            }
            Some("--cwd") => {
                cwd = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--cwd requires a directory".to_owned())?,
                ));
            }
            Some("--") => {
                command.extend(&mut args);
                break;
            }
            Some("-h" | "--help") => return Err(usage().to_owned()),
            Some(option) if option.starts_with('-') => {
                return Err(format!("unknown option {option:?}\n\n{}", usage()));
            }
            _ => command.push(arg),
        }
    }

    if command.is_empty() {
        return Err(format!("missing command\n\n{}", usage()));
    }

    Ok(Args {
        detach,
        user,
        unit,
        cwd,
        command,
    })
}

fn default_payload_user() -> Option<OsString> {
    env::var_os("SUDO_USER")
        .filter(|user| user != OsStr::new("root"))
        .or_else(|| env::var_os("USER"))
}

fn build_systemd_run(args: &Args, cwd: &Path, user: Option<&OsStr>) -> Command {
    let mut command = Command::new(SYSTEMD_RUN);
    command.arg("--slice").arg(SLICE);
    command.arg("--working-directory").arg(cwd);
    command.args([
        "--property=CPUWeight=idle",
        "--property=IOWeight=1",
        "--property=Nice=19",
        "--property=CPUSchedulingPolicy=idle",
        "--property=IOSchedulingClass=idle",
    ]);

    if let Some(user) = user {
        command.arg("--uid").arg(user);
    }
    if let Some(unit) = &args.unit {
        command.arg("--unit").arg(unit);
    }

    command.args(["--collect", "--service-type=exec"]);
    if !args.detach {
        command.args(["--wait", "--pipe", "--quiet"]);
    }

    command.arg("--");
    command.args(&args.command);
    command
}

const fn usage() -> &'static str {
    "Usage: evictable-run [--user USER] [--cwd DIR] [--detach] [--unit NAME] -- COMMAND [ARG...]\n\
     \n\
     Launch COMMAND in evictable.slice with cgroup and per-process idle scheduling.\n\
     The launcher needs permission to create a top-level systemd transient unit;\n\
     normally invoke it through sudo. The payload runs as --user, SUDO_USER, or USER.\n\
     \n\
     --detach     create a transient service and return after it starts\n\
     --unit NAME  choose the transient unit name\n\
     --cwd DIR    use DIR as the payload working directory\n\
     --user USER  run the payload as this user or numeric uid"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn rendered_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn parses_foreground_command_without_separator() {
        let parsed = parse_args(strings(&["--user", "jan", "cargo", "test"]));
        assert_eq!(
            parsed,
            Ok(Args {
                detach: false,
                user: Some(OsString::from("jan")),
                unit: None,
                cwd: None,
                command: strings(&["cargo", "test"]),
            })
        );
    }

    #[test]
    fn separator_allows_command_options() {
        let parsed = parse_args(strings(&[
            "--detach", "--unit", "job", "--", "rg", "--files",
        ]));
        assert_eq!(
            parsed,
            Ok(Args {
                detach: true,
                user: None,
                unit: Some(OsString::from("job")),
                cwd: None,
                command: strings(&["rg", "--files"]),
            })
        );
    }

    #[test]
    fn parses_explicit_cwd() {
        let parsed = parse_args(strings(&[
            "--user",
            "jan",
            "--cwd",
            "/home/jan/project",
            "--",
            "cargo",
            "test",
        ]));
        assert_eq!(
            parsed,
            Ok(Args {
                detach: false,
                user: Some(OsString::from("jan")),
                unit: None,
                cwd: Some(PathBuf::from("/home/jan/project")),
                command: strings(&["cargo", "test"]),
            })
        );
    }

    #[test]
    fn rejects_missing_command() {
        assert!(parse_args(strings(&["--detach"])).is_err());
    }

    #[test]
    fn foreground_uses_waited_transient_service() {
        let args = Args {
            detach: false,
            user: Some(OsString::from("jan")),
            unit: None,
            cwd: None,
            command: strings(&["cargo", "test"]),
        };
        let command =
            build_systemd_run(&args, Path::new("/home/jan/project"), args.user.as_deref());
        let rendered = rendered_args(&command);
        assert!(rendered.contains(&"--wait".to_owned()));
        assert!(rendered.contains(&"--pipe".to_owned()));
        assert!(rendered.contains(&"--property=CPUWeight=idle".to_owned()));
        assert!(rendered.contains(&"--property=CPUSchedulingPolicy=idle".to_owned()));
        assert_eq!(rendered.last().map(String::as_str), Some("test"));
    }

    #[test]
    fn detached_uses_transient_service() {
        let args = Args {
            detach: true,
            user: Some(OsString::from("jan")),
            unit: Some(OsString::from("corpus-refresh")),
            cwd: None,
            command: strings(&["uv", "run", "tool.py"]),
        };
        let command =
            build_systemd_run(&args, Path::new("/home/jan/project"), args.user.as_deref());
        let rendered = rendered_args(&command);
        assert!(rendered.contains(&"--collect".to_owned()));
        assert!(rendered.contains(&"--service-type=exec".to_owned()));
        assert!(!rendered.contains(&"--wait".to_owned()));
        assert!(!rendered.contains(&"--pipe".to_owned()));
        assert!(
            rendered
                .windows(2)
                .any(|pair| pair == ["--unit", "corpus-refresh"])
        );
    }
}
