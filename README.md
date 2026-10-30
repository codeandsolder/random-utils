# random-utils

Small systems utilities that are too useful to leave as shell snippets.

## Observability

The long-running utilities use native structured journald logging when available, with compact stderr fallback outside systemd. Optional metrics are delivered directly through [`lurkmoar`](https://github.com/codeandsolder/lurkmoar-rs) rather than exposing another scrape server. Configure `/etc/random-utils/telemetry.env` from [`packaging/telemetry.env.example`](packaging/telemetry.env.example); if `RANDOM_UTILS_METRICS_URL` is absent, metrics are disabled without affecting utility behavior.

Metrics use `job=<utility>`, `instance=<hostname>`, and `resolution=raw`. Delivery is change-driven with a 60-second heartbeat, a one-second default HTTP timeout, and a bounded 10 MiB outage spool under `/var/lib/random-utils`. Telemetry failures are logged but never block the policy/killer behavior.

`crawl-killer` reports only crawler-specific scan outcomes (matches/kills/failures, oldest matched age and scan duration). `laptop-policy` reports only policy-specific intent/candidate state (desired charge ceiling, ZFS sync intent and hibernate candidacy). Generic laptop hardware state belongs in `rs-linux-exporter`; the direct producers retain only their own lurkmoar delivery-health series.



## random-utils-update

`random-utils-update` is the shared host updater for small tools that do not justify a bespoke package repository. One five-minute systemd timer drives a declarative `/etc/random-utils/update.toml`; each package has its own minimum check interval, so adding another managed binary does not create another service/timer pair. A backwards wall-clock jump makes packages immediately due rather than suppressing checks until the old timestamp catches up.

The native `github-release` source resolves GitHub's stable `releases/latest` redirect without consuming REST API quota, downloads one or more release artifacts, requires SHA-256 verification from either a per-asset checksum file or shared `SHA256SUMS`, and installs all artifacts as one transaction. Existing destinations are backed up first, replacement happens by same-directory atomic rename, ownership is preserved unless the config explicitly overrides it, and configured service restarts, post-update hooks, and health checks must all pass before state is committed. A failed activation restores every replaced file and restarts the old services.

For genuinely package-specific rollout logic, a `command` source delegates the update while keeping scheduling and fleet inventory in the same config. This is intended for cases such as sccache where drain/protocol compatibility is real application logic rather than generic file installation. Command execution is argv-based, never a shell string, supports explicit success/defer exit codes and a timeout, and receives `RANDOM_UTILS_UPDATE_PACKAGE` / `RANDOM_UTILS_UPDATE_TAG` environment metadata.

The updater also supports pre-update, post-update, rollback and health commands, HTTP health checks, systemd-active checks, package-specific intervals, `--package`, `--force`, `--dry-run`, and `--list`. State lives under `/var/lib/random-utils/updater`; the recorded tag is trusted only while the installed file hashes still match the committed state, so an accidentally replaced/corrupted binary is repaired even when the release tag itself did not change.

See [`packaging/update.toml`](packaging/update.toml), [`packaging/random-utils-update.service`](packaging/random-utils-update.service), and [`packaging/random-utils-update.timer`](packaging/random-utils-update.timer). The example migrates the ordinary `rs-linux-exporter` release updater directly and delegates the sccache-specific rollout through its existing hardened updater.

## evictable-run

`evictable-run` launches explicitly disposable-performance work in the system-level `evictable.slice`. The slice uses cgroup-v2 idle CPU scheduling (`CPUWeight=idle`) and minimum proportional I/O weight, so work remains fully work-conserving when the machine is otherwise idle but yields to ordinary user sessions and system services under contention. Payloads also get `Nice=19`, `CPUSchedulingPolicy=idle`, and `IOSchedulingClass=idle` so priority remains low inside the slice itself.

This is intentionally an explicit class rather than an inference from process names or `nice` values. A `nice=19` process in a normal logind session still belongs to that session's CPU cgroup and can otherwise receive a substantial group-scheduler share.

Install [`packaging/evictable.slice`](packaging/evictable.slice) as `/etc/systemd/system/evictable.slice`, run `systemctl daemon-reload`, and install the release binary as `/usr/local/bin/evictable-run`. Creating a top-level systemd transient service requires root; the payload itself runs as the selected unprivileged user.

Foreground work waits for completion and pipes stdout/stderr back to the caller:

```bash
sudo evictable-run --user jan -- cargo test
```

Long-running work can be detached into a transient service. Its stdout/stderr go to the journal and `systemd-run` prints the generated unit name unless `--unit` supplies one:

```bash
sudo evictable-run --user jan --cwd /path/to/project --detach --unit corpus-refresh -- \
  uv run --no-project --python 3 python scripts/update-corpus-progress.py ...
```

Transient services get systemd's normal login environment for the selected user rather than arbitrary caller environment variables. Commands that need additional environment should make that configuration explicit rather than relying on an SSH shell's ambient state.

## crawl-killer

`crawl-killer` is a deliberately blunt Linux cleanup utility for accidental filesystem traversals that outlive their usefulness. Each invocation scans `/proc` and sends `SIGKILL` to matching processes at least five minutes old. The default target set is `ack`, `ag`, `bfs`, `du`, `fd`, `fdfind`, `fgrep`, `find`, `grep`, `rgrep`, `rg`, `ripgrep`, and `tree`; long-running transfer or mutation tools such as `rsync`, `tar`, `cp`, and `rm` are intentionally not included.

The process age is derived from `/proc/<pid>/stat` using the kernel clock tick rate, and the process identity is re-read immediately before signalling to reduce PID-reuse races. A process blocked in uninterruptible I/O keeps the `SIGKILL` pending and exits when the kernel allows it to resume.

Useful manual modes:

```bash
crawl-killer --dry-run
crawl-killer --max-age-seconds 600
crawl-killer --max-age-seconds 300 --name grep --name find
```

Supplying one or more `--name` options replaces the default target set. The supplied systemd timer runs the one-shot service every 30 seconds as root, so the effective lifetime limit is roughly 5:00–5:30:

```bash
systemctl enable --now crawl-killer.timer
```

## laptop-policy

`laptop-policy` is a Linux policy daemon for laptops that are also used as unattended build nodes. It currently manages four related policies:

- sets ZFS `sync=disabled` while aggregate battery capacity is above a configurable threshold (40% by default), and restores `sync=standard` at or below it;
- hibernates after a short grace period when wall power is absent, the lid is closed, and no external DRM display is connected;
- after 48 continuous hours on external power, limits charging to 80% on hardware exposing a supported charge-limit interface;
- after one continuous hour off external power, restores the charge limit to 100%.

The plug/unplug timers are persisted across daemon restarts and hibernation. Charge-limit support is runtime-probed: the generic Linux `charge_control_end_threshold` ABI is preferred, with the Acer `acer-wmi-battery` health-mode ABI supported when present. Unsupported hardware is logged and left alone.

On Acer systems without the generic power-supply threshold ABI, [`acer-wmi-battery`](https://github.com/frederik-h/acer-wmi-battery) can expose Acer's firmware health mode as `/sys/bus/wmi/drivers/acer-wmi-battery/health_mode`. This path is hardware-verified on the Swift SF314-42: its firmware advertises WMI GUID `79772EC5-04B1-4BFD-843C-61E7F77B6CC9`, reports health mode as supported, and accepts enable/disable transitions. A DKMS installation is appropriate until the equivalent driver is available in the running kernel.

### Important semantics

`sync=disabled` tells ZFS to acknowledge synchronous writes before they are committed to stable storage. A crash or power loss can therefore lose acknowledged writes. This utility exists for systems where that trade-off is deliberate.

The hibernate policy deliberately does **not** treat the built-in eDP/LVDS/DSI panel as an external display. Any connected HDMI/DP/DVI/USB graphics connector prevents automatic hibernation. If lid state, battery capacity, or external-power state cannot be read reliably, the daemon fails safe and skips the corresponding destructive action.

### Configuration

See [`packaging/laptop-policy.toml`](packaging/laptop-policy.toml). Empty `zfs_pools` means “derive the pool containing `/` using `findmnt`”.

Run a non-mutating probe with:

```bash
laptop-policy --config /etc/random-utils/laptop-policy.toml --once --dry-run
```

### systemd

Install the release binary as `/usr/local/bin/laptop-policy`, copy the example configuration to `/etc/random-utils/laptop-policy.toml`, and install [`packaging/laptop-policy.service`](packaging/laptop-policy.service).

`systemd-logind` must not independently suspend on lid close, otherwise it can race the daemon before the daemon decides whether an external display is attached. The supplied [`packaging/80-laptop-policy-logind.conf`](packaging/80-laptop-policy-logind.conf) makes the daemon the owner of lid-close policy.

The supplied [`packaging/80-laptop-policy-sleep.conf`](packaging/80-laptop-policy-sleep.conf) explicitly enables hibernation. If a host previously masked `sleep.target` or `hibernate.target`, those two targets must be unmasked; `suspend.target`, `hybrid-sleep.target`, and `suspend-then-hibernate.target` may remain masked.
