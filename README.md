# random-utils

Small systems utilities that are too useful to leave as shell snippets.

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
