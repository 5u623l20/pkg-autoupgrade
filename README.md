# pkg-autoupgrade

A [pkg(8)](https://man.freebsd.org/pkg/8) plugin that automates unattended package upgrades from [periodic(8)](https://man.freebsd.org/periodic/8), with boot environment safety nets, service restart detection, and MOTD notifications.

## Features

- **`pkg autoupgrade`** subcommand invoked daily by a periodic script
- **pkgbase-aware**: base system repos are excluded by default; opt in per repo name
- **ZFS safety net**: creates a named boot environment before each upgrade run, prunes old ones
- **UFS safety net**: backs up `/boot/kernel` to `/boot/kernel.old` before a kernel upgrade
- **Vulnerable-only mode**: optionally restricts upgrades to packages with known CVEs via `pkg audit`
- **Package blocklist**: exclude packages by POSIX extended regex pattern
- **Service restart**: detects services affected by upgrades via two paths:
  - Direct: rc script ownership — which package owns it, was it upgraded?
  - Embedded checkrestart: scans running processes for stale executable VNODE mappings (catches shared-library upgrades, e.g. openssl upgraded while nginx still maps old libssl.so)
  - Services in `AU_RESTART_SERVICES` restart automatically; others get a MOTD notice
- **Reboot detection**: if the kernel was upgraded and the system is not jailed, reboots automatically (if configured) or writes a MOTD notice; supports scheduled reboot time and logged-in user guard
- **Autoremove**: optionally removes orphaned packages after a successful upgrade
- **Email notifications**: sends post-upgrade reports via `sendmail(8)` with configurable send policy
- **Persistent MOTD notices**: stamped into `/var/run/motd` under a delimited section; persisted to `/var/db/pkg-autoupgrade/notices` and re-stamped at boot by an included rc.d script

## Repository layout

```
pkg-autoupgrade/
  src/
    pkg-autoupgrade.c     plugin entry points, command dispatch
    config.c              UCL configuration loading
    upgrade.c             repo update, job build/solve/apply, blocklist, autoremove
    services.c            service detection and restart
    be_support.c          libbe(3) BE creation/pruning, UFS kernel backup
    motd.c                MOTD rewrite and state persistence
    audit.c               pkg audit integration (vulnerable-only mode)
    mail.c                post-upgrade email notifications
  include/
    pkg-autoupgrade.h     shared constants and types
    config.h
    upgrade.h
    services.h
    be_support.h
    motd.h
    audit.h
    mail.h
  man/
    pkg-autoupgrade.8     man page
  conf/
    autoupgrade.conf.sample
  periodic/
    500.pkg-autoupgrade
  rc.d/
    pkg-autoupgrade-motd
  Makefile
  LICENSE.txt
```

## Dependencies

| Library | Purpose |
|---------|---------|
| `libpkg` | pkg(8) plugin and jobs API |
| `libbe` | ZFS boot environment management |
| `libprocstat` | stale-mapping process scan |
| `libucl` | transitively required by `pkg/audit.h` (`textproc/libucl`) |

`libpkg`, `libbe`, and `libprocstat` are part of the FreeBSD base system or installed alongside pkg. `libucl` is available as a port.

## Building

```sh
cd pkg-autoupgrade
make
sudo make install
```

`make install` places:

- `${PREFIX}/lib/pkg/autoupgrade.so` - plugin shared object
- `${PREFIX}/etc/pkg/autoupgrade.conf.sample` - sample config
- `${PREFIX}/etc/periodic/daily/500.pkg-autoupgrade` - periodic script
- `${PREFIX}/etc/rc.d/pkg-autoupgrade-motd` - boot MOTD rc script
- `${PREFIX}/share/man/man8/pkg-autoupgrade.8.gz` - man page

## Configuration

Enable the plugin in `/usr/local/etc/pkg.conf`:

```
PLUGINS [ "autoupgrade" ];
```

Copy and edit the sample config:

```sh
vi /usr/local/etc/pkg/autoupgrade.conf
```

Enable the daily periodic run in `/etc/periodic.conf`, `/etc/periodic.conf.local`, or `/usr/local/etc/periodic.conf`:

```sh
daily_pkg_autoupgrade_enable="YES"
```

Enable the MOTD rc service in `/etc/rc.conf`:

```sh
pkg_autoupgrade_motd_enable="YES"
```

### Key config directives

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `AU_ALLOW_BASE_UPGRADE` | bool | `false` | Upgrade pkgbase repos |
| `AU_BASE_REPOS` | string | `"FreeBSD-base"` | Comma-separated repo names to treat as base |
| `AU_BE_ENABLED` | bool | `true` | Create a BE before upgrading (ZFS only) |
| `AU_BE_PREFIX` | string | `"pre-autoupgrade"` | BE name prefix |
| `AU_BE_KEEP` | int | `5` | Maximum auto-created BEs to retain |
| `AU_UFS_KERNEL_BACKUP` | bool | `true` | Back up `/boot/kernel` on UFS before kernel upgrade |
| `AU_ONLY_UPGRADE_VULNERABLE_PKG` | bool | `false` | Only upgrade packages with known CVEs |
| `AU_BLOCKLISTED_PACKAGES` | string | `""` | Comma-separated POSIX ERE patterns to exclude |
| `AU_AUTOREMOVE` | bool | `false` | Remove orphaned packages after upgrade |
| `AU_ALLOW_REBOOT` | bool | `false` | Reboot automatically after kernel upgrade |
| `AU_REBOOT_TIME` | string | `"now"` | Reboot time: `"now"` or `"HH:MM"` |
| `AU_REBOOT_IF_USERS_LOGGED_IN` | bool | `false` | Reboot even if users are logged in |
| `AU_RESTART_SERVICES` | string | `""` | Services safe to restart automatically (comma-separated) |
| `AU_MAIL_TO` | string | `""` | Email recipient for post-upgrade reports |
| `AU_MAIL_REPORT` | string | `"on-change"` | Send policy: `always`, `on-change`, `on-error` |

See `pkg-autoupgrade(8)` and `autoupgrade.conf.sample` for full details.

## MOTD notices

Pending notices are written to `/var/run/motd` between delimiters:

```
# --- pkg-autoupgrade begin ---
Service needs restart after upgrade: nginx (not in AU_RESTART_SERVICES)
System reboot required: kernel was upgraded (FreeBSD-kernel-14.2)
# --- pkg-autoupgrade end ---
```

The section is replaced atomically on each run. Notices are also persisted to `/var/db/pkg-autoupgrade/notices` and re-stamped at boot by the `pkg_autoupgrade_motd` rc service (runs after `motd`, before `LOGIN`).

## Security notes

- The plugin must run as root; it exits immediately otherwise.
- Service names are validated against `[A-Za-z0-9._-]` before being passed to `service(8)` via `system(3)`.
- `AU_MAIL_TO` is validated against control characters to prevent header injection.
- No credentials are stored or transmitted.
