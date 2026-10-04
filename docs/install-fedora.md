# Installing conductor-backup on Basalt OS / Fedora

conductor-backup on a Basalt OS (Fedora 44 based, SELinux enforcing) or
Fedora 44 domain controller, from the RPM packages. The configuration
is the one the README describes ("Install on a domain controller"); this
page lists what differs. The Basalt OS package lab
(see
[testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)) runs it with
SELinux enforcing: backups through conductor-helper to S3-compatible
storage (HTTPS) and to a local directory, verified after upload and again
with `conductor-backup verify`.

## Package

```sh
sudo dnf install conductor-backup         # Basalt OS: from basalt-tools
sudo dnf install ./conductor-backup-<version>-1.x86_64.rpm ./conductor-backup-selinux-<version>-1.noarch.rpm
                                          # Fedora, or a release's assets (check SHA256SUMS)
```

`conductor-backup-selinux` comes with it wherever the targeted policy is
installed. The package creates the `conductor-backup` user (sysusers.d) and
owns `/etc/conductor-backup` (root:conductor-backup 0750) with
`credentials/` (root 0700), `conductor-backup.toml` and `drill.toml` (0640,
`%config(noreplace)`) and `/var/lib/conductor-backup`. It ships the helper
drop-in, inactive, in `/usr/share/conductor-backup/systemd/`. Nothing is
enabled or started.

Then the README's steps: account, credentials, recipients, configuration,
`[backup] enabled = true` in `/etc/conductor/helper.toml`, the helper
drop-in link, `systemctl enable --now conductor-backup.timer
conductor-backup.path`.

## SELinux

- Backups on a DC run in `conductor_backup_t`: configuration
  (`conductor_backup_conf_t`), state and spool (`conductor_backup_var_lib_t`),
  the helper's backup socket, a local destination
  (`/var/backups/conductor-backup`, `conductor_backup_store_t`), HTTPS
  (`http_port_t`: 443, 9000, ...) to S3-compatible storage and webhooks,
  SMTP. conductor-helper (`conductor_helper_t`, from conductor-selinux) runs
  `samba-tool` and the age encryption; this module lets it write the spool
  and read the recipients.
- Another local destination: `sudo semanage fcontext -a -t
  conductor_backup_store_t '/srv/backups(/.*)?' && sudo restorecon -R
  /srv/backups`. An S3 endpoint on another port: `sudo semanage port -a -t
  http_port_t -p tcp <port>`.
- Restore drills (a separate drill host, never a DC) run in
  `conductor_backup_drill_t`, an unconfined domain set by the unit
  drop-in the policy package installs
  (`/usr/lib/systemd/system/conductor-backup-drill.service.d/selinux.conf`):
  the drill builds its own namespaces and mounts and runs `samba-tool
  restore` and `samba` as root inside a network-less sandbox. The unit's own
  systemd sandbox still applies.

## Upgrade and removal

`dnf upgrade` changes nothing that runs (timers, path unit, oneshot
services pick up the new binary on their next run) and keeps edited
configuration (`.rpmnew` beside it). `dnf remove` stops and disables the
units, removes the packaged files, the policy module and the helper drop-in
link, and keeps the credentials, `recipients.txt`, `/var/lib/conductor-backup`
and the user. Backups in a bucket or a local destination are never touched.
