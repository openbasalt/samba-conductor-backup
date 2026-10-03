# conductor-backup

Encrypted Samba Active Directory backups, restore, and automated restore
drills, for Samba Conductor v2. Design: `../planning/docs/architecture.md`
(§3, §6), phase spec `../planning/docs/p3-spec.md`, recovery runbook
`../conductor/docs/restore.md`.

Status: **P3** (2026-10-03), validated in the two-DC server-home lab, including
a full-forest restore exercise (`../conductor/docs/usage-p3.md`).

## What it does

- **Online backups** with `samba-tool domain backup online`: no downtime,
  every partition, the domain's secrets and SYSVOL (with its NT ACLs).
  `conductor-helper` (root) runs it over loopback with a **dedicated account
  that holds only the three replication rights** (not an administrator); the
  password is a systemd credential of the helper and never on a command line.
- **Everything a full recovery needs** in one archive: the samba-tool
  backup, conductor's SQLite state (audit log, settings, 2FA secrets still
  sealed; sessions removed), `smb.conf`, `krb5.conf`, the conductor,
  helper and backup configurations (no secrets in them), the DC's TLS files,
  versions (Samba, OS, functional levels, components).
- **Encrypted before it is written anywhere**: the helper streams the
  archive through [age](https://age-encryption.org) (filippo.io/age, X25519)
  to the recipients listed in a root-owned file. The private keys are
  **never on a DC**: the operators keep theirs offline, the drill host keeps
  its own. A compromised DC cannot read old backups. The plaintext exists
  only in the helper's private `/tmp` (tmpfs on Debian 13) and is
  overwritten and removed as soon as the archive is built.
- **Destinations**: local directories and S3-compatible object storage
  (MinIO, AWS S3, OCI Object Storage, …): `domain/<realm>/<id>.tar.age` plus a
  **signed manifest** `<id>.json` (sizes, SHA-256 of the ciphertext,
  versions, recipients' fingerprints). Uploads sign the payload's SHA-256, so
  the server rejects a corrupted body; every copy is read back and its
  SHA-256 checked. Optional S3 object lock (GOVERNANCE/COMPLIANCE).
- **Schedule and retention** (editable by administrators in conductor's
  Backups page, with re-authentication): daily at a UTC time or every 1-12
  hours, retried every hour until one succeeds; keep N daily, M weekly, K
  monthly; nothing younger than 24 h and never the last good backup is
  deleted; a backup whose manifest does not verify (e.g. signed with a
  previous key of the DC) is reported and never deleted.
- **Alerts**: e-mail (STARTTLS/TLS) and an optional signed webhook when a
  backup fails or a destination misses one, when the last good backup is
  older than the policy, when a drill fails or is overdue; conductor's
  dashboard shows a banner, including when conductor-backup itself stopped
  running.
- **Restore** (`restore`): a real AD restore with `samba-tool domain backup
  restore` (original SIDs and GUIDs, FSMO roles seized, old DCs removed,
  krbtgt renewed), after checking the download against the signed manifest,
  and the exact next steps.
- **Restore drills** (`drill`, on a drill host, never a DC): the newest backup
  is restored into a **sandbox with no network** (new network, mount, PID,
  UTS and IPC namespaces; loopback and a dummy interface only), started,
  and checked: LDAP answers, DNS SRV records exist, Kerberos sign-in of a
  probe account works, the user count matches the source, sample SIDs are
  unchanged. The plaintext is shredded, the measured restore time (RTO) and
  every check go into a signed report that conductor shows and audits.

## How the pieces trust each other

| Piece | Runs as | Can | Cannot |
|---|---|---|---|
| `conductor-helper` | root (narrow unit) | read the DB as root, run samba-tool with the backup account, encrypt to the root-owned recipients, write ciphertext/requests/policy into conductor-backup's state (never following its symlinks) | send data anywhere; choose recipients from a request |
| `conductor-backup run` | `conductor-backup` (no capabilities) | ask the helper for an archive (its own socket, SO_PEERCRED), upload, verify, prune, sign manifests and drill requests | read AD, see the backup account's password, decrypt anything |
| `conductor` | `conductor` | read the status, ask for "back up now" / "run drill now", change the policy (schedule, retention, thresholds) through the helper, with the signed-in user as the caller, previewed, re-authenticated, audited | change destinations, credentials or recipients (host configuration only) |
| drill host | root (dedicated machine or VM) | read the bucket, decrypt with the drill identity, restore in a sandbox, sign reports | reach the DCs (the sandbox has no network; the host should have no route either) |

A bucket-only attacker cannot forge a backup (manifests are signed with a
key that lives only on the DC; age alone is not sender-authenticated), nor a
drill result (reports are signed by the drill host), nor trigger arbitrary
drills (requests are signed by the DC).

## Install on a domain controller (Debian 13 / Ubuntu 26.04)

Requires conductor and conductor-helper installed (`../conductor/docs/install.md`).

```sh
# 1. Binary, user, directories.
install -m 0755 conductor-backup /usr/local/bin/
useradd --system --user-group --home-dir /var/lib/conductor-backup --no-create-home --shell /usr/sbin/nologin conductor-backup
install -d -m 0750 -o root -g conductor-backup /etc/conductor-backup
install -d -m 0700 /etc/conductor-backup/credentials
install -d -m 0700 -o conductor-backup -g conductor-backup /var/lib/conductor-backup

# 2. The backup account: a plain user with only the replication rights on
#    every naming context (replace the SID; repeat for each NC:
#    DC=…, CN=Configuration,DC=…, CN=Schema,CN=Configuration,DC=…,
#    DC=DomainDnsZones,DC=…, DC=ForestDnsZones,DC=…).
samba-tool user create svc-conductor-backup --random-password
samba-tool user setpassword svc-conductor-backup        # prompts; keep it for step 3
samba-tool dsacl set --objectdn='DC=example,DC=com' \
  --sddl='(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;SID)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;SID)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;SID)'

# 3. Credentials (root 0600, handed to the services by systemd).
#    backup-account: the account's password (read by conductor-helper only)
#    signing-key:    conductor-backup keygen signing --out /etc/conductor-backup/credentials/signing-key
#    s3:             access_key_id = "…" / secret_access_key = "…" (TOML)

# 4. Recipients (public keys), root-owned, writable by root only:
#    the operators' offline keys (`conductor-backup keygen age --out key.txt`
#    on an offline machine, or age-keygen) and the drill host's key.
install -m 0644 recipients.txt /etc/conductor-backup/recipients.txt

# 5. Configuration (examples in this repository).
install -m 0640 -g conductor-backup conductor-backup.toml.example /etc/conductor-backup/conductor-backup.toml
install -m 0640 -g conductor helper.toml /etc/conductor/helper.toml     # [backup] section, see below

# 6. Units.
install -m 0644 deploy/systemd/conductor-backup.{service,timer,path} /etc/systemd/system/
install -D -m 0644 deploy/systemd/conductor-helper.service.d/conductor-backup.conf \
  /etc/systemd/system/conductor-helper.service.d/conductor-backup.conf
systemctl daemon-reload
systemctl restart conductor-helper
systemctl enable --now conductor-backup.timer conductor-backup.path
systemctl start conductor-backup.service       # first backup now
```

`/etc/conductor/helper.toml`:

```toml
[backup]
enabled = true
peer_user = "conductor-backup"
account = "svc-conductor-backup"
password_credential = "backup-account"   # LoadCredential= in the drop-in
server = "127.0.0.1"                     # this DC, over loopback
# dc = "dc1"
recipients_file = "/etc/conductor-backup/recipients.txt"
state_dir = "/var/lib/conductor-backup"
work_dir = "/tmp/conductor-backup"       # the helper's private /tmp (tmpfs)
conductor_db = "/var/lib/conductor/conductor.db"
# extra_files = ["/etc/…"]
```

Run backups on one DC (usually the PDC emulator); each DC prunes only its
own backups.

## Install a drill host

A small VM or machine that is **not** a DC, with `samba-ad-dc` installed but
its services disabled and masked, `iproute2`, no route to the DCs, read
access to the bucket and write access to its `drills/` prefix:

```sh
install -m 0755 conductor-backup /usr/local/bin/
install -d -m 0700 /etc/conductor-backup/credentials /var/lib/conductor-backup-drill
# credentials: drill-identity (its age identity), drill-signing-key
# (conductor-backup keygen signing), drill-probe-password, s3
install -m 0644 drill.toml.example /etc/conductor-backup/drill.toml        # edit
install -m 0644 deploy/systemd/conductor-backup-drill.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now conductor-backup-drill.timer
```

Then put its public signing key (`conductor-backup pubkey …`) in the DC's
`drill_public_keys`, and the DC's in the drill host's `backup_public_keys`.
The probe account is a plain domain user with no rights.

## Commands

```
conductor-backup run [--scheduled|--now]
conductor-backup check                      # exit 1 while an alert is active
conductor-backup status [--json]
conductor-backup list [--destination N]
conductor-backup verify ID|latest           # download + SHA-256, no decryption
conductor-backup prune [--dry-run]
conductor-backup restore ID|latest --identity KEY --target DIR --newservername NAME [--with-conductor-state] [--host-ip IP]
conductor-backup drill [--now] [--backup ID]
conductor-backup keygen signing|age --out FILE
conductor-backup pubkey FILE
```

## Why online, and when offline

`samba-tool domain backup online` replicates the DC's database over DRS
like a joining DC would, so the domain keeps running and the copy is
consistent. `samba-tool domain backup offline` reads the local files
directly (Samba stopped or with database locks) and also keeps local-only
state (e.g. `idmap.ldb`, private keytabs); it suits a DC whose replication
is broken or a domain with a single DC that is shut down for maintenance.
conductor-backup automates the online kind; take an offline backup by hand
before risky local maintenance.

## Limits

- One PUT per object: archives up to 5 GiB on S3 (multipart is not
  implemented).
- Plaintext lives briefly in the helper's `/tmp`; on hosts where `/tmp` is
  not a tmpfs it touches the disk before being overwritten (and an
  overwrite is not a guarantee on SSDs or copy-on-write file systems): use
  a tmpfs or an encrypted disk.
- The drill compares the user count with the source taken around the
  backup; objects the probe account cannot read would count as missing.
- The probe account's password in a restored copy is the one it had at
  backup time.

## Development

```sh
make check   # gofmt, go vet, staticcheck, govulncheck, go test -race
make build   # bin/conductor-backup (CGO off, static)
```

Lab: `../planning/lab/backup-infra.sh`, `drill-up.sh`, `backup-install.sh`,
`p3-snapshot.sh`, `restore-exercise.sh`; see `../planning/docs/lab.md`.

License: MIT.
