# conductor-backup: design

`conductor-backup` takes encrypted online backups of a Samba Active
Directory domain, uploads them to local directories and S3-compatible
object storage, prunes them by a retention policy, alerts when backups
fail or go stale, restores them with `samba-tool domain backup restore`,
and proves they restore with automated restore drills on a separate drill
host. It works together with conductor-helper (root, on the DC), which
produces the encrypted archive, and with conductor, which shows the status
and lets administrators change the policy. The cross-cutting design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md#integration-components),
packaging in
[packaging.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md),
and the recovery procedures in the
[restore runbook](https://github.com/openbasalt/samba-conductor/blob/main/docs/restore.md).

## Trust between the pieces

| Piece | Runs as | Can | Cannot |
|---|---|---|---|
| conductor-helper | root, narrow unit, localhost only | run samba-tool with the backup account, read conductor's database, encrypt to the root-owned recipients, write ciphertext, requests and policy into conductor-backup's state | send data anywhere; take recipients or destinations from a request |
| `conductor-backup run` | `conductor-backup`, no capabilities | ask the helper for an archive, upload, verify, prune, sign manifests and drill requests, alert | read AD, see the backup account's password, decrypt anything |
| conductor | `conductor` | read the status, request "back up now" or "run drill now", change schedule, retention and thresholds, as the signed-in administrator | change destinations, credentials or recipients |
| drill host | root, not a DC | read the bucket, decrypt with its own identity, restore in a sandbox, sign reports | reach the DCs |

## Online backup

- `samba-tool domain backup online` replicates the database over DRS like
  a joining DC would: no downtime, every partition, the domain's secrets,
  and SYSVOL with its NT ACLs. Offline backups (which also keep local-only
  state) are not automated; they suit a DC with broken replication or a
  single DC taken down for maintenance.
- The helper runs it over loopback (`--server=127.0.0.1`, inside the
  unit's localhost-only address policy) with a dedicated account that
  holds only the three replication rights (Get-Changes, Get-Changes-All,
  Get-Changes-In-Filtered-Set) on all five naming contexts; not an
  administrator. Its password is a systemd credential of the helper only,
  passed to samba-tool on an inherited pipe, never in argv.
- The archive is a tar stream holding a metadata document first (realm,
  DC, versions, domain SID, user and group counts taken before and after
  samba-tool ran, sample SIDs), the samba-tool backup, conductor's SQLite
  state (taken with `VACUUM INTO` from a read-only connection, sessions
  removed and the copy vacuumed), and host files a full recovery needs
  (`smb.conf`, `krb5.conf`, the component configurations, the DC's TLS
  files). The TOTP key is not in the archive: the secrets stay sealed and
  operators keep that key offline with their age key.

## Encryption

- The helper builds and encrypts the archive itself with age (X25519) to
  the recipients in a root-owned file it refuses if anyone else can write
  it or its directory. A request cannot name recipients.
- Plaintext exists only in the helper's private `/tmp` (tmpfs on Debian
  13) and is overwritten and removed after each run. On a disk-backed
  `/tmp` an overwrite is no guarantee (SSDs, copy-on-write file systems):
  use a tmpfs or an encrypted disk.
- Private keys are never on a DC. Operators keep theirs offline; the drill
  host has its own. A compromised DC cannot read old backups.

## Signing

- age is not sender-authenticated, and anyone with write access to the
  bucket could replace an archive together with a manifest carrying its
  new hash. So manifests, drill requests and drill reports are signed with
  Ed25519.
- Keys: private `cbsigkey1:<base64 seed>`, public `cbsig1:<base64>`
  (`conductor-backup keygen signing`, `conductor-backup pubkey`). The DC's
  key is generated on the DC and never leaves it; the drill host signs its
  reports with its own key; each side is configured with the other's
  public key.
- Envelope: `{"payload": base64(JSON), "key_id": "<id>", "signature": "<base64>"}`
  with the signature over the exact payload bytes, so no canonical
  re-encoding is involved.
- The manifest records sizes, the SHA-256 of the ciphertext, versions and
  the recipients' fingerprints.

## Spool and helper interaction

- conductor-backup's state directory (`/var/lib/conductor-backup`) holds
  `state.json` (the status conductor shows), private bookkeeping,
  `policy.json`, `requests/`, `spool/` (encrypted archives and manifests
  awaiting upload) and a run lock.
- The helper serves conductor-backup on its own socket (`backup.sock`,
  root:conductor-backup) admitting only that user (`SO_PEERCRED`), and
  conductor on `helper.sock`. Each socket serves only its peer's
  operations.
- The helper writes into conductor-backup's state with `openat` and
  `O_NOFOLLOW`, `O_EXCL`, `fchown` and `renameat` on a directory whose
  owner it checks, so a compromised conductor-backup cannot redirect
  root's writes through symbolic links.
- "Back up now" and "run drill now": the helper writes a request file and
  a systemd path unit starts the service. The helper never talks to
  systemd. A run re-checks requests before releasing its lock.
- Scheduling: a fixed hourly timer (`Persistent=true`); conductor-backup
  decides from the policy whether a slot is due (a UTC time and an
  interval of 1, 2, 3, 4, 6, 8, 12 or 24 hours) and retries every hour
  until a backup succeeds. No unit edits from the web.

## Destinations and upload

- Local directories and S3-compatible storage. Objects are
  `domain/<realm>/<id>.tar.age` plus the signed manifest `<id>.json`.
- An own minimal S3 client (SigV4, PUT, GET, HEAD, DELETE,
  ListObjectsV2) signs the payload's SHA-256 and sends Content-MD5, so
  the server rejects a corrupted body; every copy is read back and its
  hash checked. Optional object lock (governance or compliance mode).
- One PUT per object, so archives are limited to 5 GiB (multipart is not
  implemented).
- A backup a destination missed waits in the spool, raises the "failed"
  alert, and is uploaded to that destination by the next run.

## Retention

- Keep the newest backup of each of the last N days, M ISO weeks and K
  months that have backups, everything younger than 24 hours, and always
  the newest complete backup (archive plus a verified manifest of the same
  size).
- A DC prunes only its own backups. Incomplete objects are removed after
  48 hours. A backup whose manifest does not verify (for example one
  signed by an earlier key of a rebuilt DC) is reported as unverified and
  never deleted.
- `prune --dry-run` shows what would go.

## Alerts

- E-mail (STARTTLS or implicit TLS; plain SMTP only to a loopback relay;
  header values stripped of line breaks) and an optional https webhook
  signed with HMAC-SHA256.
- Conditions: a failed or partial backup, the last good backup older than
  the policy, a failed or overdue drill. One message per condition per 24
  hours while it lasts; `conductor-backup check` exits 1 while an alert is
  active.
- conductor's dashboard banner reads the cached status, recomputes
  staleness against the current time, and also warns when
  conductor-backup itself has not run for more than two hours.

## Restore

`conductor-backup restore ID --identity KEY --target DIR --newservername
NAME` downloads the backup, verifies the archive against the signed
manifest, decrypts it with the operator's key and runs `samba-tool domain
backup restore`. This is a real AD restore: original SIDs and GUIDs are
kept, FSMO roles are seized, the old DCs are removed and the krbtgt keys
renewed (tickets of the old domain stop working). The command prints the
exact next steps; conductor's state can be restored too
(`--with-conductor-state`). The scenarios (full forest loss, one DC lost
while others live, accidental deletion, key loss) are in the
[restore runbook](https://github.com/openbasalt/samba-conductor/blob/main/docs/restore.md).

## Restore drills

- Drills run on a drill host, never on a DC: they must decrypt, and a
  decrypting key on a DC would let a compromised DC read old backups.
  Backups are encrypted to the operators' keys and to the drill host's key.
- Requests flow through the bucket: the DC posts a signed request
  (`drills/<realm>/requests/`), the drill host (timer every 5 minutes)
  restores and posts a signed report (`drills/<realm>/reports/`), the DC
  reads it on its next run, and conductor records it in its state and
  audit log. The drill interval is part of the policy.
- Each drill restores the newest backup into a sandbox started by
  conductor-backup in new network, mount, PID, UTS and IPC namespaces:
  loopback and one dummy interface, private `/run/samba`, `/proc`,
  `/etc/resolv.conf` and `/etc/hosts`. The kernel kills whatever is left
  when it exits. The drill host itself should have no route to the DCs.
- Checks: archive SHA-256, LDAP rootDSE, three DNS SRV records, a
  Kerberos TGT for a probe account (a plain user with no rights), the user
  count within the range counted around the backup, and sample SIDs
  (Administrator, the lowest-RID users, Domain Admins, Domain Users)
  unchanged. The restore time (RTO) is measured from drill start to all
  checks passed. Plaintext is shredded afterwards.
- The drill host also alerts when the newest backup in the bucket is too
  old: a watchdog off the DC that keeps working if the DC's timer dies.
- Drills currently run unconfined under SELinux (namespaces, mounts,
  Samba as root); the drill host is a separate machine.

## What a backup can make the restoring host do

A backup that verifies is not a trusted one: whoever holds the DC's
signing key and can write to the bucket can produce one (age is not
sender-authenticated, and both sit with the unprivileged `conductor-backup`
user on the DC). The drill host and the operator's restore host therefore
treat the decrypted content as hostile input.

### smb.conf

The Samba backup carries the backed-up DC's `smb.conf`, and smb.conf can
make Samba run commands (`dns update command`, `check password script`,
`panic action`, `root preexec`, the other `*command` and `*script`
parameters), load modules (`vfs objects`), read other files (`include`),
use another configuration store (`config backend = registry`) and point
shares anywhere. `samba-tool domain backup restore` loads it as root and
writes the backup's sysvol into the `[sysvol]` path it names. So:

- Before the restore, conductor-backup reads the backup's `etc/smb.conf`
  itself (Samba never loads it). `include`, `config backend`, `config file`
  or `registry shares` anywhere refuse the restore; the realm must be the
  configured one; only the workgroup is taken from it (a NetBIOS domain
  name: letters, digits, `.`, `_`, `-`, at most 15 characters).
- samba-tool restores with a configuration generated from the allowlist
  below (`--configfile`): it copies that file over the backup's
  `etc/smb.conf` and keeps the backup's as `etc/smb.conf.orig`, which
  nothing loads.
- After the restore, the `smb.conf` samba-tool wrote is checked against the
  allowlist and rewritten in canonical form before Samba starts. Every
  allowlisted parameter must be present with exactly the expected value;
  anything else is dropped (and logged); the refused constructs fail the
  restore or the drill, with the reason in the drill report.

The allowlist is what `samba-tool domain backup restore` itself writes for
a restored DC (its `make_smbconf` call) and nothing more; every other
parameter keeps Samba's compiled-in default:

| Section | Parameter | Value |
|---|---|---|
| `[global]` | `netbios name` | the restored DC's name (`--newservername`, `drill.server_name`) |
| | `workgroup` | the backup's workgroup (checked as above) |
| | `realm` | the configured realm |
| | `server role` | `active directory domain controller` |
| | `private dir`, `lock dir`, `state directory`, `cache directory`, `binddns dir` | `TARGET/private`, `TARGET`, `TARGET/state`, `TARGET/cache`, `TARGET/bind-dns` |
| `[sysvol]` | `path`, `read only` | `TARGET/state/sysvol`, `no` |
| `[netlogon]` | `path`, `read only` | `TARGET/state/sysvol/<realm>/scripts`, `no` |

`TARGET` is samba-tool's target directory (the drill's throwaway restore
directory, or `--target`/samba for `restore`). Paths are compared exactly,
after cleaning, and may not contain substitutions (`%`).

After a real restore, the operator's custom parameters (TLS files and
DNS forwarders, for example) are in `etc/smb.conf.orig` for review; copy them over by
hand, never the whole file.

### The Samba backup file

samba-tool extracts the backup file (and the `sysvol.tar.gz` nested in it)
with Python's `tarfile` as root. Its extraction filter refuses most
tricks, but has had bypasses, so conductor-backup reads both archives first
and refuses links (symbolic and hard), devices, FIFOs, absolute names,
names with `..`, set-user-ID or set-group-ID files and duplicate names.
`samba-tool domain backup online` writes only directories and regular
files.

### Files root writes after the restore

`restore` copies the DC's TLS files into the restored `private/` directory
(a tree samba-tool just built from backup content) and conductor's
database into conductor's own directory (owned by the conductor user).
Neither is followed: each copy goes through an `os.Root` at a trusted
directory, every directory on the way must be a real directory (not a
symbolic link), the data goes to a new file (`O_EXCL`, `O_NOFOLLOW`) that
gets its owner and mode through the descriptor, and is renamed into
place, so a link planted at the destination is replaced, never written
through. The drill's own files in its work directory are created the same
way.

## Decisions

- Online over loopback with a replication-only account: no downtime, and
  no administrator password on the DC for a scheduled job.
- Encryption inside the root helper: plaintext never reaches the
  unprivileged process or the network.
- Two helper sockets: adding conductor-backup to the conductor group would
  let it read conductor's TLS key.
- Destinations, credentials and recipients as host configuration only: a
  compromised web process must not be able to send future backups to a
  new key or bucket.
- Signed manifests, requests and reports: age alone does not authenticate
  the sender, and bucket access alone must not allow forging a backup, a
  drill result or a drill request.
- Drills off the DC in a namespace sandbox: decryption keys stay away
  from DCs, and a restored copy can never talk to the live domain.
- Own S3 client instead of an SDK: a small dependency tree, checked
  against published signing examples and an S3-compatible server.
- Fixed hourly timer with policy-driven slots: no unit edits or reloads
  from the web, and missed slots are retried.
