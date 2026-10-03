# Security policy

Samba Conductor manages Active Directory domains, so a vulnerability in it
can mean control over a whole domain. Please report security problems
privately and give us time to fix them before they are disclosed.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/openbasalt/samba-conductor-backup/security/advisories/new>
(the "Report a vulnerability" button under the Security tab).

Do not open a public issue, pull request or discussion for a security
problem. If the problem is in another component of the family, report it
there, or here if you are not sure: we move reports between repositories.

Please include what you can of:

- the component, version (`<binary> version` or the package version) and
  distribution;
- the configuration involved (remove secrets, host names and addresses you
  do not want to share);
- steps to reproduce, and what an attacker gains (who the attacker is:
  anonymous network client, signed-in user, helpdesk, administrator, local
  user on the host);
- whether you want to be credited, and how.

We aim to acknowledge a report within 7 days and to agree on a disclosure
date with you, normally within 90 days of the report or when a fix is
released, whichever comes first. Fixes are published as a new release with
a GitHub security advisory (and a CVE when it applies).

## Supported versions

Until 1.0, only the latest release of each component receives security
fixes. Samba Conductor v1 (`edimarlnx/samba-conductor`, Meteor) is not
maintained and will not receive fixes.

## Verifying releases

Release packages are listed in a `SHA256SUMS` file signed with the project's
release key (`SHA256SUMS.asc`); the APT repository is signed with the same
key. Check the key fingerprint against the one published on the project's
site before trusting it.

## Components

| Repository | Component |
|---|---|
| [samba-conductor](https://github.com/openbasalt/samba-conductor) | conductor: web administration, self-service, conductor-helper |
| [samba-conductor-idp](https://github.com/openbasalt/samba-conductor-idp) | conductor-idp: OpenID Connect and SAML identity provider |
| [samba-conductor-sync](https://github.com/openbasalt/samba-conductor-sync) | conductor-sync: provisioning to Google Workspace |
| [samba-conductor-backup](https://github.com/openbasalt/samba-conductor-backup) | conductor-backup: encrypted backups and restore drills |
| [samba-conductor-files](https://github.com/openbasalt/samba-conductor-files) | conductor-files: agent on domain-member file servers |
| [samba-conductor-ad](https://github.com/openbasalt/samba-conductor-ad) | the `ad` Go library shared by the components |
