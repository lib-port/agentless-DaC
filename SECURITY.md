# Security policy

## Support status

Security reporting is not supported for this project. There is no vulnerability-report
intake, private disclosure channel, coordinated-disclosure process, response-time
commitment, or supported-version matrix. Do not submit suspected vulnerabilities by
issue, pull request, email, GitHub private reporting, or any other channel. Never send
the maintainer live malware, credentials, flags, decrypted victim content, or sensitive
evidence.

Users are responsible for evaluating the software, its dependencies, Detection Packs,
and their operating environment before use. Security-related changes may be made at the
maintainer's discretion, but no review, fix, notification, or release is promised. The
rest of this document describes known boundaries; it is not a warranty or support
commitment.

## Threat model

Detection Packs contain Python and therefore contain executable code. A detector
subprocess limits crashes, runtime, file descriptors, memory, and output, but it is not
an operating-system security boundary. In v0.1, only repository-reviewed first-party
packs are trusted. Do not run an unreviewed pack merely because its manifest says
`first_party: true`.

The core deliberately:

- never executes an input artifact;
- snapshots regular files through an already-open descriptor;
- rejects final-component symbolic links by default;
- verifies retained artifacts against their recorded size and SHA-256;
- runs detectors without the caller's environment variables;
- gives each detector a private working and temporary directory;
- invokes Python directly without a shell;
- validates and size-limits detector output;
- deletes raw snapshots unless retention is explicitly requested;
- creates evidence and report files with owner-only permissions.

For SSH acquisition, the core additionally:

- creates an ephemeral inventory and never writes passwords into it;
- accepts passwords only through Ansible's interactive prompt;
- enforces host-key checking, with `accept-new` available only by explicit opt-in;
- uses a core-owned playbook with fully qualified Ansible modules and no shell tasks;
- inspects absolute paths on POSIX SSH targets without following final-component links
  and fetches only named regular files;
- applies configured per-file and aggregate byte limits before eligible transfers;
- removes controller-side transport staging when the run finishes.

`--become` expands what the controller can read from the target and can make Ansible
buffer a remote file while calculating its checksum. Use it only when necessary. A
malicious or concurrently changing remote host can still race metadata inspection and
transfer; the downloaded result is therefore snapshotted and hashed again before any
detector sees it.

Pack installation rejects absolute paths, traversal, links, devices, duplicate archive
members, excessive file counts, and excessive expanded size.

## Malware handling

This repository must never contain live Hack The Box challenge binaries, malware,
credentials, flags, decrypted victim content, or other restricted artifacts. Tests use
small, non-executable synthetic byte sequences and reserved domains.

Analyze challenge files only on systems and data you are authorized to use. Prefer an
isolated malware-analysis virtual machine even though Detection Goggles performs static
analysis only.

The repository includes an operational
[Vagrant controller profile](docs/operations/vagrant-controller.md) that disables shared
folders and host-agent forwarding, runs as an unprivileged guest user, restricts network
egress to one declared SSH target, and exports only selected reports. This is defense in
depth rather than a warranty or secure sandbox. The Vagrantfile and provisioners execute
as trusted host/guest control code and must be reviewed before use; hypervisor escapes,
host compromise, and malicious target behavior remain outside this boundary.

The supported physical-host baseline is Debian 12 amd64 with exact Vagrant and provider
versions recorded in the playbook. Other hosts, architectures, tool versions, and nested
virtualization are outside the validated profile. Changing the target or any trusted
software component requires destroying and rebuilding the guest; it is not upgraded in
place.
