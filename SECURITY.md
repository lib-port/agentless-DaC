# Security policy

## Support status

Security reporting is not supported for this project. There is no vulnerability-report
intake, private disclosure channel, coordinated-disclosure process, response-time
commitment or supported-version matrix. Do not submit suspected vulnerabilities by
issue, pull request, email, GitHub private reporting or any other channel. Never send
the maintainer live malware, credentials, flags, decrypted victim content or sensitive
evidence.

Users are responsible for evaluating the software, dependencies, Detection Packs and
operating environment before use. Security-related changes may be made at the
maintainer's discretion, but no review, fix, notification or release is promised. This
document describes operational boundaries; it is not a warranty or support commitment.

## Execution boundary

Detection Packs contain executable Python. Only reviewed, trusted first-party packs
are intended for use. A manifest's `first_party: true` field is not a trust decision.
The launcher requires rootless Podman for every detector run, including tests, and
does not fall back to native execution when runtime verification fails.

Disposable analysis workloads use a read-only image, an unprivileged account, bounded
resources, no external network and no target credentials. They receive selected
evidence through managed storage and use the selected pack from the image, managed
storage or an explicitly selected read-only pack input. The operator's home, SSH
directory, full checkout and container-engine socket are not workload mounts.
Detector subprocess limits remain useful within that boundary.

CPU, memory, process and scratch-space limits do not guarantee host availability.
Managed named volumes have no hard disk quota: evidence size checks and normal cleanup
do not prevent hostile code from exhausting host storage. Monitor free space and remove
retained state deliberately; unreviewed packs remain out of scope.

Rootless containers share the host kernel. They do not provide a separate guest kernel
or protection equivalent to a virtual machine. Kernel, Podman, OCI runtime and network
backend vulnerabilities can defeat the boundary. A compromised host or account can
also access its rootless container storage. An already hostile pack remains an
unacceptable dependency even if its execution is containerised.

The initial host integration target is native Linux amd64 with cgroup v2, initially
Kali Linux and Podman 5.8.6. Real runtime, networking and cleanup checks must pass on
the actual host before operational use. Static checks and mocked tests do not validate
this boundary; see the [container playbook](docs/operations/containers.md).

## Evidence and reports

The core treats input artefacts as data and never executes them. It snapshots regular
files through open descriptors, applies count and size limits, records SHA-256 hashes
and rejects unexpected input types. Symbolic links are rejected by default; selecting
a directory never grants access to a link destination outside that selection.

Retained evidence is validated against its recorded size and hash, then re-snapshotted
before replay. Runtime evidence and retained raw content use managed volumes. Reports
export only validated JSON and Markdown through bounded, regular-file checks; raw
evidence and private keys are not exported alongside them. Sensitive paths, host
identifiers, hashes and detection details can still appear in reports.

Temporary workloads and unretained evidence are cleaned up after use. Explicit target
or evidence removal deletes the named managed storage; it does not guarantee secure
erasure from the underlying filesystem, backups or snapshots. The project has no
secure-delete or automatic retention scheduler.

## SSH and credentials

Target profiles pin a literal IPv4 address, SSH port and independently verified
host-key fingerprint. Initialisation generates an encrypted target key in managed
storage and prints only its public key. Existing private keys may be explicitly
imported for a run. Broad SSH-directory mounts and host-agent forwarding are not part
of the workflow; passwords are accepted only by interactive prompting.

Every SSH operation uses a fresh rootless network namespace. A short-lived initialiser
installs a default-deny nftables policy allowing the saved target and port before the
acquisition worker starts. Its network-administration capability is confined to that
namespace and is not granted to detection or acquisition workers. Host-key checking
remains strict, and analysis runs separately with networking disabled and no keys.

The core-owned Ansible playbook fetches only named absolute regular paths. It does not
execute pack scripts or artefacts on the target. Ansible may stage its own transient
modules remotely. A changing or malicious target can race metadata inspection and
transfer, so controller-side limits and hashing are applied after transfer as well.
`--become` expands accessible data and may cause Ansible to buffer remote content.

Removing a local target profile does not revoke its public key on the remote host.
The operator must remove that key from the target account separately.

## Dependencies and packs

The image configuration records immutable local IDs. Runtime operations do not silently
replace those images. A deliberate rebuild is required for trusted code or dependency
updates. Digest consistency establishes identity, not trust in the source or package.

Registry downloads use a separate disposable workload with no evidence or credential
mounts. Pack installation verifies digests and rejects unsafe archive paths, links,
devices, duplicate members and excessive sizes or entry counts. Installed packs use
managed storage; callers cannot redirect installation into arbitrary host directories.
A compromised registry can still publish malicious content with matching metadata.

## Malware handling

This repository must never contain live Hack The Box challenge binaries, malware,
credentials, flags, decrypted victim content or other restricted artefacts. Tests use
small synthetic byte sequences and reserved domains. Analyse only systems and data you
are authorised to use. Reports and retained evidence must follow the operator's own
storage, access-control and disposal procedures.
