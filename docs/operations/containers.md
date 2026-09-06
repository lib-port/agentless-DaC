# Playbook: disposable container runtime

## Objective and boundary

Run acquisition, analysis, pack downloads and validation through disposable rootless
Podman workloads. Analysis is offline and has no target keys. SSH acquisition receives
only the saved target's network access and selected credentials. Host exports contain
JSON and Markdown reports; raw evidence, installed packs and keys use managed storage.

Containers share the host kernel. This profile does not provide the isolation of a
virtual machine, protection against a kernel/runtime escape or safety for unreviewed
pack code. The host account, Podman, OCI runtime, network backend, images and trusted
pack remain security dependencies.

The initial integration target is native Linux amd64 with cgroup v2, initially Kali
Linux using Podman 5.8.6, netavark 1.17.2 and crun 1.28. Operational results must be
recorded on the actual host; the existence of this playbook is not validation.

## Prepare and inspect the host

Follow [controller setup](controller-setup.md). Run as the ordinary operator account:

```bash
podman --version
podman info --debug
dacctl runtime doctor
```

The runtime requires rootless operation, usable subordinate UID/GID ranges and cgroup v2
CPU, memory and process controls. Correct missing host prerequisites before use.
There is no native detector fallback or rootful substitute.

## Build immutable local images

From the reviewed checkout:

```bash
scripts/container-build
```

The build takes a source snapshot from tracked and non-ignored untracked worktree
files within its approved source directories and root metadata allowlist. Arbitrary
root files, local evidence and legacy VM state are excluded. Review both committed
and local changes first; credentials and real evidence must never enter the approved
source directories. The build records the source
commit, snapshot SHA-256, dirty status, file count and pinned base image alongside
immutable local image IDs.

Configuration is written to:

```text
${XDG_CONFIG_HOME:-~/.config}/detection-goggles/images.json
```

Its versioned structure identifies three image roles: `runtime`, `network` and
`test`. Runtime commands select the recorded `sha256:...` identities. They do not
silently pull replacements from a mutable tag. Review changes and rebuild deliberately
when application code, a trusted pack, base image or dependency locks change.

The runtime and test dependency locks are:

```text
requirements/container-runtime.lock
requirements/container.lock
```

The lock helper requires CPython 3.11 on Linux x86_64, matching the image's Python
environment. This requirement is separate from the launcher's Python 3.11-or-newer
requirement; a newer Kali system Python cannot regenerate these locks directly.
In the matching maintenance environment, check or deliberately regenerate them:

```bash
scripts/container-locks check
scripts/container-locks update
```

Review every changed version and digest before rebuilding. A matching digest establishes
consistency with the selected package, not that the package itself is trustworthy.

## Offline verification and tests

```bash
dacctl runtime doctor
scripts/container-test
scripts/container-verify
```

The test script runs in the offline test image and accepts pytest arguments for a
focused run:

```bash
scripts/container-test tests/test_engine.py
```

Every detector test stays inside the container workflow. Do not invoke the pack
entrypoints or host pytest as a workaround for an unavailable runtime. Test tooling
does not need the host engine socket or broad host mounts.

Running `container-verify` without target options performs offline checks and reports
that target networking was not tested. Preserve that distinction in the validation
record.

The offline verifier checks the worker boundary and pack discovery. It does not run
the full test suite, test report rejection or prove lifecycle cleanup; run and record
those checks separately.

## Disposable SSH acceptance fixture

After building the reviewed images, the repository provides a live acceptance harness:

```bash
python3 containers/integration.py
```

Run it as the ordinary operator account on a controlled host and network. It builds a
disposable SSH service with a known synthetic password and a test account permitted
to use sudo. The service binds a temporary port on the selected host IPv4 address,
and a second temporary listener provides a network-policy control. Building the
fixture requires package-download access. Use only its generated keys and inert
samples; do not give this fixture production credentials or evidence.

The harness checks the runtime before creating the service, then exercises:

- clean and matching local files, all three detection rules, source preservation and
  rejection of a symbolic link outside the selected directory;
- managed evidence replay and partial acquisition of both local and remote files;
- generated encrypted keys, explicit key import, SSH passwords and sudo prompts,
  including a generated key followed by a separate become-password prompt;
- rejection of a wrong key passphrase and a wrong host-key fingerprint;
- permitted SSH access and denial of an adjacent port whose listener is first proven
  reachable from the host;
- pack build/install and host reports containing exactly JSON and Markdown, with no
  raw evidence, fixture passwords, passphrase or private-key marker;
- removal of the fixture's retained evidence, target profile and SSH service, and
  closure of its listener before the success message is printed.

Detectors still execute only in the mandatory analysis containers. Record the actual
result; listing these checks does not imply a completed run. The harness supplies
synthetic prompt input through pipes, so record separate PTY checks for terminal echo
suppression/restoration and separate interruption-cleanup checks. Export rejection,
tampered replay and the remaining acceptance cases below also need their own results.

## Live target-network verification

Use a controlled POSIX SSH target with non-sensitive synthetic files and an
independently verified host-key fingerprint:

```bash
scripts/container-verify \
  --target-ip 192.0.2.10 \
  --target-port 22 \
  --host-key-fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
```

Each acquisition creates a fresh rootless network namespace. A short-lived initialiser
installs a default-deny nftables policy before the worker begins, allowing only the
declared IPv4 address and port. The initialiser's network-administration capability
does not reach the acquisition or analysis process. Analysis subsequently runs in a
separate container with networking disabled.

Verify both sides of the policy: the target SSH connection must work, while DNS,
HTTPS, another controlled IPv4 address and another port fail. Confirm repeated
operations use fresh namespaces and that one run cannot inherit another target's
network permission. An offline pass or an active nftables service alone does not prove
these properties.

For a denied-port check, first prove that a controlled listener on that port is
reachable from the host, then prove that the acquisition namespace cannot connect.
A closed port or missing route cannot demonstrate firewall enforcement. The
disposable acceptance harness performs this comparison using its adjacent listener.

## Target credentials and acquisition

Create a saved target profile using the verified fingerprint:

```bash
dacctl target init lab \
  --host 192.0.2.10 \
  --port 22 \
  --host-key-fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
```

Initialisation creates an encrypted private key in managed storage and prints its
public key for registration on the remote account. The profile stores only identifying
metadata and its managed volume reference. The host SSH agent and SSH directory are
not forwarded. An existing key can be explicitly selected with `run ssh --identity`
without admitting sibling files.

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab \
  --user analyst \
  --remote-file /authorised/synthetic-fixture.bin
```

The SSH workload contains acquisition code and target credentials. The analysis
workload contains selected evidence and a trusted pack, with no target credentials.
A separate downloader handles registry traffic without either evidence or target keys.

## Reports and retained state

Reports export automatically to `--output`, normally `reports/<run-id>/`. There
is no separate report-export command. Export accepts only bounded regular
`report.json` and `report.md` files, refuses unsafe paths and existing destinations,
and creates owner-only output. Each report is limited to 10 MiB and must have exactly
one hard link with stable descriptor metadata during copying. View reports as
untrusted text.

`--retain-evidence` preserves a managed volume, not a raw host export:

```bash
dacctl evidence list
dacctl run evidence htb-malevolent-modmaker --run-id RUN_ID
dacctl evidence remove RUN_ID
```

Host metadata lives under
`${XDG_DATA_HOME:-~/.local/share}/detection-goggles/controller/`.
Private keys, raw evidence and installed packs are held in managed Podman volumes.

Named volumes have no hard disk quota. Evidence admission limits and bounded temporary
filesystems are not a quota on persistent storage. Monitor available host space and
remove retained evidence when no longer needed; resource controls do not guarantee
host availability against hostile pack code.

Temporary operation containers, namespaces and unretained data are cleaned up after
use. Target credentials and explicitly retained evidence persist until removed.
Retire a target with `dacctl target remove NAME`, then remove its public key from
the remote account. Volume deletion does not guarantee secure erasure.

## Operational acceptance record

Before using real evidence, record host/kernel versions, Podman/network/OCI versions,
cgroup delegation, source identity and all image IDs. Complete these checks:

1. The runtime rejects rootful operation, missing required controls and missing images.
2. Local synthetic analysis produces the expected clean and matching reports offline.
3. Selected-input admission rejects unsupported files, escaping links and excessive data.
4. The allowed target succeeds and disallowed destinations/ports fail.
5. Analysis cannot access acquisition keys, host SSH agents, broad host mounts or an
   engine socket.
6. A named synthetic SSH file is fetched, snapshotted and analysed with the expected
   source metadata and exit code.
7. Retained evidence replays without contacting the target, while altered evidence is
   rejected.
8. Export rejects traversal, links, excessive size, missing formats, unexpected files
   and existing destinations without publishing unintended content.
9. Interruptions and repeated runs clean up operation-owned resources without deleting
   retained or unrelated state.
10. Target removal and explicit evidence removal affect only the selected managed state.

Keep a short validation record with the UTC date, source snapshot digest, image IDs,
host/runtime versions, command and exit status for each check. Record the container
suite, live SSH harness, PTY behaviour and interrupted-run cleanup separately, with
links to their logs and any remaining unexecuted cases.

Record failures as failures and describe unexecuted checks as pending. Do not weaken
image identity, firewall policy, host-key checking, export admission or permissions
merely to obtain a successful test result.
