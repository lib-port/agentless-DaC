# Playbook: controller setup

## Objective

Prepare the host launcher and mandatory rootless Podman runtime. The initial
integration target is native Linux amd64 with cgroup v2, initially Kali Linux with
Podman 5.8.6. Containerised or nested development sessions can support some checks, but
do not by themselves demonstrate the intended host boundary.

## Host prerequisites

Install Podman, its rootless networking/storage dependencies and Python 3.11 or newer
through the host's trusted package manager. System package installation and subordinate
UID/GID configuration may require an administrator. Run project commands as the
ordinary operator account, never through `sudo podman`.

Rootless execution requires usable subordinate UID/GID ranges and delegated cgroup v2
CPU, memory and process controls. Verify the installed environment:

```bash
podman --version
podman info --debug
python3 --version
```

The currently selected integration baseline uses Podman 5.8.6, netavark 1.17.2 and
crun 1.28. Record actual versions when validating another host. A version string alone
does not establish that networking, storage or resource limits work.

## Install the launcher

From a trusted checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

The host installation provides `dacctl` and orchestration dependencies. Ansible and
detector execution belong in container images; installing Ansible on the host does not
satisfy the runtime requirement.

Inspect the trusted source and build the images:

```bash
scripts/container-build
dacctl runtime doctor
scripts/container-verify
```

The build records immutable local runtime, network and test image IDs in
`${XDG_CONFIG_HOME:-~/.config}/detection-goggles/images.json`. Runtime commands use
those IDs without automatically pulling changed tags. Rebuild deliberately when the
reviewed source or dependency set changes.

## Confirm packs and validation

```bash
dacctl --version
dacctl pack list
dacctl pack validate htb-malevolent-modmaker
scripts/container-test
```

The source pack is version `0.1.2`, declares `files,evidence,ssh`, contains three
rules and sets `remote_execution: false`. The image contains the reviewed
source pack from its build snapshot; source edits require a rebuild or an explicitly
selected read-only pack input. Unrelated current directories are not searched.

Installed packs use managed container storage. A local archive installation requires
an explicit SHA-256; registry installation requires a published registry and matching
immutable release asset. Follow the [pack lifecycle playbook](pack-lifecycle.md).

## Storage and operating checks

Host metadata lives under
`${XDG_DATA_HOME:-~/.local/share}/detection-goggles/controller/`.
Project-managed volumes hold installed packs, retained evidence and target credentials.
Container storage belongs to the operator's rootless Podman account.

Choose an owner-only host report directory with enough space. Selected local inputs
are copied into managed storage; containers do not need the source parent directory,
home directory or SSH directory mounted. Raw evidence stays in managed storage unless
an existing external evidence bundle is explicitly supplied as an input.

Before handling real evidence, complete the [container validation procedure](containers.md).
Confirm runtime prerequisites, image identities, allowed and denied network behaviour,
offline analysis, credential separation, bounded export and cleanup. Record failures
as incomplete validation.

## Target setup and retirement

Register a target using `dacctl target init` with its IPv4 address, port and
independently verified fingerprint; see [SSH acquisition](ssh-acquisition.md).
A generated private key stays encrypted in managed storage, and the printed public
key must be registered on the intended remote account.

Use `dacctl target remove NAME` and `dacctl evidence remove RUN_ID` for explicitly
selected managed state. Remove retired public keys from their target accounts
separately. These operations do not guarantee secure erasure of backing storage.

The former Vagrant profile is not part of this runtime. Existing virtual machines,
disks or credentials created by an earlier checkout are not migrated or destroyed
automatically; retire them using the reviewed earlier lifecycle and revoke their
remote keys before discarding that environment.
