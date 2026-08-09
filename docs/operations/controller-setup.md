# Playbook: controller setup

## Objective

Prepare an isolated controller with the Detection Goggles core and the one first-party
Malevolent ModMaker Detection Pack.

This playbook installs directly into an already isolated controller. To create a
disposable KVM guest on the supported bare-metal Debian 12 amd64 host, use the
[Vagrant controller playbook](vagrant-controller.md) instead.

## Preconditions

- Python 3.11 or newer is installed.
- The controller account owns a private working directory.
- The repository checkout or a trusted core wheel is available.
- If SSH acquisition is required, OpenSSH and Ansible can run on the controller.
- The operator has read [SECURITY.md](../../SECURITY.md).

## Procedure: source checkout

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

For remote acquisition, install the optional SSH dependency as well:

```bash
python -m pip install -e '.[dev,ssh]'
```

The source-tree pack is discoverable while the current directory is the repository.
Confirm the installation:

```bash
dacctl --version
dacctl pack list
dacctl pack validate htb-malevolent-modmaker
```

Expected pack properties are version `0.1.1`, sources `files,evidence,ssh`, three rules,
and `remote_execution: false`.

## Procedure: built core and local pack archive

Install a trusted core wheel into a clean virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install ./detection_goggles-0.1.0-py3-none-any.whl
```

Install Ansible support only if needed:

```bash
python -m pip install './detection_goggles-0.1.0-py3-none-any.whl[ssh]'
```

Local pack archives require an explicit SHA-256:

```bash
dacctl pack install ./htb-malevolent-modmaker-0.1.1.tar.gz \
  --sha256 79083d7e291a4687edae28c91df153c652772899c483a34bc91ee47eeb732e1b
```

Then confirm discovery from outside the source checkout:

```bash
dacctl pack list
dacctl pack validate htb-malevolent-modmaker@0.1.1
```

## Procedure: registry installation after publication

Registry operations need outbound HTTPS and require the registry plus matching immutable
release asset to have been published. Before the first release, use the local archive
procedure above. After publication, inspect the available identity and version:

```bash
dacctl pack available
```

Install by ID:

```bash
dacctl pack install htb-malevolent-modmaker
```

The client selects a core-compatible version, checks the downloaded SHA-256 against the
registry, validates the extracted pack, and installs it under the per-user data
directory. A digest match establishes consistency with the registry; it does not make
pack code safe.

For an offline registry copy:

```bash
dacctl pack available --registry ./registry/packs.yml
dacctl pack verify ./htb-malevolent-modmaker-0.1.1.tar.gz \
  --registry ./registry/packs.yml
```

## Optional pack roots

Use a global CLI option when a pack is stored outside the default locations:

```bash
dacctl --pack-root /opt/detection-goggles/packs pack list
dacctl --pack-root /opt/detection-goggles/packs \
  run files htb-malevolent-modmaker ./sample.bin
```

For multiple persistent roots, set `DAC_PACK_PATH` to an operating-system path-separated
list. Prefer `--pack-root` in recorded procedures because it makes the selected source
explicit.

## Controller preparation

Create separate, owner-only locations for source artifacts and reports:

```bash
mkdir -m 700 evidence reports
```

Do not place the virtual environment, source artifacts, or reports in a shared or
automatically synchronized directory. Ensure the filesystem has enough space for the
configured acquisition limit plus reports and any retained evidence.

For SSH runs, verify the actual Ansible executable and core playbook syntax:

```bash
ansible-playbook --version
ansible-playbook --syntax-check -i 'dac_target,' \
  src/detection_goggles/ansible/fetch_files.yml
```

## Verification checklist

- `dacctl --version` reports the expected core version.
- `dacctl pack validate` succeeds for the exact intended pack version.
- `dacctl pack list` reports only expected paths, identities, and versions.
- The report and evidence locations are owner-only.
- Ansible is installed only when SSH acquisition is required.
- No password, key content, malware, or sensitive evidence is stored in shell history or
  project files.

## Rollback and removal

The CLI has no uninstall command. Installed packs are versioned, so an operator can
select an older installed version explicitly with `pack-id@version`. Remove an installed
version only after resolving its exact per-user path and confirming that no recorded
procedure depends on it. Removal and secure disposal are operator-managed activities.
