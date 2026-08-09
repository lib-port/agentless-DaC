# Maintainer development guide

This document records the project's internal contracts and release procedure for its
maintainer. Detection Goggles does not accept external code, documentation, Detection
Pack, or pull-request contributions.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component contracts and
[docs/operations/pack-lifecycle.md](docs/operations/pack-lifecycle.md) for the complete
manual release playbook.

## Detection Pack contract

A Detection Pack:

- must contain `pack.yml`;
- must declare at least one detection;
- must keep every detection in `detections/<RULE-ID>/` with `rule.yml` and a Python
  entrypoint;
- must depend only on a compatible core version, never another pack;
- must declare every input source and whether it permits remote execution;
- must declare at least one supported report format;
- must emit protocol-v1 JSON that validates against the detector-output schema;
- must include clean and matching synthetic tests;
- must not contain credentials, flags, restricted lab material, or live malware.

Pack-provided remote execution is not part of the v1 contract. The `ssh` source is a
core-owned, generic adapter that fetches only user-selected regular files. A pack may
declare that source while keeping `remote_execution: false`; collectors, playbooks, or
scripts inside a pack are never invoked on the target.

The manifest's `detections` list is authoritative. Undeclared detection directories and
missing entrypoints fail validation.

Pack versions use canonical stable `X.Y.Z` syntax. Shared, standard-library-only profile
logic may live directly under `detections/`; rule entrypoints should load it explicitly
so artifact and correlation rules cannot drift.

Detector implementations should use only the Python standard library. They receive one
JSON request on standard input and must write exactly one JSON object to standard output.
Diagnostics may be written to standard error, but reports intentionally expose only
bounded failure information.

Artifact-scope detections receive one artifact at a time. Bundle-scope detections receive
the complete evidence set and should be reserved for correlation. A multi-stage
correlation must require distinct artifacts for distinct roles. Findings must refer only
to artifact IDs present in the request.

## Tests and packaging

The maintainer runs the complete validation set locally:

```bash
ruff check .
ruff format --check .
pytest
dacctl pack validate htb-malevolent-modmaker
dacctl pack build htb-malevolent-modmaker --output dist
.venv/bin/ansible-playbook --syntax-check -i 'dac_target,' \
  src/detection_goggles/ansible/fetch_files.yml
```

Changes to the disposable controller profile additionally require:

```bash
bash -n scripts/vm-* vm/guest/dac-key-init vm/provision/bootstrap.sh
sh -n vm/guest/dacctl
shellcheck scripts/vm-* vm/guest/dac-key-init vm/guest/dacctl \
  vm/provision/bootstrap.sh
ruby -c Vagrantfile
```

On Debian 12 amd64 with CPython 3.11, verify the committed lock files with:

```bash
scripts/vm-locks check
```

When dependency ranges or pins intentionally change, regenerate both environments from
canonical PyPI, review every version and digest, and recheck the result:

```bash
scripts/vm-locks update
git diff -- requirements/vm.lock requirements/vm-runtime.lock
scripts/vm-locks check
```

The runtime lock must remain a strict subset without build, pytest, Ruff, or setuptools.
Hash agreement proves consistency with the selected wheel; it is not a trust decision.

Before release, complete the initialization, verification, allowed/denied network,
synthetic acquisition, report rejection/export, reboot, destruction, and key-revocation
procedure in the
[physical-host release validation](docs/operations/vagrant-controller.md#physical-host-release-validation)
section. Use a clean bare-metal Debian 12 amd64 KVM/libvirt host. A container or nested-VM
run cannot validate the hypervisor, management network, mount isolation, nftables, or
destruction behavior.

Any change to a core contract requires all pack tests to be run. A pack release receives
an independent semantic version and immutable archive; changing pack behavior requires
an appropriate version increment. Before publishing, build twice, compare the archives
byte-for-byte, and verify the final digest against `registry/packs.yml`.
Every independently distributed pack archive includes its own license file. The builder
must reject any source tree that would exceed installer entry-count or expanded-size
limits and must not expose a partial final archive after failure.
