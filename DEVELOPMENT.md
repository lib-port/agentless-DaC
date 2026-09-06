# Maintainer development guide

This document records the project's internal contracts and release procedure.
Detection Goggles does not accept external code, documentation, Detection Pack or
pull-request contributions.

## Execution and testing

All detector execution, including synthetic detector tests, requires the container
runtime. Do not run pack entrypoints, engine tests or the complete pytest suite
directly on the host. A missing runtime is a failure, not a reason to substitute native
execution or report skipped integration checks as successful.

From a trusted checkout with rootless Podman configured:

```bash
scripts/container-build
dacctl runtime doctor
scripts/container-test
scripts/container-verify
```

The scripts use immutable image IDs recorded in
`${XDG_CONFIG_HOME:-~/.config}/detection-goggles/images.json`. Test and validation
tooling belongs in the test image; production analysis uses the runtime image.
Application code, packs and dependencies are trusted inputs to the image build.
Inspect changes before rebuilding and review the resulting versions and digests.

Host-side static lint or syntax checks are useful, but do not replace the container
suite. Never mount the host Podman socket, home directory or SSH directory into a
detector workload to make a test pass.

## Detection Pack contract

A Detection Pack:

- contains `pack.yml`, its own licence and at least one declared detection;
- keeps each rule under `detections/<RULE-ID>/` with `rule.yml` and a Python entrypoint;
- depends only on a compatible core version, never another pack;
- declares its sources, execution policy and supported report formats;
- emits protocol-v1 JSON that validates against the detector-output schema;
- includes clean and matching synthetic tests;
- contains no credentials, flags, restricted lab material or live malware.

The manifest's detection list is authoritative. Missing entrypoints, undeclared rule
directories and paths escaping the pack fail validation. Versions use canonical stable
`X.Y.Z` syntax. Detection implementations use the Python standard library; shared
profile logic may live directly under `detections/` and should be loaded explicitly.

The SSH source is a core-owned adapter. Packs may declare it while keeping
`remote_execution: false`. Pack collectors, scripts and playbooks never run on the
target. Detectors consume acquired evidence; they do not independently acquire files
or connect to networks.

Artefact-scope rules receive one file at a time. Bundle-scope rules receive the complete
evidence set; distinct roles in a multi-stage correlation require distinct artefacts.
Finding subjects must belong to the detector request. Each invocation reads one JSON
request on standard input and writes one JSON object on standard output. Diagnostic
output is bounded and is not copied wholesale into reports.

## Container boundary

The launcher must fail closed when rootless execution, cgroup v2, pinned images or
required resource controls are unavailable. Each command creates disposable workloads.
Analysis has no network, credentials or broad host application mounts. SSH acquisition uses
a newly created network namespace whose initialiser installs the target allowlist
before the acquisition process starts. The initialiser's network capability is not
granted to analysis or acquisition workers.

Only selected local inputs and explicitly selected private keys may be imported.
Installed packs, retained evidence and target credentials use managed storage.
Normal report export accepts only the expected JSON and Markdown files; it must reject
links, traversal, excessive sizes, unexpected members and existing destinations.
Pack downloads run separately from evidence processing and never receive target keys.

Rootless containers share the host kernel. Tests cannot establish a virtual-machine
security boundary. The initial host integration target is native Linux amd64 with
cgroup v2, initially Kali Linux and Podman 5.8.6.

## Required integration validation

Follow the [container playbook](docs/operations/containers.md) using a controlled SSH
target with synthetic non-sensitive fixtures. Record the host, kernel, Podman, OCI
runtime, network backend and image IDs. Verify both allowed and denied network paths,
credential separation, input admission, report rejection, retained-evidence replay,
interrupt cleanup and repeated runs.

An unavailable Podman installation or missing host privilege is an incomplete check.
Keep its failure visible in the validation record. Do not claim that documentation,
unit mocks or static tests prove actual networking, resource enforcement or isolation.

## Packaging and release

The core wheel and Detection Pack archives remain separate. Run package validation
and builds in the test/build container workflow, then validate the trusted pack:

```bash
dacctl pack validate htb-malevolent-modmaker
dacctl pack build htb-malevolent-modmaker --output dist-a
dacctl pack build htb-malevolent-modmaker --output dist-b
cmp dist-a/htb-malevolent-modmaker-0.1.2.tar.gz \
  dist-b/htb-malevolent-modmaker-0.1.2.tar.gz
dacctl pack verify dist-a/htb-malevolent-modmaker-0.1.2.tar.gz \
  --registry registry/packs.yml
```

Any core contract change requires all pack tests. A change to pack behaviour, metadata,
tests or shipped documentation requires an appropriate independent version increase
and a new archive digest. Builds must be deterministic and obey installer entry-count
and expanded-size limits. A failed build must not publish a partial archive.

Releases are prepared manually using the [pack lifecycle playbook](docs/operations/pack-lifecycle.md).
No publication or operational validation is implied by a committed registry entry.
