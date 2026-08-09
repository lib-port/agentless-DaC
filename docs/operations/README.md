# Operational playbooks

These playbooks are the run procedures for Detection Goggles v0.1. They describe the
implemented command line and its safety boundaries; they are not a support commitment.
The project does not accept external contributions or security reports.

## Playbook index

| Operation | Use when | Playbook |
| --- | --- | --- |
| Prepare a controller | Installing the core or a pack on a new system | [Controller setup](controller-setup.md) |
| Isolate a controller VM | Running operational analysis away from the physical host | [Disposable Vagrant controller](vagrant-controller.md) |
| Analyze local artifacts | Challenge files are already on the controller | [Local file analysis](local-file-analysis.md) |
| Acquire named remote files | Authorized files reside on a POSIX SSH host | [SSH acquisition](ssh-acquisition.md) |
| Preserve or rerun evidence | A run must be reproducible without the original source | [Evidence retention and replay](evidence-replay.md) |
| Install, build, or release a pack | Managing the independently packaged first-party pack | [Pack lifecycle](pack-lifecycle.md) |
| Diagnose a failed or partial run | A command returns exit code 2 or an unexpected result | [Troubleshooting](troubleshooting.md) |

Read [the architecture reference](../ARCHITECTURE.md) for component ownership and data
flow, and [the security policy](../../SECURITY.md) before handling challenge artifacts.

## Operator responsibilities

Before every run, the operator is responsible for confirming:

- the target, files, credentials, and data are authorized for analysis;
- the controller is an appropriate malware-analysis environment;
- the Detection Pack and core version are the intended trusted versions;
- output and retained evidence have an approved storage location;
- requested size, count, recursion, symlink, SSH, and privilege options are deliberate;
- no sensitive material will be sent to the project maintainer.

Detection Goggles never executes an input artifact, but trusted Detection Pack Python is
executable code on the controller. The detector subprocess is not an operating-system
sandbox.

## Standard command outcome

Every invocation that reaches reporting writes a unique report directory. The process
exit code is part of the operational result:

| Exit code | Operator interpretation | Required action |
| ---: | --- | --- |
| `0` | Complete evaluation; no rule matched | Review the report and record the negative result |
| `1` | Complete evaluation; at least one rule matched | Triage findings and preserve the report |
| `2` | Partial acquisition, unavailable evidence, or operational/detector error | Treat the run as incomplete and follow the troubleshooting playbook |

A finding and an operational error can occur in the same run. Exit code `2` takes
precedence because the result set is incomplete.

## Standard output layout

With the default `--output reports`, a run produces:

```text
reports/<run-id>/
├── report.json
├── report.md
└── evidence/          only when --retain-evidence is selected
```

Use `report.json` for automation and `report.md` for analyst review. Both can contain
sensitive paths, hashes, host identifiers, and detection details. Retained evidence also
contains raw snapshots.

## Operational invariants

- Do not interpret `not_detected` as proof that a file is safe.
- Do not interpret a partial run as a clean result.
- Do not alter retained evidence if it may be replayed later.
- Do not put credentials in a pack, registry, report, shell argument, or evidence file.
- Do not enable recursion, symlink following, `accept-new`, or `become` by habit.
- Do not run a pack solely because its manifest claims `first_party: true`.
- Do not send reports, diagnostics, artifacts, or suspected vulnerabilities to the
  maintainer.
