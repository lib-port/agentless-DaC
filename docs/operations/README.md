# Operational playbooks

These playbooks describe Detection Goggles' mandatory rootless Podman workflow.
They are operating procedures, not a support or security warranty. The project does
not accept external contributions or security reports.

| Operation | Playbook |
| --- | --- |
| Install the launcher and prepare rootless Podman | [Controller setup](controller-setup.md) |
| Build, check and validate disposable workloads | [Container runtime](containers.md) |
| Analyse explicitly selected local files | [Local file analysis](local-file-analysis.md) |
| Register a target and acquire named remote files | [SSH acquisition](ssh-acquisition.md) |
| Retain, replay and remove managed evidence | [Evidence replay](evidence-replay.md) |
| Validate, build and install trusted packs | [Pack lifecycle](pack-lifecycle.md) |
| Diagnose incomplete or failed operations | [Troubleshooting](troubleshooting.md) |
| Inspect recorded migration checks and outstanding validation | [Validation record](validation-record.md) |

Read [the architecture](../ARCHITECTURE.md) and [security policy](../../SECURITY.md)
before handling evidence. The operator is responsible for authorisation, pack trust,
the actual host's validation, target-key verification, report handling and retention.

## Standard outcome

| Exit code | Interpretation |
| ---: | --- |
| `0` | Complete evaluation; no detections |
| `1` | Complete evaluation; detections require triage |
| `2` | Partial acquisition, unavailable evidence or an operational error |

An error takes precedence over detections in the same run. If failure occurs before
reporting, the command can return `2` without producing a normal run report.
Do not interpret a partial run as clean or a negative result as proof of safety.

## Reports and retention

The default host output contains only:

```text
reports/<run-id>/
├── report.json
└── report.md
```

Use JSON for automation and Markdown for analyst review. Both may contain sensitive
paths, hashes, target identifiers and findings. Treat them as untrusted text.

`--retain-evidence` preserves raw snapshots in managed container storage. It does not
add raw evidence to the host report directory. Use `dacctl evidence list`,
`dacctl run evidence PACK --run-id RUN_ID` and `dacctl evidence remove RUN_ID`
to manage retained runs.

## Operational invariants

- Use only reviewed packs and artefacts you are authorised to analyse.
- Run detections and detection tests through the container workflow.
- Stop when runtime, image identity or network-policy checks fail.
- Supply selected files rather than broad home or SSH-directory mounts.
- Obtain target host-key fingerprints through an independent trusted channel.
- Keep passwords out of arguments, reports and metadata.
- Remove remote public keys separately when retiring target profiles.
- Do not send diagnostics, reports, artefacts or suspected vulnerabilities to the maintainer.
