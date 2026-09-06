# Playbook: local file analysis

## Objective and prerequisites

Analyse explicitly selected controller-local files using trusted static detections in
a disposable offline container. The rootless runtime and pinned images must pass
`dacctl runtime doctor`; follow [controller setup](controller-setup.md) first.

Choose authorised inputs, an owner-only report location and whether raw evidence
needs retention. Never execute a challenge binary to check whether it is valid.
For an independent source record, calculate hashes before acquisition:

```bash
sha256sum ./evidence/artifact-one ./evidence/artifact-two
```

## Analyse explicit files

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  ./evidence/artifact-two \
  --output ./reports
```

The launcher admits only selected regular inputs and copies their bytes into managed
storage. A container never receives a broad mount of the parent directory or operator
home. Snapshot acquisition records hashes and detects changes during copying.
The offline analysis workload receives no SSH keys and no external network.

Capture the exit code immediately when scripting:

```bash
dacctl run files htb-malevolent-modmaker ./evidence/artifact-one
result=$?
printf 'dacctl exit code: %s\n' "$result"
```

Code `0` means complete with no detections, `1` means detections, and `2` means an
incomplete run or operational error. A negative result does not establish safety.

## Directory selection and limits

Recursion requires an explicit option:

```bash
dacctl run files htb-malevolent-modmaker ./evidence --recursive
```

Traversal is deterministic. Links and non-regular input types are rejected by default;
a selected directory cannot grant access through a link outside that selection.
Acquisition issues make the result incomplete even if other files are analysed.

Defaults are 128 MiB per file, 512 MiB total, 1,000 files and a 10-second detector
timeout cap. Hard ceilings are 1 GiB per file, 4 GiB total and 5,000 files. For a small
expected set:

```bash
dacctl run files htb-malevolent-modmaker ./evidence \
  --recursive \
  --max-file-size 32MiB \
  --max-total-size 128MiB \
  --max-files 50 \
  --timeout 5
```

Size options accept bytes, `KiB`, `MiB` or `GiB`. The detector timeout is from 1 to
30 seconds and remains subject to each rule's own limit. Container resource limits
also apply. Increasing a timeout cannot repair unavailable evidence.

## Retain and replay

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  ./evidence/artifact-two \
  --retain-evidence \
  --output ./reports
dacctl evidence list
dacctl run evidence htb-malevolent-modmaker@0.1.2 --run-id RUN_ID
```

Retention keeps raw snapshots in managed storage. Host exports still contain only
`report.json` and `report.md`. Use the exact retained run ID printed by the command.
See [evidence replay](evidence-replay.md) for integrity checks and removal.

## Review the report

```bash
python -m json.tool ./reports/RUN_ID/report.json
```

Check artefact count, acquisition issues, the expected rule evaluations, subject paths
and hashes, pack version and the process exit code. Reports can contain sensitive
metadata and should be viewed as untrusted text.

`MMM-003` correlates loader and ransomware profiles on distinct artefacts across the
supplied set. Related files must be analysed together for that correlation to run.
Separate single-file commands are not equivalent.

Record the run ID, pack version, input hashes and exit code. Resolve acquisition issues
or label the result incomplete. Unretained evidence and temporary workloads should be
cleaned up; retained runs remain until explicitly removed.
