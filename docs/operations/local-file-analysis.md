# Playbook: local file analysis

## Objective

Run the Malevolent ModMaker detections against explicitly selected controller-local
files without executing or modifying the originals.

## Preconditions

- The core and pack pass the controller-setup verification.
- Files were obtained through an authorized Hack The Box workflow.
- Analysis occurs in an isolated malware-analysis environment.
- The operator has chosen whether raw evidence may be retained.
- The output filesystem has enough free space.

Under the disposable Vagrant profile, local means guest-local. Place or acquire evidence
inside `/var/lib/detection-goggles/evidence`; the profile intentionally provides no host
shared folder or raw-artifact upload/export command.

## Input selection

Prefer explicit file paths. Record the supplied paths and, when chain-of-custody matters,
record independent hashes before the run:

```bash
sha256sum ./evidence/artifact-one ./evidence/artifact-two
```

Do not open or execute challenge binaries to test whether they are valid. Detection
Goggles reads their bytes as data.

## Procedure: explicit files

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  ./evidence/artifact-two \
  --output ./reports
```

The source adapter opens each regular file, copies it into an owner-only temporary
bundle, hashes it, checks for changes during the copy, runs detections against the
snapshot, and removes that snapshot after reporting.

Record the CLI's exit code immediately in scripted operations:

```bash
dacctl run files htb-malevolent-modmaker ./evidence/artifact-one
result=$?
printf 'dacctl exit code: %s\n' "$result"
```

Interpret the code using the [standard outcome table](README.md#standard-command-outcome).

## Procedure: retain replayable evidence

Use retention only when raw snapshots are required:

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  ./evidence/artifact-two \
  --retain-evidence \
  --output ./reports
```

Retention adds `evidence/manifest.json` and `evidence/artifacts/` beneath the report run
directory. Treat the entire directory as sensitive. Continue with the
[evidence-retention playbook](evidence-replay.md).

## Procedure: directory recursion

Directories are rejected unless recursion is explicitly enabled:

```bash
dacctl run files htb-malevolent-modmaker ./evidence --recursive
```

Recursive traversal sorts directory and file names for deterministic input ordering.
It skips symbolic links by default and records each skip as an acquisition issue. A run
with any acquisition issue returns exit code `2`, even if other files were evaluated.

Following links is a separate, high-risk choice:

```bash
dacctl run files htb-malevolent-modmaker ./evidence \
  --recursive \
  --follow-symlinks
```

Enable it only after resolving link targets and confirming that expansion cannot escape
the intended dataset or create a directory cycle.

## Resource limits

Defaults are 128 MiB per file, 512 MiB total, 1,000 files, and a 10-second detector
timeout cap. Hard ceilings are 1 GiB per file, 4 GiB total, and 5,000 files. Lower the
operational limits when the expected dataset is smaller:

```bash
dacctl run files htb-malevolent-modmaker ./evidence \
  --recursive \
  --max-file-size 32MiB \
  --max-total-size 128MiB \
  --max-files 50 \
  --timeout 5
```

Size values accept bytes or `KiB`, `MiB`, and `GiB`. The detector timeout must be from
1 through 30 seconds. Hitting a file, byte, or count limit is an explicit acquisition
issue, not a clean result.

## Report review

The CLI prints the exact Markdown report path. Review the machine-readable summary
without executing report content:

```bash
RUN_ID="replace-with-run-id"
python -m json.tool "./reports/${RUN_ID}/report.json"
```

Confirm:

- `summary.artifact_count` equals the successfully acquired files;
- `summary.acquisition_issue_count` is zero for a complete run;
- every expected rule has an evaluation;
- evaluation statuses are understood;
- findings refer to expected display paths and hashes;
- the process exit code matches the report.

`MMM-003` is bundle-scoped and correlates loader and ransomware profiles on distinct
artifacts across the entire supplied set. Running related artifacts together is
therefore operationally different from scanning them in separate commands.

## Completion criteria

- The report directory is stored in the approved location.
- The run ID, pack ID, pack version, input hashes, and exit code are recorded.
- Any acquisition issue or detector error is resolved or the run is labeled incomplete.
- Temporary evidence was deleted automatically, or retained evidence is handled under
  the replay playbook.
- The original artifacts remain unchanged according to the operator's independent
  hashes when those hashes were recorded.
