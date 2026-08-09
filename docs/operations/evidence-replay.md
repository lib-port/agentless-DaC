# Playbook: evidence retention and replay

## Objective

Preserve controller-side file snapshots with integrity metadata and rerun detections
without reading the original local path or reconnecting to the SSH target.

## Retain evidence during acquisition

Retention must be selected on the original run:

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  --retain-evidence \
  --output ./reports
```

The equivalent option is available on `run ssh` and `run evidence`.

The resulting layout is:

```text
reports/<run-id>/
├── report.json
├── report.md
└── evidence/
    ├── manifest.json
    └── artifacts/
        └── file-0001
```

The manifest records the original evidence run ID, source metadata, artifact IDs,
display paths, sizes, SHA-256 digests, media types, modification times, and acquisition
issues.

## Preserve the bundle

Treat the entire report directory as one record. Before moving it, record independent
checksums from inside the run directory:

```bash
sha256sum report.json report.md evidence/manifest.json evidence/artifacts/* \
  > CHECKSUMS.sha256
```

Move or archive the report only through an approved evidence-handling process. Preserve
owner-only access. A compressed archive does not add confidentiality; use storage-layer
encryption when required.

Do not rename files under `evidence/artifacts`, edit `manifest.json`, or replace links.
Artifact names are contract references, not original filenames.

## Replay procedure

```bash
RUN_ID="replace-with-original-run-id"
dacctl run evidence htb-malevolent-modmaker \
  "./reports/${RUN_ID}/evidence" \
  --output ./replay-reports
```

Before detection, replay validates the manifest schema, resolves every content reference
beneath the bundle root, rejects links, hashes every artifact, and compares both size and
SHA-256. It enforces the normal 128 MiB per-file, 512 MiB total, and 1,000-file defaults
before reading artifact content, with the same CLI limit options as other sources. It
then copies the verified evidence into a new temporary snapshot and detects against that
copy.

Use an exact pack version when reproducibility depends on rule implementation:

```bash
RUN_ID="replace-with-original-run-id"
dacctl run evidence htb-malevolent-modmaker@0.1.1 \
  "./reports/${RUN_ID}/evidence" \
  --output ./replay-reports
```

## Compare original and replay

The replay report has a new `run.id` and retains the original bundle's ID in
`run.evidence_run_id`. Compare:

- pack ID and version;
- evidence run ID;
- artifact IDs, sizes, and SHA-256 values;
- evaluation status per rule and subject;
- finding rule IDs and evidence;
- acquisition issues.

Finding and evaluation UUIDs and measured durations are run-specific and need not be
identical. A different pack version can legitimately produce different results.

## Retain a replay snapshot

To create a fresh retained copy beneath the replay report:

```bash
RUN_ID="replace-with-original-run-id"
dacctl run evidence htb-malevolent-modmaker@0.1.1 \
  "./reports/${RUN_ID}/evidence" \
  --retain-evidence \
  --output ./replay-reports
```

The source manifest remains unchanged; retention copies verified artifacts to the new
run directory.

## Integrity failure response

An integrity error means the retained directory cannot be treated as the manifest's
recorded evidence. Do not bypass the check or rewrite hashes to make replay succeed.
Instead:

1. stop using the affected bundle;
2. preserve its current state if local procedures require investigation;
3. compare it with independently stored checksums or backups;
4. reacquire from the authorized original source when possible;
5. label any report based on different evidence as a new acquisition.

## Completion criteria

- The exact pack version used for replay is recorded.
- Manifest and artifact integrity verification succeeded.
- Original and replay run IDs are distinguishable.
- Differences in evaluations or findings are explained.
- Stored reports and raw snapshots remain access-controlled.
- Disposal, when required, follows the operator's approved process; Detection Goggles
  has no secure-delete or evidence-retention scheduler.
