# Playbook: evidence retention and replay

## Objective

Preserve acquired snapshots in managed storage and repeat detections without reading
the original local source or reconnecting to the target. Replay always runs in the
mandatory offline container workflow.

## Retain the original acquisition

```bash
dacctl run files htb-malevolent-modmaker \
  ./evidence/artifact-one \
  --retain-evidence \
  --output ./reports
```

The same retention option is available on SSH acquisition and replay. Host output
contains only:

```text
reports/<run-id>/
├── report.json
└── report.md
```

Raw snapshots remain in a project-managed volume. Host metadata under
`${XDG_DATA_HOME:-~/.local/share}/detection-goggles/controller/evidence/`
records the retained run's reference; it is not a raw evidence export.

The managed bundle contains `manifest.json` and `artifacts/file-<number>` files.
Its manifest records source information, the original evidence run ID, artefact IDs,
display paths, sizes, SHA-256 digests, media types, modification times and acquisition
issues.

## List and replay a managed run

```bash
dacctl evidence list
dacctl run evidence htb-malevolent-modmaker@0.1.2 \
  --run-id RUN_ID \
  --output ./replay-reports
```

Use the exact retained ID and pin the pack version when comparing rule behaviour.
Replay validates schema, path containment, regular-file status, size and SHA-256,
then creates a new snapshot for analysis. The retained source is not modified or
executed. Normal count and byte limits apply before content is admitted.

A replay receives a new `run.id` while `run.evidence_run_id` refers to the original
evidence. Compare pack versions, original evidence IDs, artefact hashes, evaluations,
findings and acquisition issues. UUIDs and measured durations are run-specific and
need not match. A changed pack version can produce a different result.

Add `--retain-evidence` to preserve the new run's managed snapshot as well.

## Import an existing bundle

An explicitly selected Evidence Bundle v1 directory can be imported:

```bash
dacctl run evidence htb-malevolent-modmaker@0.1.2 \
  ./authorised-saved-bundle \
  --output ./replay-reports
```

Provide either the bundle path or `--run-id`, not both. The importer validates the
manifest and referenced artefacts, then copies only admitted content into managed
storage. It does not give analysis a broad mount of the directory's parent.

This path supports an existing authorised bundle, including one produced by an older
checkout. The new retention workflow does not create host `reports/<id>/evidence`
directories or offer ordinary raw-evidence export.

## Integrity failure

An integrity error means the content cannot be treated as the recorded bundle.
Preserve its state according to local procedures, compare independent checksums or
backups, and reacquire from the authorised source where possible. Do not edit hashes
or paths simply to make replay succeed. Evidence reacquired from different bytes is a
new acquisition.

## Remove retained evidence

```bash
dacctl evidence remove RUN_ID
```

Resolve the intended run with `evidence list` first. Removal deletes that run's managed
state. It does not delete previously exported reports, independently imported source
bundles, backups or snapshots, and it does not guarantee secure erasure.

The operator owns retention decisions. There is no automatic retention scheduler or
secure-delete facility. Stored reports, managed volumes and their underlying rootless
container storage must follow the operator's access-control and disposal procedures.
