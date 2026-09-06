# Playbook: troubleshooting

## First response

Capture the command with secrets redacted, its exit code and any exported reports.
Inspect acquisition issues and every evaluation status. Record the core/pack versions,
runtime configuration and image IDs before retrying.

Do not send diagnostics, reports, artefacts, credentials or suspected vulnerabilities
to the maintainer. Security reporting is not supported.

```bash
dacctl --version
dacctl runtime doctor
dacctl pack list
dacctl pack validate htb-malevolent-modmaker
podman --version
podman info --debug
```

Use the same operator account, environment and image configuration as the failed run.

## Runtime verification fails

Podman is mandatory. Do not rerun the detector natively or switch to rootful Podman
when the rootless boundary fails. Check the reported prerequisite:

| Condition | Response |
| --- | --- |
| Podman missing | Install the approved host packages through an administrator |
| Running as root or rootful runtime | Use the configured ordinary operator account |
| Missing subordinate UID/GID ranges | Correct host rootless configuration before retrying |
| Missing cgroup v2 delegation | Restore delegated CPU, memory and process controls |
| Missing or stale image configuration | Review source/dependencies and run `scripts/container-build` |
| Image ID no longer exists locally | Rebuild deliberately; do not silently substitute a tag |
| Network namespace or nftables initialisation fails | Stop acquisition and inspect rootless networking support |
| Resource controls cannot be applied | Treat the runtime as unavailable until the host configuration is corrected |

The initial integration baseline is native Linux amd64, cgroup v2 and Kali Podman
5.8.6. Other environments require their own integration results. A successful
`podman info` or offline test is not proof of target-only networking.

```bash
scripts/container-test
scripts/container-verify
```

Offline verification does not test a real SSH target. Use the explicit target options
documented in [the container playbook](containers.md) for live validation.

## Target registration or SSH failure

```bash
dacctl target list
```

Confirm the saved profile, literal IPv4 address, port and independently verified
host-key fingerprint. `run ssh` requires `--target NAME`; arbitrary `--host` and
`accept-new` are not available. A new address or key requires independently verified
profile replacement, not weakened checking.

If key initialisation fails or leaves incomplete state, remove the named failed
profile through the managed lifecycle before recreating it. Never register a key whose
private counterpart was not successfully encrypted.

Confirm the remote account has the printed public key and can read the requested
absolute regular files. For explicit identity import, select the intended regular
private key file. The host SSH agent and broad SSH directory are not available inside
acquisition; their presence on the host does not establish authentication.

For normal operation, answer password, key passphrase and become prompts in the
interactive terminal. The acceptance harness supplies only synthetic prompt values
through pipes. Do not put production credentials in arguments or environment
variables. Ansible is supplied by the image;
installing it on the host does not repair a missing runtime image.

If the allowed target works but DNS, HTTPS or another target does not, the namespace
policy is behaving as intended. If the allowed target fails, check route, saved address,
port, service, host key and target Python prerequisites without broadening egress.

`--connection-timeout` bounds connection attempts. `--acquisition-timeout` bounds
the whole acquisition, including stalled modules and transfer. Raise it only after
confirming expected progress.

## Exit codes and partial results

| Exit code | Meaning |
| ---: | --- |
| `0` | Complete evaluation with no detections |
| `1` | Complete evaluation with detections |
| `2` | Acquisition issue, unknown evaluation or operational failure |

A run may have both findings and an error; `2` takes precedence. Failure before
normal reporting can produce only an `error:` message, without a report directory.

## Acquisition issues

| Code | Meaning |
| --- | --- |
| `not_found` | Requested path does not exist |
| `permission_denied` | Input cannot be inspected or read |
| `not_regular` | Unsupported file type or remote directory |
| `symlink_rejected` | Link admission was denied |
| `directory_requires_recursive` | Local directory supplied without recursion |
| `size_limit` | Per-file or total-byte limit reached |
| `file_limit` | File-count limit reached |
| `io_error` | Input changed, inspection/fetch failed or other I/O failure |

Resolve the named condition or label the run incomplete. A failed remote checksum or
fetch is not accepted merely because residual bytes exist. Local inputs must remain
stable during snapshotting. A link inside a selected directory does not authorise
reading outside that directory.

## Pack resolution or installation

Check the exact pack identity/version and any explicit source root. The current
directory is not an implicit pack root. A source pack's files must be regular and its
manifest/rules must validate.

Installed packs use managed storage. `--destination-root` is rejected; it is not a
way to select a host installation path. A local archive needs `--sha256`. Network
installation needs a published registry and release asset, credential-free HTTPS and
a matching digest. Do not bypass safe extraction or compatibility checks.

Do not directly run pack entrypoints to debug a failure. Use the container suite with
synthetic non-sensitive fixtures.

## Detector error or timeout

An error can mean a timeout, nonzero exit, invalid JSON, excessive output, schema
failure or invalid artefact reference. Reports intentionally omit full detector
standard error.

Check the intended image and pack version, evidence size, count, integrity, rule and
operator timeout, and available container resource limits. Reproduce through
`scripts/container-test`; repeatedly increasing limits does not diagnose a fault.

## Retained evidence cannot be replayed

```bash
dacctl evidence list
```

Use a retained run ID or an explicitly selected bundle path, not both. The referenced
managed volume must exist and its manifest and artefacts must pass validation.
Do not edit a digest to accept altered evidence. Compare independent records, restore
an authorised known-good source or reacquire as a new evidence run.

Ordinary report directories contain no raw `evidence/` child in this workflow.
Use `--run-id` for managed retention.

## Export or cleanup fails

Export accepts only the expected bounded regular JSON and Markdown report files.
It rejects unsafe members, links, traversal and existing output destinations.
Check the selected host directory, permissions, free space and expected run ID.
Do not bypass the exporter with a bulk container copy that includes raw evidence.

If cleanup fails, record the operation's named containers, networks and volumes and
inspect only that state. Avoid broad `podman system prune` or deleting unrelated
volumes. Retained evidence and target credentials are deliberately persistent until
their specific removal commands are used.

`dacctl target remove NAME` does not revoke the public key remotely.
`dacctl evidence remove RUN_ID` does not delete exported reports. Neither operation
guarantees secure erasure from the backing store.

## Validation record

Record completed checks and unresolved failures separately. Actual runtime,
network-policy, resource-limit, credential-separation and cleanup behaviour must be
tested on the intended host. The project promises no support response or security
review; operators must manage unresolved issues within their own authorised process.
