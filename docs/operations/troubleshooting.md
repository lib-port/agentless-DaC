# Playbook: troubleshooting

## First response

When a run is unexpected:

1. capture the exact command with credentials and secrets redacted;
2. record the process exit code;
3. preserve `report.json` and `report.md` if they were created;
4. inspect `summary.acquisition_issue_count` and every evaluation status;
5. confirm core and exact pack versions;
6. retry only after identifying which condition changed.

Do not send diagnostics, reports, artifacts, credentials, or suspected vulnerabilities
to the maintainer. Security reporting is not supported.

## Basic diagnostics

```bash
RUN_ID="replace-with-run-id"
dacctl --version
dacctl pack list
dacctl pack validate htb-malevolent-modmaker
python -m json.tool "./reports/${RUN_ID}/report.json"
```

For SSH operations:

```bash
HOST="10.10.10.10"
ansible-playbook --version
ssh-keygen -F "${HOST}"
```

Run diagnostics from the same virtual environment, working directory, user account,
pack roots, and network context as the failed operation.

## Disposable controller VM

Use this section with the
[disposable Vagrant controller playbook](vagrant-controller.md). Do not bypass a failed
isolation check or continue using a partially provisioned guest.

Start on the physical Debian 12 host from the repository root:

```bash
test "$(vagrant --version)" = "Vagrant 2.3.4"
virsh -c qemu:///system list
vagrant plugin list
git status --short
```

Respond according to the failed lifecycle stage:

| Symptom or stage | Required response |
| --- | --- |
| A KVM, libvirt, Vagrant, provider, argument, box-metadata, or clean-worktree preflight fails before `vagrant up` | Correct the reported host or input condition and rerun. Do not change a reviewed digest to match unexpected metadata. |
| `VM state already exists` | Run `scripts/vm-verify`. If it is the expected healthy controller, continue using it; otherwise destroy it with `scripts/vm-destroy` before rebuilding. |
| `vagrant up`, provisioning, reload, or `scripts/vm-verify` fails | Treat the VM as incomplete. Revoke its target key if registered, run `scripts/vm-destroy`, correct the underlying condition, and rebuild from a clean commit. |
| The scanned SSH key does not match the sealed fingerprint | Stop. Reconfirm the fingerprint through the independent channel. A legitimate corrected or rotated key requires destroying and rebuilding the controller with the new fingerprint. |
| Key generation is interrupted, uses an empty passphrase, or reports partial/unsafe key state | Destroy the VM. Do not repair or reuse the guest disk. Revoke a public key if it was registered. |
| The configured target works but DNS, HTTPS, another IP, or another port does not | This is the intended sealed-egress policy. A different target or port requires a rebuild. |
| The configured target is unreachable | Confirm its literal IP, port, route, service, and independently verified host key. Do not open general egress. If the sealed values are wrong, rebuild. |
| `vm-pull-report` rejects a run ID or guest report | Confirm the printed run ID and that both `report.json` and `report.md` still exist in the guest run directory. Do not replace the exporter with `scp` or copy raw evidence. |
| `vm-pull-report` says the destination exists | Select a new empty destination. Remove an old export only through the operator's approved retention process; the command intentionally never overwrites it. |
| `vm-destroy` fails | Assume the disk and private key remain. Revoke the target key immediately, restore libvirt/Vagrant access, and rerun the command. Do not claim destruction until it prints its success message. |

Initialization removes state automatically only when it fails before invoking Vagrant.
After Vagrant is invoked, `.vagrant/dac-vm.json` is deliberately retained so the normal
destroy path still knows the sealed target. Never delete `.vagrant` manually. If state was
lost or corrupted while a domain may remain, revoke the target key and have the physical-
host virtualization administrator reconcile the Vagrant and libvirt state before further
use.

The sealed guest cannot update Debian, Python dependencies, or packs. Package-install and
registry failures inside it are expected; destroy and rebuild from a reviewed commit and
lock files instead. Never use a snapshot containing credentials or evidence as a repair
or upgrade mechanism.

## Exit-code decision table

| Exit | Condition | Response |
| ---: | --- | --- |
| `0` | No findings and no operational problem | Confirm all expected artifacts and rules were evaluated |
| `1` | Findings and no operational problem | Triage findings; this is not a command failure |
| `2` | Any acquisition issue, `error`, or `unknown` evaluation | Treat all conclusions as incomplete |

If the CLI prints `error:` and no report path, failure occurred before a normal report was
written, such as pack resolution, evidence validation, or total acquisition failure.

## Acquisition issue codes

| Code | Meaning | Operator response |
| --- | --- | --- |
| `not_found` | Supplied path does not exist | Correct the path or document that evidence is unavailable |
| `permission_denied` | Local input cannot be inspected or read | Use an authorized readable copy; do not broaden access casually |
| `not_regular` | Input is an unsupported non-regular type, or a remote path is not a regular file | Supply an explicit regular file; remote directories are not traversed |
| `symlink_rejected` | A link was encountered while link following was disabled | Resolve and authorize the target before considering `--follow-symlinks` |
| `directory_requires_recursive` | A local directory was supplied without `--recursive` | Select individual files or deliberately enable recursion |
| `size_limit` | Per-file or aggregate byte limit was reached | Verify expected size before increasing the narrowest limit |
| `file_limit` | Maximum artifact count was reached | Narrow selection or deliberately raise `--max-files` |
| `io_error` | Input changed, remote metadata was unavailable, fetch failed, or another I/O condition occurred | Inspect source stability, filesystem state, and Ansible output |

Any issue makes the run partial and produces exit code `2` if a report is written.

## Pack cannot be found

Symptoms include `Detection Pack ... was not found` or an empty `pack list`.

Check:

- the core is running from the intended source checkout when using its pack;
- global `--pack-root` appears before the `pack` or `run` command;
- `DAC_PACK_PATH` uses the platform path separator;
- an installed pack is under `<root>/<pack-id>/<version>/pack.yml`;
- the requested `pack-id@version` exists;
- pack files are regular and not symbolic links.

The current directory is not searched implicitly. `pack list` prints the selected path;
an ID/version duplicated across roots is a contract error rather than a silent override.

## Pack or rule contract failure

Validation errors include a schema path and reason. Do not edit an installed immutable
pack to suppress the error. Resolve the expected source/version, rebuild through the
maintainer process if applicable, and reinstall under a new version.

A core compatibility error means the pack's `compatibility.core` range excludes the
running core. Select a compatible installed version or intentionally change the core;
do not bypass the check.

## Local acquisition failures

- For a missing path, resolve it from the command's working directory or use an absolute
  path.
- For a directory error, decide between explicit files and `--recursive`.
- For a symlink, inspect every link target before opting in to following.
- For changing files, stop the writer or make an authorized stable copy before retrying.
- For size/count limits, independently inspect expected dataset size before changing
  limits.
- For an output-root symlink error, select a normal directory; the writer intentionally
  refuses symbolic output roots.

## SSH connection failure

If Ansible returns a nonzero transport status, the adapter reports the status and no
normal run report is guaranteed.

If the overall acquisition timeout expires, increase it only after confirming that the
target and transfer are progressing. `--connection-timeout` cannot bound a stalled
module or transfer; `--acquisition-timeout` bounds the complete Ansible process group.

Check in this order:

1. host syntax, port, and route;
2. known-host entry and independently expected fingerprint;
3. SSH user and selected identity or agent;
4. interactive terminal availability for `--ask-pass`;
5. target Python/Ansible module requirements;
6. access to each absolute remote path;
7. become policy and prompt requirements;
8. controller and target free space.

An unknown key under strict policy is expected to fail. A changed key must be
investigated; do not switch to `accept-new` to bypass it. `accept-new` applies only to an
unknown first-seen key.

If metadata exists but a regular file was not fetched, inspect Ansible's terminal output
for read, checksum, connection, or target-change conditions. The report deliberately
uses a bounded generic issue rather than copying arbitrary transport diagnostics into
its JSON.

## Ansible is missing

The CLI reports that SSH acquisition requires `ansible-playbook`. Install the optional
dependency in the same environment as `dacctl`:

```bash
python -m pip install -e '.[ssh]'
```

For a built wheel, install its `ssh` extra. Confirm that the executable resolved by
`command -v ansible-playbook` belongs to the intended environment.

## Detector timeout or error

An `error` evaluation can mean timeout, nonzero exit, invalid JSON, oversized output,
schema failure, or an invalid artifact reference. The report intentionally omits
detector standard error.

Confirm:

- the exact trusted pack version;
- the artifact count and size;
- the operator timeout and rule timeout;
- that retained evidence still passes integrity checks;
- that the controller has sufficient memory and process/file-descriptor capacity.

Do not repeatedly raise the timeout for an unexplained detector failure. Reproduce with
the pack's synthetic tests and a non-sensitive fixture.

## Retained evidence fails verification

The loader rejects missing files, links, paths escaping the bundle, size mismatches, and
SHA-256 mismatches. Do not edit the manifest to match altered content. Compare against
independent checksums, restore an authorized known-good copy, or reacquire and treat it
as a new evidence run.

## Registry or installation failure

- Registry and pack network URLs must be credential-free HTTPS.
- The default network workflow is usable only after the registry commit and matching
  immutable release asset have been published; use a digest-verified local archive
  during development.
- A local registry must be a regular, non-symlink file below the size limit.
- A local install requires `--sha256`.
- A digest mismatch blocks both verification and installation.
- An installed identical version is not overwritten.
- Unsafe archive paths, links, devices, duplicates, file-count excess, and expanded-size
  excess are rejected.

Never weaken digest or extraction checks to install an archive. Resolve the independently
expected registry, version, filename, and digest.

## Report handling problems

The report writer refuses to overwrite an existing run directory and rejects a symbolic
output root. Ordinary path and permission failures are returned as clean `error:`
messages with exit code `2`, not tracebacks. Check parent permissions, free space, and
path type. A partial owner-only directory can remain if writing fails; inspect it locally
and either preserve or dispose of it through the operator's approved process.

## No reporting or escalation channel

The project offers no vulnerability-reporting or coordinated-disclosure channel. The
maintainer does not request security diagnostics and makes no response or fix commitment.
Operators must evaluate, mitigate, patch, fork, discontinue, or otherwise manage issues
within their own authorization and risk process without transmitting sensitive material
to the maintainer.
