# Container migration validation record

This record captures checks observed on 6 September 2026 UTC. A result below describes
the run observed, not a guarantee for another host or a later build.

## Host examined

| Component | Observed value |
| --- | --- |
| Host distribution | Kali Linux 2026.3, amd64 |
| Host kernel | `7.1.5+kali-amd64` |
| Podman | `5.8.6`, local and rootless |
| Network backend | Netavark `1.17.2`, pasta |
| OCI runtime | crun `1.28` |
| Cgroups | v2, with CPU, memory and process controllers delegated |
| Core / bundled pack | Detection Goggles `0.2.0` / Malevolent ModMaker `0.1.2` |

## Observed results

| Check | Observation |
| --- | --- |
| Runtime boundary | Private PID, IPC and UTS namespaces; offline networking; effective limits of two CPUs, 4 GiB and 128 processes; no capabilities; no-new-privileges enabled |
| Container suite | `scripts/container-test`: 105 passed; six host-refusal checks appropriately skipped inside the container |
| Host-only verification | `pytest -m 'not container'`: 52 passed; five detector tests skipped and 54 container tests deselected; no detector ran on the host |
| Offline verification | Runtime and bundled pack discovery passed |
| Final end-to-end acceptance | The complete live harness passed again against the image identities below, including generated-key-plus-become prompting, pack verification and cleanup |
| Local analysis and replay | Clean and matching synthetic files, all three rules, source preservation, managed replay and partial local acquisition passed in the first complete live harness |
| Selected-input boundary | The live harness rejected a symbolic link outside the selected directory |
| SSH acquisition | Generated encrypted and explicitly imported keys, SSH password authentication, sudo prompting and partial remote acquisition passed; the repeated harness also passed generated-key-plus-become prompting |
| Negative authentication | Wrong key passphrase and wrong host-key fingerprint were rejected |
| Target network policy | The declared SSH destination worked; an adjacent port with a listener proven reachable from the host was denied from the acquisition namespace |
| Report export | The live harness found only `report.json` and `report.md`, without its synthetic passwords, passphrase or private-key marker |
| Export rejection | Container regressions passed for traversal, symbolic links, FIFOs, hardlinks, unexpected entries and metadata changes during export |
| Pack build/install | A built archive passed verification and the already-bundled installation path |
| Normal cleanup | The first complete live harness removed its retained evidence, target profile and SSH service and closed its listener before reporting success |
| Interrupted acquisition | An independent SIGINT check removed the acquisition workload and pod |
| Terminal handling | An independent real-PTY check found no echo of the synthetic secret and confirmed restoration of terminal flags |
| Registry transport | An actual HTTPS registry download through the separate downloader and subsequent offline parsing passed |
| Source staging | Regression passed excluding arbitrary root files, evidence and legacy VM credentials from the image context |
| Static checks | Ruff formatting/lint, shell syntax and `git diff --check` passed |

The remote registry check read the existing `0.1.1` catalogue. It does not establish
publication of a `0.1.2` archive or registry update, and no release publication is
claimed.

The fixture uses only generated synthetic credentials and inert samples. Its known
test password and sudo-enabled account are confined to the disposable service; it is
not a production target configuration. See the [container playbook](containers.md)
for its controlled-network prerequisites and the distinction between the offline
verifier, container suite, live harness and independent checks.

## Validated image identities

The final regression suite and strict network-policy read-back used these immutable
local images. They were built from the reviewed working tree before this result record
and the final documentation notes were completed; no application code changed afterwards.

```json
{
  "source_sha256": "661bf13317d7fc64bce3b507a8842247cfa88ac4764bcc0e6bc3ad532dd46a9a",
  "runtime": "sha256:d9fe585ddb875c6d02feb392d3bbda1dd1924de3a8898334c78e518e11fd4541",
  "network": "sha256:6518781bb76a21909ee3a58867c096759151590382130f9ece340069e66bcbd6",
  "test": "sha256:ce8b0ad1467d72e690e127a72dbe4a8e12264457abda4fa6f2a5b2a9323b7b0e"
}
```

The operator's current image selection and build provenance are also recorded in
`${XDG_CONFIG_HOME:-~/.config}/detection-goggles/images.json`. Rebuilding deliberately
can produce different identities; rerun acceptance after changes.

These observations concern rootless containers sharing the host kernel. They do not
establish a separate-kernel security boundary or provide a support or security warranty.
