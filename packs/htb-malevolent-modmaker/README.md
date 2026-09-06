# Malevolent ModMaker Detection Pack

This is the first-party Detection Goggles pack for Hack The Box's **Malevolent
ModMaker** Sherlock. It statically analyses files obtained by the authorised operator.
It does not download, include, execute, decrypt or modify challenge artefacts.

The pack detects three explainable behaviour profiles:

- `MMM-001`: a Windows Go executable combining AES-GCM primitives and file
  transformation operations;
- `MMM-002`: a Windows executable combining network retrieval and process execution;
- `MMM-003`: correlation of both profiles on distinct artefacts in one evidence set.

Detection Goggles core 0.2 or newer runs the pack in its mandatory rootless Podman
workflow. Prepare the reviewed images and verify the runtime before analysis:

```bash
dacctl runtime doctor
dacctl run files htb-malevolent-modmaker ./path/to/artifact1 ./path/to/artifact2
```

To fetch named files from an authorised POSIX SSH target, first register its literal
IPv4 address, SSH port and independently verified host-key fingerprint:

```bash
dacctl target init lab \
  --host 192.0.2.10 \
  --port 22 \
  --host-key-fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
```

Register the printed public key on the intended target account, then acquire files:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --target lab --user analyst \
  --remote-file /opt/evidence/artifact1 \
  --remote-file /opt/evidence/artifact2
```

Acquisition runs with access restricted to the saved target. A separate offline
container evaluates the files without SSH credentials. The pack contains no remote
playbook or credential material and declares `remote_execution: false`.

Synthetic tests ship with the archive. Run them through the hardened test image from
the trusted Detection Goggles checkout; direct host pytest and entrypoint execution
are not supported:

```bash
scripts/container-build
scripts/container-test packs/htb-malevolent-modmaker/tests
```

Matching samples are generated in a temporary directory from inert PE-shaped bytes.
No challenge binary is included. Artefact and correlation rules share the same static
profile implementation so their marker requirements cannot drift. The archive
includes its MIT licence.

These are static behavioural heuristics, not a substitute for reverse engineering.
Benign software can contain individual traits, and stripped or packed binaries can
conceal them. A negative result does not prove that a file is safe. Rootless containers
share the host kernel and do not provide virtual-machine isolation.

Hack The Box and Malevolent ModMaker are referenced for interoperability and training.
This project is not affiliated with or endorsed by Hack The Box.
