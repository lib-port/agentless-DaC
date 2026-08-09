# Malevolent ModMaker Detection Pack

This is the first-party Detection Goggles pack for Hack The Box's **Malevolent
ModMaker** Sherlock. It performs static analysis of files that the user obtains from
Hack The Box. It does not download, include, execute, decrypt, or modify challenge
artifacts.

The pack detects three explainable behavior profiles:

- `MMM-001`: a Windows Go executable combining AES-GCM primitives and file
  transformation operations;
- `MMM-002`: a Windows executable combining network retrieval and process execution;
- `MMM-003`: correlation of both profiles on distinct artifacts in one evidence set.

Run it against extracted challenge files in an isolated malware-analysis environment:

```bash
dacctl run files htb-malevolent-modmaker ./path/to/artifact1 ./path/to/artifact2
```

Or have the core fetch only explicitly named files from an authorized SSH target before
running the same detectors locally:

```bash
dacctl run ssh htb-malevolent-modmaker \
  --host 10.10.10.10 --user htb \
  --remote-file /opt/evidence/artifact1 \
  --remote-file /opt/evidence/artifact2
```

Install the core's optional SSH support with `pip install 'detection-goggles[ssh]'`.
This pack contains no remote playbook or credential material and declares
`remote_execution: false`.

The archive is self-testing. With Detection Goggles and pytest installed, run
`pytest tests` from the unpacked pack directory. Its matching samples are generated
in a temporary directory from inert PE-shaped bytes; no challenge binary is included.
The artifact and correlation rules load the same shared static-profile implementation,
so their marker requirements cannot drift. The archive includes its MIT license.

The detections are behavioral static heuristics, not a substitute for reverse
engineering. Benign software can contain individual traits, and stripped or packed
binaries can conceal them.

Hack The Box and Malevolent ModMaker are referenced for interoperability and training
context. This project is not affiliated with or endorsed by Hack The Box.
