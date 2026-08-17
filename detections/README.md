# Detections

## `sigma/`

The rules themselves, in **Sigma** format. These are the source of truth — portable, vendor-neutral
YAML that any Sigma backend can convert.

| Rule | ID | Level |
|---|---|---|
| Potential PyArmor Obfuscated PyInstaller Payload Extraction | `677086ae-fcc3-4202-93b0-61932ab8ad36` | medium |
| Suspicious Double Extension Executable Launched From User Writable Path | `fc5cd64c-4e5f-46f3-b402-557f3128c842` | high |
| Suspicious Microsoft Defender Exclusion Added Via WMIC | `27cf3735-02a9-4c63-91fc-2a03e651f8cf` | high |

The three are cross-linked through their `related` fields: they were written against the same
intrusion, and the double-extension and PyArmor rules describe two properties of the same artefact.

## `elastic/`

The same rules converted to Elastic detection rules, as exported from the detection engine. These
are the deployable artefacts, not the source — regenerate them from `sigma/` rather than editing
them by hand:

```bash
pip install pysigma pysigma-backend-elasticsearch pysigma-pipeline-sysmon
sigma convert -t lucene -p ecs_windows sigma/ -o rules.json
```

Import the JSON through Kibana → Security → Rules → Import, or the
`POST /api/detection_engine/rules/_import` API.

## Validation

All three fired, or were correctly silent, against live malware in a detonation lab rather than
being assumed correct:

- **PyArmor extraction** and **WMIC Defender exclusion** both fired on a PyArmor-obfuscated
  PyInstaller loader.
- **Double extension** did *not* fire, correctly: the sample ships in the wild as `composer.php.exe`
  but was executed under its SHA256 filename, so the condition was absent. The rule remains
  untested rather than proven.

The detonation is written up in
[`detonations/2026-08-17-pyarmor-pyinstaller-loader`](../detonations/2026-08-17-pyarmor-pyinstaller-loader).

## `disabled-esql-rules-20260817.md`

Which prebuilt ES|QL rules were disabled and why — mostly rules that hard-fail against fields this
estate does not produce.
