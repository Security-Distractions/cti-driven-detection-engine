# pfSense integration — OPNsense Squid PR bundle

Prepared 2026-08-10. Nothing has been submitted to Elastic.

| File | Where it goes in elastic/integrations |
|---|---|
| `squid.yml` | `packages/pfsense/data_stream/log/elasticsearch/ingest_pipeline/squid.yml` |
| `test-opnsense-squid.log` | `packages/pfsense/data_stream/log/_dev/test/pipeline/` |
| `changelog-entry.yml` | prepend to `packages/pfsense/changelog.yml`, and bump `version` in `manifest.yml` to 1.25.5 |
| `ISSUE.md` | issue body — file this first, then reference it from the PR |
| `PR.md` | PR description |

The `-expected.json` companion for the fixture is generated, not hand-written:
`elastic-package test pipeline --generate` produces it.

## Validation already done

* Classic pfSense fixtures: output **byte-identical** before/after (differential `_simulate` on a live 9.5.0 cluster)
* 5 real OPNsense events: previously `pipeline_error`, now fully parsed into ECS
* No new field definitions needed — reuses `squid.request_status` / `squid.hierarchy_status`

## Not yet done

* Fork, branch, commit, and open the issue + PR
* `elastic-package test pipeline` locally (needs the elastic-package toolchain + Docker)
