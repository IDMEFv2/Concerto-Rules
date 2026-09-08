# tools — IDMEFv2 conformance audit

`concerto_audit.py` checks the parsing rules and the IDMEFv2 mappings of a
Concerto-SIEM installation against the IDMEFv2 draft-08 schema, and writes an
Excel report.

## What it checks

- parsing rules that have no IDMEFv2 mapping, and mappings whose id matches no
  parsing rule
- mappings that set no `Category`
- target fields that do not exist in the IDMEFv2 schema
- values that are not part of the enumeration declared by the schema
  (`Category`, `Priority`, …), including the values of `translate` dictionaries
  and their `fallback`
- every `samples:` line replayed against its own pattern, using a built-in GROK
  engine — no Logstash, no container needed
- fields captured by a pattern but never used by the mapping
- id uniqueness across the whole installation

The IDMEFv2 data model is **read from the schema at runtime**: swapping
`IDMEFv2.schema` is all it takes to validate against another draft version.

## Usage

```bash
pip install pyyaml openpyxl regex
python3 concerto_audit.py <path-to-logstash-folder> [report.xlsx] [IDMEFv2.schema]
```

Example, from a Concerto-SIEM checkout:

```bash
python3 tools/concerto_audit.py ./logstash report.xlsx tools/IDMEFv2.schema
```

On Windows, `run_audit.bat` does the same: double-click it, or drag the
`logstash` folder onto it.

## Report

Three sheets: a summary, one line per source with the counters, and the detailed
anomaly list (source, rule id, anomaly type, detail).

## Known false-positive sources, handled

Two pipeline behaviours would otherwise be reported as lost data, and are
accounted for:

- `scripts/fill_alert.rb` fills `Hostname`, `Location`, `IP`, `Port` and
  `GeoLocation` on its own from the `[@metadata][IDMEFv2][source|target]`
  directive;
- a grok in `pipeline/00-my_processed.conf` derives `.ip` / `.hostname` from the
  ECS `address` field.

A pattern capturing one of these is consumed by the pipeline even though no
mapping line mentions it.
