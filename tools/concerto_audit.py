#!/usr/bin/env python3
"""
Coverage & conformance audit of Concerto-SIEM rules.

Reads logstash/rulesets/ (parsing) and logstash/idmef/ (IDMEFv2 mapping) and
produces an Excel report: coverage by source, id matching, Category presence,
id uniqueness, pattern testing against embedded samples, captured-but-unused
fields.

Usage :
    python concerto_audit.py <path_to_logstash> [output.xlsx] [IDMEFv2.schema]
    # e.g. python concerto_audit.py ./Concerto-SIEM/logstash report.xlsx

Dependencies: pip install pyyaml openpyxl regex
    Reference schema: IDMEFv2.schema (draft-08) next to this script, or 3rd argument.
"""
import sys
import json
import pathlib
import yaml
try:
    import regex as re          # supporte quantif. possessifs, groupes atomiques, POSIX
    _ENGINE = "regex"
except ImportError:             # repli
    import re
    _ENGINE = "re"
from collections import defaultdict
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# --- Minimal GROK engine (patterns actually used in the repository) ---
GROK = {
    "USERNAME": r"[a-zA-Z0-9._-]+", "USER": r"%{USERNAME}",
    "INT": r"(?:[+-]?(?:[0-9]+))", "POSINT": r"\b(?:[1-9][0-9]*)\b",
    "NONNEGINT": r"\b(?:[0-9]+)\b", "NUMBER": r"(?:[+-]?(?:[0-9]+(?:\.[0-9]+)?))",
    "BASE16NUM": r"(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))",
    "WORD": r"\b\w+\b", "NOTSPACE": r"\S+", "SPACE": r"\s*",
    "DATA": r".*?", "GREEDYDATA": r".*",
    "IPV4": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    "IPV6": r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|%{IPV4})",
    "IP": r"(?:%{IPV6}|%{IPV4})",
    "HOSTNAME": r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*",
    "IPORHOST": r"(?:%{IP}|%{HOSTNAME})",
    "MAC": r"(?:[A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}",
    "YEAR": r"(?:\d\d){1,2}", "MONTHNUM": r"(?:0?[1-9]|1[0-2])",
    "MONTHDAY": r"(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])",
    "HOUR": r"(?:2[0123]|[01]?[0-9])", "MINUTE": r"(?:[0-5][0-9])",
    "SECOND": r"(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)",
    "TTY": r"\S+",  # non-standard: assumption (e.g. pts/0)
}
_TOK = re.compile(r"%\{(\w+)(?::((?:\[[^\]]*\])+|\w[\w.]*))?(?::\w+)?\}")

# --- IDMEFv2 data model loaded from the draft-08 schema ---
# Reference: IDMEFv2/IDMEFv2-Drafts-IETF, file 08/IDMEFv2.schema
# (Version "2.D.V08", draft-lehmann-idmefv2-08 dated 2026-04-26 - the latest
# authoritative version). The schema ships next to this script as IDMEFv2.schema.
# The model (class attributes + enumerations) is built at runtime, so swapping
# IDMEFv2.schema is all it takes to change the reference version.
SCHEMA_VERSION = "?"
ROOT = pathlib.Path(__file__).resolve().parent
ALERT_ATTRS = set()
IDMEF_CLASSES = {}
ENUM_BY_PATH = {}


def build_model_from_schema(path):
    """Build (Alert attributes, classes, enumerations, version) from the JSON schema."""
    with open(path, encoding="utf-8") as fh:
        s = json.load(fh)
    defs = s.get("definitions", {})
    props = s.get("properties", {})

    def enum_of(node):
        if "$ref" in node:
            return defs.get(node["$ref"].split("/")[-1], {}).get("enum")
        if node.get("type") == "array" and "items" in node:
            return enum_of(node["items"])
        return node.get("enum")

    alert, classes, ebp = set(), {}, {}
    for name, node in props.items():
        t = node.get("type")
        if t == "object":
            classes[name] = set(node.get("properties", {}).keys())
            for a, an in node.get("properties", {}).items():
                e = enum_of(an)
                if e:
                    ebp[f"{name}.{a}"] = set(e)
        elif t == "array" and node.get("items", {}).get("type") == "object":
            classes[name] = set(node["items"].get("properties", {}).keys())
            for a, an in node["items"].get("properties", {}).items():
                e = enum_of(an)
                if e:
                    ebp[f"{name}.{a}"] = set(e)
        else:
            alert.add(name)
            e = enum_of(node)
            if e:
                ebp[name] = set(e)
    ver = (props.get("Version", {}).get("enum") or ["?"])[0]
    return alert, classes, ebp, ver


def resolve_field(path):
    """(status, enum_key, reason) where status is one of ok/invalid/skip."""
    segs = re.findall(r"\[([^\]]+)\]", path)
    if not segs:
        return "skip", None, ""
    first = segs[0]
    if first == "@metadata":
        return "skip", None, ""
    if first in IDMEF_CLASSES:
        rest = [s for s in segs[1:] if not s.isdigit()]
        if not rest:
            return "skip", None, ""
        attr = rest[0]
        if attr in IDMEF_CLASSES[first]:
            return "ok", f"{first}.{attr}", ""
        return "invalid", None, f"attribute '{attr}' not found in class {first}"
    if first in ALERT_ATTRS:
        return "ok", first, ""
    return "invalid", None, f"unknown top-level field '{first}' (schema {SCHEMA_VERSION})"


def resolve(pattern, depth=0):
    if depth > 60:
        raise ValueError("GROK recursion too deep")
    def repl(m):
        name = m.group(1)
        if name not in GROK:
            raise KeyError(name)
        return f"(?:{resolve(GROK[name], depth+1)})"
    return _TOK.sub(repl, pattern)


def compile_pattern(pattern):
    """Convert a Concerto pattern into a testable Python regex. Returns (regex, labels)."""
    labels, counter = [], [0]
    def repl(m):
        name, field = m.group(1), m.group(2)
        if name not in GROK:
            raise KeyError(name)
        body = resolve(GROK[name])
        if field:
            counter[0] += 1
            g = f"g{counter[0]}"
            labels.append((g, field))
            return f"(?P<{g}>{body})"
        return f"(?:{body})"
    regex = _TOK.sub(repl, pattern)
    return re.compile(regex), labels


def field_labels(pattern):
    """Fields captured by a pattern (bracket-path labels)."""
    out = []
    for m in _TOK.finditer(pattern):
        if m.group(2):
            out.append(m.group(2))
    return out


def load_rules(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rs = data.get("ruleset", {})
    return rs.get("rules", []) or []


def rule_id(r):
    return str(r.get("id", "")).strip()


def mapping_has_category(rule):
    txt = yaml.safe_dump(rule, width=10 ** 9)
    return bool(re.search(r"\[Category\]", txt))


# Attributes that fill_alert.rb populates on its own from the
# [@metadata][IDMEFv2][source|target] directive, plus the ECS "address" field
# that 00-my_processed.conf splits into .ip / .hostname upstream. A pattern that
# captures one of these is consumed by the pipeline even though no mapping line
# mentions it, so it must not be reported as unused.
IMPLICIT_FILL_SUBPATHS = (
    "[hostname]", "[ip]", "[port]", "[address]",
    "[geo][name]", "[geo][location][lat]", "[geo][location][lon]",
)


def mapping_referenced_fields(rule):
    # width: yaml.safe_dump wraps at 80 columns by default, which splits long
    # %{[Attachment][RawLog][Content]...} interpolations in two and makes them
    # invisible to the search below. Disable wrapping.
    txt = yaml.safe_dump(rule, width=10 ** 9)
    refs = set(re.findall(r"\[Attachment\]\[RawLog\]\[Content\](?:\[[^\]]+\])+", txt))
    for role in ("source", "target"):
        cls = (rule.get("fields") or {}).get(f"[@metadata][IDMEFv2][{role}]")
        if cls:
            for sub in IMPLICIT_FILL_SUBPATHS:
                refs.add(f"[Attachment][RawLog][Content][{cls}]{sub}")
    return refs


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 1
    base = pathlib.Path(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else "concerto_audit.xlsx"
    schema_path = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "IDMEFv2.schema"
    global ALERT_ATTRS, IDMEF_CLASSES, ENUM_BY_PATH, SCHEMA_VERSION
    if schema_path.exists():
        ALERT_ATTRS, IDMEF_CLASSES, ENUM_BY_PATH, SCHEMA_VERSION = \
            build_model_from_schema(schema_path)
        print(f"IDMEFv2 schema loaded: {schema_path.name} (Version {SCHEMA_VERSION}) - "
              f"{len(ENUM_BY_PATH.get('Category', []))} categories")
    else:
        print(f"WARNING: schema not found ({schema_path}). "
              "IDMEFv2 conformance checks disabled.")
    rdir, idir = base / "rulesets", base / "idmef"

    sources = sorted(p.stem for p in rdir.glob("*.yml"))
    mapped = {p.stem for p in idir.glob("*.yml")}

    rows = []            # une ligne par source
    anomalies = []       # (source, id, type, detail)
    all_ids = defaultdict(list)   # id -> [sources] for global uniqueness

    for src in sources:
        prules = load_rules(rdir / f"{src}.yml")
        pids = [rule_id(r) for r in prules]
        for i in pids:
            all_ids[i].append(src)

        has_map = src in mapped
        mrules = load_rules(idir / f"{src}.yml") if has_map else []
        mids = [rule_id(r) for r in mrules]

        # id matching
        pset, mset = set(pids), set(mids)
        unmapped_ids = sorted(pset - mset) if has_map else sorted(pset)
        orphan_ids = sorted(mset - pset) if has_map else []

        # missing Category
        no_cat = [rule_id(r) for r in mrules if not mapping_has_category(r)]

        # off-schema target fields + off-enumeration values (IDMEFv2 draft-08)
        off_schema = []
        off_enum = []
        for r in mrules:
            targets = []
            for k, v in (r.get("fields") or {}).items():
                vals = v if isinstance(v, list) else [v]
                targets.append((k, [str(x) for x in vals]))
            for t in (r.get("translate") or []):
                if isinstance(t, dict) and t.get("target"):
                    vals = list((t.get("dictionary") or {}).values())
                    if "fallback" in t:
                        vals.append(t["fallback"])
                    targets.append((t["target"], [str(x) for x in vals]))
            for path, values in targets:
                status, enum_key, reason = resolve_field(path)
                if status == "invalid":
                    off_schema.append((rule_id(r), path, reason))
                    anomalies.append((src, rule_id(r),
                                      "Target field not in IDMEFv2 schema", f"{path} : {reason}"))
                    continue
                if status == "skip" or not enum_key:
                    continue
                allowed = ENUM_BY_PATH.get(enum_key)
                if not allowed:
                    continue
                for val in values:
                    if "%{" in val or not val:
                        continue          # dynamic/template value
                    if val not in allowed:
                        off_enum.append((rule_id(r), enum_key, val))
                        anomalies.append((src, rule_id(r),
                                          "Value not in IDMEFv2 enumeration",
                                          f"{enum_key} = '{val}' (non-conformant)"))

        # pattern vs sample testing
        s_tested = s_ok = s_ko = s_skip = 0
        captured_all = {}
        for r in prules:
            pat = r.get("pattern")
            if not pat:
                continue
            captured_all[rule_id(r)] = field_labels(pat)
            samples = r.get("samples") or []
            try:
                rx, _ = compile_pattern(pat)
            except (KeyError, re.error) as e:
                s_skip += len(samples)
                anomalies.append((src, rule_id(r), "Pattern not tested",
                                  f"unresolved pattern: {e}"))
                continue
            for s in samples:
                s_tested += 1
                if rx.search(str(s)):
                    s_ok += 1
                else:
                    s_ko += 1
                    anomalies.append((src, rule_id(r), "Sample not matched",
                                      str(s)[:80]))

        # captured but never used in the mapping
        unused = []
        if has_map:
            refs = set()
            for r in mrules:
                refs |= mapping_referenced_fields(r)
            captured = set()
            for labs in captured_all.values():
                for l in labs:
                    if l.startswith("[Attachment]"):
                        captured.add(l)
            unused = sorted(captured - refs)

        # structural anomalies
        for i in unmapped_ids:
            anomalies.append((src, i, "Parsing rule without IDMEFv2 mapping", ""))
        for i in orphan_ids:
            anomalies.append((src, i, "Orphan mapping (id absent from parsing)", ""))
        for i in no_cat:
            anomalies.append((src, i, "Mapping w/o Category", ""))
        for f in unused:
            anomalies.append((src, "", "Captured field never used",
                              f.replace("[Attachment][RawLog][Content]", "...")))

        # summary status
        if not has_map:
            statut = "Not mapped"
        elif s_ko or no_cat or orphan_ids or off_schema or off_enum:   # hard defects
            statut = "Mapped - defects"
        elif unused:                            # soft signal
            statut = "Mapped - review"
        elif s_skip:
            statut = "Mapped - not tested"
        else:
            statut = "Mapped & tested OK"

        rows.append({
            "source": src, "n_parse": len(prules), "map": "yes" if has_map else "no",
            "n_map": len(mrules), "unmapped": len(unmapped_ids),
            "orphan": len(orphan_ids), "no_cat": len(no_cat),
            "s_tested": s_tested, "s_ok": s_ok, "s_ko": s_ko,
            "unused": len(unused), "off_schema": len(off_schema),
            "off_enum": len(off_enum), "statut": statut,
        })

    dup_ids = {i: s for i, s in all_ids.items() if len(s) > 1}
    build_xlsx(out, rows, anomalies, dup_ids, len(sources), len(mapped))
    total_parse = sum(r["n_parse"] for r in rows)
    print(f"Sources: {len(sources)} | mapped: {len(mapped)} | "
          f"parsing rules: {total_parse} | anomalies: {len(anomalies)} | "
          f"duplicate ids: {len(dup_ids)}")
    print(f"Excel written: {out}")
    return 0


# ---------------- Excel ----------------
def build_xlsx(out, rows, anomalies, dup_ids, n_sources, n_mapped):
    FONT = "Arial"
    HDR = PatternFill("solid", fgColor="1F3864")
    HF = Font(name=FONT, size=10, bold=True, color="FFFFFF")
    CF = Font(name=FONT, size=10)
    TF = Font(name=FONT, size=14, bold=True, color="1F3864")
    thin = Side(style="thin", color="BFBFBF")
    B = Border(left=thin, right=thin, top=thin, bottom=thin)
    C = Alignment(horizontal="center", vertical="center")
    L = Alignment(horizontal="left", vertical="center", wrap_text=True)
    FILL = {
        "Not mapped": PatternFill("solid", fgColor="F8CBAD"),
        "Mapped - defects": PatternFill("solid", fgColor="FFE699"),
        "Mapped - review": PatternFill("solid", fgColor="FCE4D6"),
        "Mapped - not tested": PatternFill("solid", fgColor="DDEBF7"),
        "Mapped & tested OK": PatternFill("solid", fgColor="C6EFCE"),
    }
    wb = Workbook()

    # ---- Summary ----
    s = wb.active; s.title = "Summary"; s.sheet_view.showGridLines = False
    s["A1"] = "Coverage & conformance audit - Concerto-SIEM rules"; s["A1"].font = TF
    s.merge_cells("A1:C1")
    s["A2"] = "Generated by concerto_audit.py on the IDMEFv2/Concerto-SIEM repository (main branch)."
    s["A2"].font = Font(name=FONT, size=9, italic=True, color="595959"); s.merge_cells("A2:E2")

    kpis = [
        ("Parsed sources (rulesets/ files)", n_sources),
        ("IDMEFv2-mapped sources (idmef/ files)", n_mapped),
        ("Sources WITHOUT IDMEFv2 mapping", n_sources - n_mapped),
        ("Total parsing rules", sum(r["n_parse"] for r in rows)),
        ("Total mapping rules", sum(r["n_map"] for r in rows)),
        ("Mapping rules without Category", sum(r["no_cat"] for r in rows)),
        ("Target fields not in IDMEFv2 schema", sum(r["off_schema"] for r in rows)),
        ("Values not in IDMEFv2 enumeration", sum(r["off_enum"] for r in rows)),
        ("Samples tested", sum(r["s_tested"] for r in rows)),
        ("Samples OK", sum(r["s_ok"] for r in rows)),
        ("Samples not matched", sum(r["s_ko"] for r in rows)),
        ("Duplicate identifiers (global)", len(dup_ids)),
    ]
    r0 = 4
    for i, (k, v) in enumerate(kpis):
        s.cell(r0+i, 1, k).font = Font(name=FONT, size=10, bold=(i < 3))
        c = s.cell(r0+i, 2, v); c.font = Font(name=FONT, size=10, bold=True); c.alignment = C
        for col in (1, 2):
            s.cell(r0+i, col).border = B
    s.cell(r0+2, 1).fill = PatternFill("solid", fgColor="F8CBAD")
    s.cell(r0+2, 2).fill = PatternFill("solid", fgColor="F8CBAD")
    s.column_dimensions["A"].width = 42; s.column_dimensions["B"].width = 14
    notes = [
        "Method: patterns tested by unanchored search against the embedded samples; a "
        "'sample not matched' is a review candidate (pattern/example drift or regex-engine "
        "residue), not a definite bug. TTY approximated as \\S+.",
        f"Regex engine: {_ENGINE}. Semantic checks (Source vs Target) are flagged but not "
        "decided: human judgment required.",
        f"Conformance reference: DRAFT-08 machine schema (IDMEFv2/IDMEFv2-Drafts-IETF, "
        f"08/IDMEFv2.schema, Version {SCHEMA_VERSION}), aligned with draft-lehmann-idmefv2-08 "
        "(2026-04-26), the latest authoritative version. Note: this draft-08 differs sharply "
        "from the old SECEF/idmefv2-definition schema (rev. 0.3, frozen since May 2021) - the "
        "category taxonomy grew from 58 to 128 values, so results differ greatly depending on "
        "the reference. Draft-08 is the one used here.",
        "Consequence: the existing mappings were written against an older taxonomy. Categories "
        "such as Recon.Scanning or Intrusion.UserCompromise no longer exist in draft-08, while "
        "Access.Other is now valid. See the Detailed anomalies tab for the values to fix.",
    ]
    for j, txt in enumerate(notes):
        nr = r0 + len(kpis) + 1 + j
        cell = s.cell(nr, 1, txt)
        cell.font = Font(name=FONT, size=8, italic=True, color="808080")
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        s.merge_cells(start_row=nr, start_column=1, end_row=nr, end_column=5)
        s.row_dimensions[nr].height = 26

    # ---- Coverage by source ----
    cov = wb.create_sheet("Coverage by source"); cov.sheet_view.showGridLines = False
    heads = ["Source", "Parsing rules", "IDMEFv2 mapping", "Mapping rules",
             "Parsing w/o mapping", "Orphan mapping", "Mapping w/o Category",
             "Fields off-schema", "Values off-enum", "Samples tested",
             "Samples OK", "Samples KO", "Unused fields", "Status"]
    widths = [20, 15, 14, 14, 15, 14, 16, 14, 14, 13, 11, 11, 15, 18]
    for c, (h, w) in enumerate(zip(heads, widths), 1):
        cell = cov.cell(1, c, h); cell.fill = HDR; cell.font = HF
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = B; cov.column_dimensions[get_column_letter(c)].width = w
    cov.row_dimensions[1].height = 30
    for i, r in enumerate(rows, 2):
        vals = [r["source"], r["n_parse"], r["map"], r["n_map"], r["unmapped"],
                r["orphan"], r["no_cat"], r["off_schema"], r["off_enum"],
                r["s_tested"], r["s_ok"], r["s_ko"], r["unused"], r["statut"]]
        for c, v in enumerate(vals, 1):
            cell = cov.cell(i, c, v); cell.font = CF; cell.border = B
            cell.alignment = L if c in (1, 14) else C
        cov.cell(i, 14).fill = FILL.get(r["statut"], PatternFill())
    cov.freeze_panes = "A2"
    cov.auto_filter.ref = f"A1:{get_column_letter(len(heads))}{len(rows)+1}"

    # ---- Detailed anomalies ----
    an = wb.create_sheet("Detailed anomalies"); an.sheet_view.showGridLines = False
    ah = ["Source", "Rule id", "Anomaly type", "Detail"]
    aw = [20, 12, 34, 70]
    for c, (h, w) in enumerate(zip(ah, aw), 1):
        cell = an.cell(1, c, h); cell.fill = HDR; cell.font = HF; cell.alignment = C
        cell.border = B; an.column_dimensions[get_column_letter(c)].width = w
    for i, (src, rid, typ, det) in enumerate(anomalies, 2):
        for c, v in enumerate([src, rid, typ, det], 1):
            cell = an.cell(i, c, v); cell.font = CF; cell.border = B
            cell.alignment = L if c == 4 else (C if c in (2,) else Alignment(vertical="center"))
    an.freeze_panes = "A2"
    if anomalies:
        an.auto_filter.ref = f"A1:D{len(anomalies)+1}"

    # ---- Duplicate ids ----
    if dup_ids:
        du = wb.create_sheet("Duplicate ids"); du.sheet_view.showGridLines = False
        for c, h in enumerate(["Id", "Present in (sources)"], 1):
            cell = du.cell(1, c, h); cell.fill = HDR; cell.font = HF; cell.border = B
        du.column_dimensions["A"].width = 12; du.column_dimensions["B"].width = 60
        for i, (idv, srcs) in enumerate(sorted(dup_ids.items()), 2):
            du.cell(i, 1, idv).border = B; du.cell(i, 1).font = CF
            cell = du.cell(i, 2, ", ".join(srcs)); cell.border = B; cell.font = CF

    wb.save(out)


if __name__ == "__main__":
    raise SystemExit(main())
