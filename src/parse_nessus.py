"""Parse Nessus Essentials HTML exports into anonymised, normalised rows.

Steps
1. Walk the data folder and read every .html file.
2. Detect the export style: summary (one row per plugin per host), host_detail (detailed
   per host export, one section per plugin and port) or plugin_detail (grouped by plugin, no host totals).
3. Resolve property and role from file names (labels only, see src/labels.py).
4. Deduplicate: byte identical files first (sha256), then alternative exports of the same
   system (same property plus role). The summary style export is preferred. Detailed host
   exports are counted at summary level (one row per distinct plugin id per host) so the
   numbers match the summary exports.
5. Write anonymised CSV only. Raw IP addresses, host names, MAC addresses, domain names, user
   names, licence keys and original file names never leave this module.

Usage
    python src/parse_nessus.py --data-dir "<folder with the Nessus HTML exports>"
"""
import argparse
import hashlib
import html
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA_DIR, SEVERITIES, load_config, write_csv, write_json  # noqa: E402
import labels  # noqa: E402

SEV_COLOURS = {"#91243E": "Critical", "#DD4B50": "High", "#F18C43": "Medium",
               "#F8C851": "Low", "#67ACE1": "Info"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
TAG_RE = re.compile(r"<[^>]+>")


def clean(txt):
    return html.unescape(TAG_RE.sub("", txt)).strip()


# ---------------------------------------------------------------------------
# File level parsing
# ---------------------------------------------------------------------------

def detect_format(text):
    if '<tr class="plugin-row">' in text:
        return "summary"
    if "Vulnerabilities by Plugin" in text:
        return "plugin_detail"
    if re.search(r"toggleSection\('id\d+-container'\)", text):
        return "host_detail"
    return "unknown"


def host_fingerprint(text):
    """Salted hash of the host heading, used in memory only to recognise one host."""
    m = re.search(r'<div xmlns="" id="id2"[^>]*>(.*?)<div class="clear"', text, re.S)
    if not m:
        m = re.search(r'<div xmlns="" id="id\d+" style="font-size: 22px[^>]*>(.*?)<div class="clear"',
                      text, re.S)
    if not m:
        return None
    return hashlib.sha256(("hiss-rat|" + clean(m.group(1))).encode("utf-8")).hexdigest()


def parse_tiles(text):
    nums = re.findall(r"font-size: 45px[^>]*>(\d+)</div>", text)
    if len(nums) >= 5:
        return dict(zip(SEVERITIES, [int(x) for x in nums[:5]]))
    return None


def parse_summary_rows(text):
    rows = []
    for tr in re.findall(r'<tr class="plugin-row">(.*?)</tr>', text, re.S):
        sev = re.search(r"text-transform: uppercase; background: #[0-9A-Fa-f]+;[^>]*>([A-Za-z]+)</span>", tr)
        if not sev:
            continue  # footnote row
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        cells = [clean(t) for t in tds]
        pid = re.search(r"/plugins/nessus/(\d+)", tr)
        name = cells[-1] if cells else ""
        cvss = cells[3] if len(cells) > 3 else ""
        rows.append({
            "plugin_id": pid.group(1) if pid else "",
            "plugin_name": name,
            "severity": sev.group(1),
            "cvss": cvss.replace("*", ""),
        })
    return rows


def parse_host_detail(text):
    """Return (rows, cve_map, tiles). Rows are distinct plugin ids (summary level counting)."""
    heads = list(re.finditer(
        r"<div xmlns=\"\" id=\"id\d+\" style=\"[^\"]*background: (#[0-9A-Fa-f]{6});[^\"]*\" class=\"\" "
        r"onclick=\"toggleSection\('id\d+-container'\);\"[^>]*>(\d+) - (.*?)<div id=", text, re.S))
    rows, seen, cve_map = [], set(), {}
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        section = text[m.end():end]
        pid, name = m.group(2), clean(m.group(3))
        sev = SEV_COLOURS.get(m.group(1).upper(), "Info")
        cves = sorted(set(re.findall(r"<td[^>]*>CVE</td>\s*<td[^>]*><a[^>]*>(CVE-\d{4}-\d{4,7})</a>", section)))
        c3 = re.search(r"CVSS v3\.0 Base Score<div class=\"clear\"></div>\s*</div>\s*<div[^>]*>([\d.]+)", section, re.S)
        if cves:
            cve_map.setdefault(pid, set()).update(cves)
        if pid in seen:
            continue
        seen.add(pid)
        rows.append({"plugin_id": pid, "plugin_name": name, "severity": sev,
                     "cvss": c3.group(1) if c3 else ""})
    return rows, cve_map, parse_tiles(text)


def count_rows(rows):
    c = OrderedDict((s, 0) for s in SEVERITIES)
    for r in rows:
        c[r["severity"]] += 1
    return c


class Export:
    """One parsed HTML file (internal only; never serialised with raw identifiers)."""

    def __init__(self, ref, relpath, raw):
        text = raw.decode("utf-8", "replace")
        self.ref = ref
        self.sha = hashlib.sha256(raw).hexdigest()
        self.fmt = detect_format(text)
        self.fp = host_fingerprint(text) if self.fmt != "plugin_detail" else None
        self.tiles = parse_tiles(text) if self.fmt != "plugin_detail" else None
        self.cve_map = {}
        self.rows = []
        if self.fmt == "summary":
            self.rows = parse_summary_rows(text)
        elif self.fmt == "host_detail":
            self.rows, self.cve_map, _ = parse_host_detail(text)
        self.prop, self.prop_basis = labels.resolve_property(relpath)
        self.role = labels.resolve_role(relpath)
        self.counts = count_rows(self.rows) if self.rows else None


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def collect_files(data_dir):
    out = []
    for dp, dns, fns in os.walk(data_dir):
        dns.sort()
        for fn in sorted(fns):
            if fn.lower().endswith(".html"):
                full = os.path.join(dp, fn)
                out.append((os.path.relpath(full, data_dir).replace("\\", "/"), full))
    return out


def build(data_dir):
    cfg = load_config()
    files = collect_files(data_dir)
    exports = []
    for i, (rel, full) in enumerate(files, 1):
        with open(full, "rb") as fh:
            raw = fh.read()
        exports.append(Export("F%02d" % i, rel, raw))
    log = []

    # Resolve roles that the file name did not reveal by matching the host fingerprint.
    for e in exports:
        if e.role is None and e.fp:
            for o in exports:
                if o is not e and o.fp == e.fp and o.role is not None:
                    e.role = o.role
                    e.prop = o.prop if e.prop is None else e.prop
                    break
    unresolved = [e for e in exports if e.role is None or e.prop is None]

    # Stage 1: byte identical duplicates
    first_by_hash = {}
    distinct = []
    for e in exports:
        if e.sha in first_by_hash:
            log.append({"file_ref": e.ref, "format": e.fmt, "property": e.prop, "role": e.role,
                        "decision": "dropped", "reason": "byte identical to " + first_by_hash[e.sha].ref,
                        "sha256_12": e.sha[:12]})
        else:
            first_by_hash[e.sha] = e
            distinct.append(e)

    # Stage 2: alternative exports of the same system (same property plus role)
    groups = OrderedDict()
    for e in distinct:
        groups.setdefault((e.prop, e.role), []).append(e)

    fmt_pref = {"summary": 0, "host_detail": 1, "plugin_detail": 2, "unknown": 3}
    systems = []
    plugin_cves = defaultdict(set)
    for e in exports:
        for pid, cs in e.cve_map.items():
            plugin_cves[pid].update(cs)
    checks = []
    for (prop, role), members in groups.items():
        members.sort(key=lambda e: (fmt_pref[e.fmt], -len(e.rows), e.ref))
        rep = members[0]
        merged = len(members)
        fps = {m.fp for m in members if m.fp}
        for m in members[1:]:
            reason = "alternative export of the same system (same property and role)"
            if m.fp and rep.fp and m.fp != rep.fp:
                reason += "; WARNING host fingerprint differs"
            log.append({"file_ref": m.ref, "format": m.fmt, "property": prop, "role": role,
                        "decision": "dropped", "reason": reason + "; kept " + rep.ref,
                        "sha256_12": m.sha[:12]})
        log.append({"file_ref": rep.ref, "format": rep.fmt, "property": prop, "role": role,
                    "decision": "kept", "reason": "representative of %d distinct export(s)" % merged,
                    "sha256_12": rep.sha[:12]})
        if rep.fmt not in ("summary", "host_detail"):
            continue
        # cross-check the representative against its own tile counts
        if rep.tiles and rep.counts:
            checks.append({"file_ref": rep.ref, "tiles_match_rows": dict(rep.tiles) == dict(rep.counts)})
        # cross-check a detailed export against the summary export if both exist
        for m in members[1:]:
            if m.fmt == "host_detail" and m.counts and rep.fmt == "summary":
                checks.append({"file_ref": m.ref, "detail_summary_level_matches_summary":
                               dict(m.counts) == dict(rep.counts)})
        systems.append({"prop": prop, "role": role, "rep": rep, "exports": merged,
                        "fp_count": len(fps)})

    # Build normalised rows
    systems.sort(key=lambda s: (cfg_prop_order(cfg, s["prop"]), labels.ROLE_ORDER.get(s["role"][0], 99),
                                s["role"][1] or 0))
    seq = defaultdict(int)
    sys_rows, finding_rows = [], []
    for s in systems:
        role_key, unit = s["role"]
        rdef = labels.ROLES[role_key]
        seq[(s["prop"], rdef["code"])] += 1
        n = unit if unit else seq[(s["prop"], rdef["code"])]
        sid = "%s-%s-%02d" % (s["prop"], rdef["code"], n)
        rep = s["rep"]
        c = rep.counts
        label = rdef["label"] + (" %d" % unit if unit else "")
        all_cves = set()
        plugin_list = []
        for r in rep.rows:
            cves = set(CVE_RE.findall(r["plugin_name"])) | plugin_cves.get(r["plugin_id"], set())
            all_cves |= cves
            finding_rows.append({
                "system_id": sid, "property": s["prop"], "role": label, "plugin_id": r["plugin_id"],
                "plugin_name": r["plugin_name"], "severity": r["severity"], "cvss": r["cvss"],
                "cve_ids": ";".join(sorted(cves)),
            })
            if r["severity"] != "Info":
                plugin_list.append("%s:%s" % (r["severity"], r["plugin_name"]))
        sys_rows.append({
            "system_id": sid, "property": s["prop"], "role_key": role_key, "role": label,
            "role_group": rdef["group"], "critical": c["Critical"], "high": c["High"],
            "medium": c["Medium"], "low": c["Low"], "info": c["Info"],
            "low_plus": c["Critical"] + c["High"] + c["Medium"] + c["Low"],
            "source_format": rep.fmt, "exports_merged": s["exports"],
            "cve_ids": ";".join(sorted(all_cves)),
            "plugins_low_plus": " | ".join(plugin_list),
        })

    totals = OrderedDict((k, sum(r[k.lower()] for r in sys_rows)) for k in SEVERITIES)
    summary = {
        "html_files_read": len(exports),
        "byte_identical_files_dropped": sum(1 for l in log if l["reason"].startswith("byte identical")),
        "alternative_exports_dropped": sum(1 for l in log if l["reason"].startswith("alternative export")),
        "distinct_systems": len(sys_rows),
        "severity_totals": totals,
        "low_or_above": sum(r["low_plus"] for r in sys_rows),
        "files_by_format": {f: sum(1 for e in exports if e.fmt == f) for f in
                            ("summary", "host_detail", "plugin_detail", "unknown")},
        "unresolved_property_or_role": len(unresolved),
        "internal_checks": checks,
        "parsing_assumptions": [
            "Property and role come from file and folder names only.",
            "A file whose name hides its role inherits property and role from a file with the same host fingerprint (fingerprint is held in memory only).",
            "Detailed host exports are counted at summary level: one row per distinct plugin id.",
        ],
    }
    return sys_rows, finding_rows, log, summary


def cfg_prop_order(cfg, prop):
    codes = list(cfg["properties"].keys())
    return codes.index(prop) if prop in codes else 99


SYS_FIELDS = ["system_id", "property", "role_key", "role", "role_group", "critical", "high", "medium",
              "low", "info", "low_plus", "source_format", "exports_merged", "cve_ids", "plugins_low_plus"]
FIND_FIELDS = ["system_id", "property", "role", "plugin_id", "plugin_name", "severity", "cvss", "cve_ids"]
LOG_FIELDS = ["file_ref", "format", "property", "role", "decision", "reason", "sha256_12"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=os.environ.get("HISS_DATA_DIR"),
                    help="folder holding the Nessus HTML exports (searched recursively)")
    ap.add_argument("--out-dir", default=DATA_DIR)
    a = ap.parse_args(argv)
    if not a.data_dir or not os.path.isdir(a.data_dir):
        print("Data folder not found. Pass --data-dir or set HISS_DATA_DIR.", file=sys.stderr)
        return 2
    sys_rows, find_rows, log, summary = build(a.data_dir)
    # role tuples are stored as strings in the log
    for l in log:
        l["role"] = l["role"][0] + (" %d" % l["role"][1] if l["role"][1] else "") if l["role"] else ""
    write_csv(os.path.join(a.out_dir, "systems_normalised.csv"), sys_rows, SYS_FIELDS)
    write_csv(os.path.join(a.out_dir, "findings_normalised.csv"), find_rows, FIND_FIELDS)
    write_csv(os.path.join(a.out_dir, "parse_log.csv"), log, LOG_FIELDS)
    write_json(os.path.join(a.out_dir, "parse_summary.json"), summary)
    t = summary["severity_totals"]
    print("files %d | dropped %d identical + %d alternative | systems %d | C/H/M/L/I %d/%d/%d/%d/%d | low+ %d" % (
        summary["html_files_read"], summary["byte_identical_files_dropped"],
        summary["alternative_exports_dropped"], summary["distinct_systems"],
        t["Critical"], t["High"], t["Medium"], t["Low"], t["Info"], summary["low_or_above"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
