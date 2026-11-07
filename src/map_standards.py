"""Map recurring finding families to ISO/IEC 27001:2022 Annex A, PCI DSS v4.0.x and GDPR.

config/standards_map.json holds one primary mapping per standard per family, a one line
rationale and a verification status for the PCI DSS requirement number. Plugin names are
assigned to families with the regular expressions in that file.

Optional check:  python src/map_standards.py --iso-xlsx "ISO 27001 Controls.xlsx"
confirms that every mapped Annex A id and title appears in the sheet (needs openpyxl).
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import CONFIG_DIR, DATA_DIR, OUT_DIR, SEV_RANK, load_config, read_csv, write_csv, write_json  # noqa: E402

MAP_FIELDS = ["family_key", "family", "systems_affected", "findings_low_plus", "plugin_rows_all", "iso_27001_2022_control",
              "iso_control_title", "pci_dss_v4_requirement", "pci_status", "gdpr_article", "rationale"]
TOP_FIELDS = ["rank", "plugin_id", "finding", "family", "severity", "systems_affected", "properties_affected",
              "risk_contribution", "cve_ids"]


def load_map():
    with open(os.path.join(CONFIG_DIR, "standards_map.json"), encoding="utf-8") as fh:
        m = json.load(fh)
    for f in m["families"]:
        f["_rx"] = [re.compile(p, re.I) for p in f["patterns"]]
    return m


def classify(plugin_name, fam_map):
    for f in fam_map["families"]:
        if any(rx.search(plugin_name) for rx in f["_rx"]):
            return f["key"]
    return ""


def compute(findings=None, systems=None, cfg=None, fam_map=None):
    cfg = cfg or load_config()
    fam_map = fam_map or load_map()
    findings = findings if findings is not None else read_csv(os.path.join(DATA_DIR, "findings_normalised.csv"))
    fam_of = {}
    for r in findings:
        r["family"] = classify(r["plugin_name"], fam_map)
    rows = []
    for f in fam_map["families"]:
        mine = [r for r in findings if r["family"] == f["key"]]
        low_plus = [r for r in mine if r["severity"] != "Info"]
        rows.append({
            "family_key": f["key"], "family": f["label"],
            "systems_affected": len({r["system_id"] for r in mine}),
            "findings_low_plus": len(low_plus), "plugin_rows_all": len(mine),
            "iso_27001_2022_control": f["iso"], "iso_control_title": f["iso_title"],
            "pci_dss_v4_requirement": f["pci"], "pci_status": f["pci_status"],
            "gdpr_article": f["gdpr"], "rationale": f["rationale"],
        })
    return {"families": rows, "findings": findings}


def top_findings(findings, systems_scored, cfg, limit=25):
    """Rank Low and above plugin rows by risk contribution = severity weight x tier weight, summed over systems."""
    sw = cfg["severity_weights"]
    tier_w = {s["system_id"]: s["tier_weight"] for s in systems_scored}
    groups = {}
    for r in findings:
        if r["severity"] == "Info":
            continue
        key = (r["plugin_id"], r["plugin_name"], r["severity"])
        g = groups.setdefault(key, {"systems": set(), "props": set(), "contrib": 0, "cves": set(),
                                    "family": r.get("family", "")})
        g["systems"].add(r["system_id"])
        g["props"].add(r["property"])
        g["contrib"] += sw[r["severity"]] * tier_w.get(r["system_id"], 1)
        g["cves"].update(c for c in r["cve_ids"].split(";") if c)
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1]["contrib"], -SEV_RANK[kv[0][2]], kv[0][1]))
    out = []
    for i, ((pid, name, sev), g) in enumerate(ordered[:limit], 1):
        out.append({"rank": i, "plugin_id": pid, "finding": name, "family": g["family"] or "other",
                    "severity": sev, "systems_affected": len(g["systems"]),
                    "properties_affected": len(g["props"]), "risk_contribution": g["contrib"],
                    "cve_ids": ";".join(sorted(g["cves"]))})
    return out


def check_iso_sheet(path, fam_map):
    import openpyxl  # noqa: WPS433
    wb = openpyxl.load_workbook(path, read_only=True)
    sheet = {}
    for r in wb.active.iter_rows(values_only=True):
        if r and r[1]:
            sheet[str(r[1]).strip()] = str(r[2]).strip() if r[2] else ""
    problems = []
    for f in fam_map["families"]:
        if sheet.get(f["iso"]) != f["iso_title"]:
            problems.append("%s: %r not matched in sheet" % (f["key"], f["iso"]))
    return {"checked_controls": len({f["iso"] for f in fam_map["families"]}), "problems": problems,
            "all_titles_match": not problems}


def write_outputs(res, out_dir=None):
    out_dir = out_dir or OUT_DIR
    write_csv(os.path.join(out_dir, "standards_mapping.csv"), res["families"], MAP_FIELDS)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso-xlsx", default=os.environ.get("HISS_ISO_XLSX"))
    a = ap.parse_args(argv)
    fam_map = load_map()
    res = compute(fam_map=fam_map)
    write_outputs(res)
    for r in res["families"]:
        print("%-30s sys %2d  low+ %3d  %-7s PCI %-8s %s" % (r["family_key"], r["systems_affected"],
              r["findings_low_plus"], r["iso_27001_2022_control"], r["pci_dss_v4_requirement"], r["gdpr_article"]))
    other = [f for f in res["findings"] if not f["family"] and f["severity"] != "Info"]
    print("Low-or-above rows with no family:", len(other))
    if a.iso_xlsx and os.path.exists(a.iso_xlsx):
        chk = check_iso_sheet(a.iso_xlsx, fam_map)
        write_json(os.path.join(DATA_DIR, "standards_check.json"), chk)
        print("ISO sheet check:", chk)


if __name__ == "__main__":
    main()
