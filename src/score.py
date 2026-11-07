"""Risk scoring for HISS-RAT.

Formulae (all weights are in config/assumptions.yaml)
    TS  = 10 x Critical + 6 x High + 3 x Medium + 1 x Low          technical severity score
    w   = tier weight of the system role (A04: 5, 3, 2, 1)           criticality multiplier
    R   = TS x w                                                      risk score
    SI  = 100 x R / max(R over all systems)                           system index, 0 to 100
    Band thresholds apply to the absolute R so that one extreme system does not push every
    other system into the lowest band:
        Critical R >= 250 | High 100 to 249 | Medium 30 to 99 | Low 1 to 29 | None R = 0
    PRI = 100 x sum(R of the property) / max over properties of that sum     property risk index
    GI  = mean of SI over all scanned systems                                 group index
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DATA_DIR, OUT_DIR, load_config, read_csv, to_int, write_csv  # noqa: E402

RISK_FIELDS = ["rank", "system_id", "property", "role", "role_group", "tier", "tier_weight", "critical",
               "high", "medium", "low", "info", "technical_score", "risk_score", "system_index",
               "risk_band"]
PROP_FIELDS = ["property", "property_label", "systems_scanned", "critical", "high", "medium", "low", "info",
               "low_plus", "total_risk_score", "property_risk_index", "mean_system_index",
               "systems_critical_band", "systems_high_band", "worst_system"]
ROLE_FIELDS = ["role_group", "systems", "critical", "high", "medium", "low", "info", "technical_score",
               "total_risk_score", "mean_system_index"]


def load_systems(path=None):
    rows = read_csv(path or os.path.join(DATA_DIR, "systems_normalised.csv"))
    for r in rows:
        for k in ("critical", "high", "medium", "low", "info", "low_plus", "exports_merged"):
            r[k] = to_int(r.get(k))
    return rows


def technical_score(r, sev_w):
    return (sev_w["Critical"] * r["critical"] + sev_w["High"] * r["high"] +
            sev_w["Medium"] * r["medium"] + sev_w["Low"] * r["low"])


def band_for(risk, bands):
    if risk >= bands["Critical"]:
        return "Critical"
    if risk >= bands["High"]:
        return "High"
    if risk >= bands["Medium"]:
        return "Medium"
    if risk >= bands["Low"]:
        return "Low"
    return "None"


def tier_of(r, cfg, shift=0):
    t = cfg["role_tier"][r["role_key"]]
    return min(4, max(1, t + shift))


def score_systems(systems, cfg, sev_w=None, tier_weights=None, shift=0):
    """Return a list of dicts with TS, tier, weight and R. Does not rank."""
    sev_w = sev_w or cfg["severity_weights"]
    tw = tier_weights or {t: v["weight"] for t, v in cfg["tiers"].items()}
    out = []
    for r in systems:
        tier = tier_of(r, cfg, shift)
        ts = technical_score(r, sev_w)
        out.append(dict(r, tier=tier, tier_weight=tw[tier], technical_score=ts,
                        risk_score=ts * tw[tier]))
    return out


def rank_key(s):
    return (-s["risk_score"], -s["technical_score"], s["system_id"])


def compute(systems=None, cfg=None):
    cfg = cfg or load_config()
    systems = systems if systems is not None else load_systems()
    scored = score_systems(systems, cfg)
    scored.sort(key=rank_key)
    max_r = max((s["risk_score"] for s in scored), default=0) or 1
    register = []
    for i, s in enumerate(scored, 1):
        s["rank"] = i
        s["system_index"] = round(100.0 * s["risk_score"] / max_r, 1)
        s["risk_band"] = band_for(s["risk_score"], cfg["risk_bands"])
        register.append(s)

    props = []
    max_prop_r = 0
    by_prop = {}
    for s in register:
        by_prop.setdefault(s["property"], []).append(s)
    for code, meta in cfg["properties"].items():
        members = by_prop.get(code, [])
        tot = sum(m["risk_score"] for m in members)
        max_prop_r = max(max_prop_r, tot)
    max_prop_r = max_prop_r or 1
    for code, meta in cfg["properties"].items():
        members = by_prop.get(code, [])
        tot = sum(m["risk_score"] for m in members)
        worst = members[0]["system_id"] if members else ""
        props.append({
            "property": code, "property_label": meta["label"], "systems_scanned": len(members),
            "critical": sum(m["critical"] for m in members), "high": sum(m["high"] for m in members),
            "medium": sum(m["medium"] for m in members), "low": sum(m["low"] for m in members),
            "info": sum(m["info"] for m in members),
            "low_plus": sum(m["critical"] + m["high"] + m["medium"] + m["low"] for m in members),
            "total_risk_score": tot,
            "property_risk_index": round(100.0 * tot / max_prop_r, 1),
            "mean_system_index": round(sum(m["system_index"] for m in members) / len(members), 1) if members else 0,
            "systems_critical_band": sum(1 for m in members if m["risk_band"] == "Critical"),
            "systems_high_band": sum(1 for m in members if m["risk_band"] == "High"),
            "worst_system": worst,
        })

    roles = {}
    for s in register:
        g = roles.setdefault(s["role_group"], [])
        g.append(s)
    role_rows = []
    for name, members in roles.items():
        role_rows.append({
            "role_group": name, "systems": len(members),
            "critical": sum(m["critical"] for m in members), "high": sum(m["high"] for m in members),
            "medium": sum(m["medium"] for m in members), "low": sum(m["low"] for m in members),
            "info": sum(m["info"] for m in members),
            "technical_score": sum(m["technical_score"] for m in members),
            "total_risk_score": sum(m["risk_score"] for m in members),
            "mean_system_index": round(sum(m["system_index"] for m in members) / len(members), 1),
        })
    role_rows.sort(key=lambda r: -r["total_risk_score"])

    total_r = sum(s["risk_score"] for s in register)
    group = {
        "systems": len(register),
        "group_index": round(sum(s["system_index"] for s in register) / len(register), 1) if register else 0,
        "total_risk_score": total_r,
        "worst_system": register[0]["system_id"] if register else "",
        "worst_system_share_of_total_r": round(register[0]["risk_score"] / total_r, 3) if total_r else 0,
        "band_counts": {b: sum(1 for s in register if s["risk_band"] == b)
                        for b in ("Critical", "High", "Medium", "Low", "None")},
        "bands": cfg["risk_bands"],
    }
    return {"register": register, "properties": props, "roles": role_rows, "group": group}


def write_outputs(res, out_dir=None):
    out_dir = out_dir or OUT_DIR
    write_csv(os.path.join(out_dir, "risk_register.csv"), res["register"], RISK_FIELDS)
    write_csv(os.path.join(out_dir, "property_summary.csv"), res["properties"], PROP_FIELDS)
    write_csv(os.path.join(out_dir, "role_summary.csv"), res["roles"], ROLE_FIELDS)


def main():
    res = compute()
    write_outputs(res)
    print("Top 10 systems by risk score")
    for s in res["register"][:10]:
        print("%2d %-22s TS %4d x %d = R %5d  index %5.1f  %s" % (
            s["rank"], s["system_id"], s["technical_score"], s["tier_weight"], s["risk_score"],
            s["system_index"], s["risk_band"]))
    print("Group:", res["group"])
    for p in res["properties"]:
        print("%-20s R %5d  PRI %5.1f  mean SI %5.1f" % (p["property_label"], p["total_risk_score"],
                                                          p["property_risk_index"], p["mean_system_index"]))


if __name__ == "__main__":
    main()
