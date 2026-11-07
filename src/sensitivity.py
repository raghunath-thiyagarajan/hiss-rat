"""Sensitivity analysis for HISS-RAT.

Ranking stability
    Severity weights: each of the four weights is scaled by minus and plus 20 percent in turn,
    plus two opposing combinations (Critical up and the rest down, and the reverse). A uniform
    scaling of all four weights is included as a control because it cannot change the ranking.
    Tier weights: every system is moved one tier more critical and one tier less critical, the
    four tier weights are each moved by minus and plus one, and all four together.
    For every case the system ranking by risk score R is compared with the base case using the
    Spearman rank correlation (average ranks for ties) and the top 5 systems are checked.

Downtime cost range
    ADR is varied by minus and plus 20 percent and occupancy over 55, 65 and 75 percent; the group
    cost of each scenario is reported for every combination.

Outputs: outputs/sensitivity.csv and outputs/sensitivity_summary.txt
"""
import itertools
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import impact  # noqa: E402
import score  # noqa: E402
from common import OUT_DIR, load_config, write_csv  # noqa: E402

FIELDS = ["analysis", "case", "spearman_rho", "top5_overlap", "top5_set_stable", "top5_order_stable",
          "rank1_system", "scenario", "adr_factor", "occupancy", "group_cost_inr"]


def average_ranks(values):
    """Rank 1 = largest value; ties share the mean rank."""
    order = sorted(range(len(values)), key=lambda i: -values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        mean_rank = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = mean_rank
        i = j + 1
    return ranks


def spearman(a, b):
    ra, rb = average_ranks(a), average_ranks(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = math.sqrt(sum((x - ma) ** 2 for x in ra))
    vb = math.sqrt(sum((y - mb) ** 2 for y in rb))
    if va == 0 or vb == 0:
        return 1.0 if va == vb else 0.0
    return cov / (va * vb)


def top_ids(scored, n):
    return [s["system_id"] for s in sorted(scored, key=score.rank_key)[:n]]


def ranking_cases(cfg):
    pct = cfg["sensitivity"]["severity_weight_pct"]
    base_sw = cfg["severity_weights"]
    base_tw = {t: v["weight"] for t, v in cfg["tiers"].items()}
    cases = []
    for sev in ("Critical", "High", "Medium", "Low"):
        for sign, tag in ((-1, "minus"), (1, "plus")):
            sw = dict(base_sw)
            sw[sev] = base_sw[sev] * (1 + sign * pct)
            cases.append(("severity_weights", "%s weight %s %d%%" % (sev, tag, int(pct * 100)), sw, base_tw, 0))
    sw = {k: (v * (1 + pct) if k == "Critical" else v * (1 - pct)) for k, v in base_sw.items()}
    cases.append(("severity_weights", "Critical +%d%% and others -%d%%" % (pct * 100, pct * 100), sw, base_tw, 0))
    sw = {k: (v * (1 - pct) if k == "Critical" else v * (1 + pct)) for k, v in base_sw.items()}
    cases.append(("severity_weights", "Critical -%d%% and others +%d%%" % (pct * 100, pct * 100), sw, base_tw, 0))
    for sign, tag in ((-1, "minus"), (1, "plus")):
        sw = {k: v * (1 + sign * pct) for k, v in base_sw.items()}
        cases.append(("severity_weights", "All weights %s %d%% (control)" % (tag, int(pct * 100)), sw, base_tw, 0))
    cases.append(("tier_weights", "Every system one tier more critical", base_sw, base_tw, -1))
    cases.append(("tier_weights", "Every system one tier less critical", base_sw, base_tw, 1))
    for d, tag in ((-1, "minus"), (1, "plus")):
        tw = {t: max(1, w + d) for t, w in base_tw.items()}
        cases.append(("tier_weights", "All tier weights %s 1" % tag, base_sw, tw, 0))
    for t in sorted(base_tw):
        for d, tag in ((-1, "minus"), (1, "plus")):
            tw = dict(base_tw)
            tw[t] = max(1, tw[t] + d)
            cases.append(("tier_weights", "Tier %d weight %s 1" % (t, tag), base_sw, tw, 0))
    return cases


def run(systems=None, cfg=None):
    cfg = cfg or load_config()
    systems = systems if systems is not None else score.load_systems()
    top_n = cfg["sensitivity"]["top_n"]
    base = score.score_systems(systems, cfg)
    base_r = [s["risk_score"] for s in base]
    base_top = top_ids(base, top_n)
    rows = []
    for analysis, label, sw, tw, shift in ranking_cases(cfg):
        sc = score.score_systems(systems, cfg, sev_w=sw, tier_weights=tw, shift=shift)
        rho = spearman(base_r, [s["risk_score"] for s in sc])
        top = top_ids(sc, top_n)
        rows.append({"analysis": analysis, "case": label, "spearman_rho": round(rho, 4),
                     "top5_overlap": len(set(top) & set(base_top)),
                     "top5_set_stable": set(top) == set(base_top), "top5_order_stable": top == base_top,
                     "rank1_system": top[0]})
    # downtime cost range
    adr_pct = cfg["sensitivity"]["adr_pct"]
    cost_rows = []
    for adr_f, occ in itertools.product((1 - adr_pct, 1.0, 1 + adr_pct), cfg["sensitivity"]["occupancy_range"]):
        res = impact.compute(cfg, adr_factor=adr_f, occupancy_override={"low": occ, "base": occ, "high": occ})
        for g in res["group"]:
            cost_rows.append({"analysis": "downtime_cost", "case": "ADR x%.1f, occupancy %d%%" % (adr_f, round(occ * 100)),
                              "scenario": g["scenario_id"], "adr_factor": round(adr_f, 2), "occupancy": occ,
                              "group_cost_inr": g["cost_base_inr"]})
    return {"base_top": base_top, "ranking": rows, "cost": cost_rows}


def summarise(res, cfg):
    rk = res["ranking"]
    non_control = [r for r in rk if "(control)" not in r["case"]]
    rhos = [r["spearman_rho"] for r in non_control]
    worst = min(non_control, key=lambda r: r["spearman_rho"])
    set_stable = sum(1 for r in non_control if r["top5_set_stable"])
    order_stable = sum(1 for r in non_control if r["top5_order_stable"])
    lines = ["HISS-RAT sensitivity summary (weights and tiers are assumed; see config/assumptions.yaml)", ""]
    lines.append("Base case top 5 systems: " + ", ".join(res["base_top"]))
    lines.append("")
    lines.append("Ranking stability across %d perturbations (control cases excluded)" % len(non_control))
    lines.append("  Spearman rho against base: min %.3f, mean %.3f, max %.3f" % (min(rhos), sum(rhos) / len(rhos), max(rhos)))
    lines.append("  Lowest rho: %s (%.3f)" % (worst["case"], worst["spearman_rho"]))
    lines.append("  Top 5 set unchanged in %d of %d cases; exact order unchanged in %d of %d cases" % (
        set_stable, len(non_control), order_stable, len(non_control)))
    lines.append("  Rank 1 system unchanged in %d of %d cases" % (
        sum(1 for r in non_control if r["rank1_system"] == res["base_top"][0]), len(non_control)))
    unstable = [r for r in non_control if not r["top5_set_stable"]]
    if unstable:
        lines.append("  Cases that change the top 5 set:")
        for r in unstable:
            lines.append("    - %s (overlap %d of 5, rho %.3f)" % (r["case"], r["top5_overlap"], r["spearman_rho"]))
    ctrl = [r for r in rk if "(control)" in r["case"]]
    lines.append("  Control (uniform scaling of all severity weights) rho: " + ", ".join("%.3f" % r["spearman_rho"] for r in ctrl))
    lines.append("")
    lines.append("Downtime cost range, group total in INR (ADR minus and plus %d%%, occupancy 55 to 75%%; assumed)" %
                 int(cfg["sensitivity"]["adr_pct"] * 100))
    for sid, s in cfg["scenarios"].items():
        vals = [r["group_cost_inr"] for r in res["cost"] if r["scenario"] == sid]
        base = [r["group_cost_inr"] for r in res["cost"] if r["scenario"] == sid and r["adr_factor"] == 1.0 and abs(r["occupancy"] - cfg["occupancy"]["base"]) < 1e-9][0]
        lines.append("  %s %-30s min %s | base %s | max %s" % (sid, s["name"], format(min(vals), ","), format(base, ","), format(max(vals), ",")))
    return "\n".join(lines) + "\n", {
        "perturbations": len(non_control), "rho_min": min(rhos), "rho_mean": sum(rhos) / len(rhos),
        "rho_max": max(rhos), "lowest_rho_case": worst["case"], "top5_set_stable_cases": set_stable,
        "top5_order_stable_cases": order_stable,
        "rank1_stable_cases": sum(1 for r in non_control if r["rank1_system"] == res["base_top"][0]),
        "base_top5": res["base_top"],
        "cost_range": {sid: {"min": min(r["group_cost_inr"] for r in res["cost"] if r["scenario"] == sid),
                             "max": max(r["group_cost_inr"] for r in res["cost"] if r["scenario"] == sid)}
                       for sid in cfg["scenarios"]},
    }


def write_outputs(res, cfg, out_dir=None):
    out_dir = out_dir or OUT_DIR
    write_csv(os.path.join(out_dir, "sensitivity.csv"), res["ranking"] + res["cost"], FIELDS)
    text, summary = summarise(res, cfg)
    with open(os.path.join(out_dir, "sensitivity_summary.txt"), "w", encoding="utf-8") as fh:
        fh.write(text)
    return text, summary


def main():
    cfg = load_config()
    res = run(cfg=cfg)
    text, _ = write_outputs(res, cfg)
    print(text)


if __name__ == "__main__":
    main()
