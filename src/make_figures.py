"""Render the HISS-RAT report figures from the anonymised output CSVs (matplotlib required).

    python src/make_figures.py [--src outputs] [--out outputs/figures]

White background, 6.5 inch width, 200 dpi. Titles state the takeaway and are computed from the data.
"""
import argparse, csv, os, sys, textwrap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ap = argparse.ArgumentParser()
_ap.add_argument("--src", default=os.path.join(_ROOT, "outputs"))
_ap.add_argument("--out", default=os.path.join(_ROOT, "outputs", "figures"))
_a = _ap.parse_args()
SRC, OUT = _a.src, _a.out
os.makedirs(OUT, exist_ok=True)
INK, MUTE, GRID = "#1d2430", "#5b6675", "#e3e6ea"
SEV = {"Critical": "#7f1d1d", "High": "#d1453b", "Medium": "#e08a2e", "Low": "#e7bf4a"}
BAND = {"Critical": "#7f1d1d", "High": "#d1453b", "Medium": "#e08a2e", "Low": "#e7bf4a", "None": "#9aa5b1"}
BLUE, ORANGE = "#2a78d6", "#eb6834"
SHORT = {}   # optional display names for property labels; labels are used as they are

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": MUTE, "axes.labelcolor": INK,
                     "text.color": INK, "xtick.color": MUTE, "ytick.color": INK, "axes.spines.top": False,
                     "axes.spines.right": False, "figure.facecolor": "white", "axes.facecolor": "white",
                     "savefig.facecolor": "white"})

def rd(name):
    with open(os.path.join(SRC, name), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

def save(fig, name):
    fig.savefig(os.path.join(OUT, name), dpi=200, metadata={"Software": None})
    plt.close(fig)
    print("wrote", name)

def title(fig, text, sub=None):
    lines = textwrap.wrap(text, 72)
    h = fig.get_size_inches()[1]
    fig.text(0.01, 1 - 0.06 / h * 1.0, "\n".join(lines), ha="left", va="top", fontsize=10, fontweight="bold", color=INK)
    if sub:
        fig.text(0.01, 1 - (0.06 + 0.17 * len(lines) + 0.07) / h, sub, ha="left", va="top", fontsize=7.5, color=MUTE)
    if len(fig.axes) == 1:
        fig.subplots_adjust(top=1 - (0.06 + 0.17 * len(lines) + 0.07 + 0.42) / h)

def stacked(rows, labelkey, fname, ttl, sub, figh):
    fig, ax = plt.subplots(figsize=(6.5, figh))
    names = [r[labelkey] for r in rows][::-1]
    left = [0] * len(rows)
    for sev in ("Critical", "High", "Medium", "Low"):
        vals = [int(r[sev.lower()]) for r in rows][::-1]
        ax.barh(names, vals, left=left, color=SEV[sev], edgecolor="white", linewidth=1.2, height=0.62, label=sev)
        for i, v in enumerate(vals):
            if v >= 4:
                ax.text(left[i] + v / 2, i, str(v), ha="center", va="center", fontsize=7,
                        color="white" if sev != "Low" else INK)
        left = [a + b for a, b in zip(left, vals)]
    for i, tot in enumerate(left):
        ax.text(tot + max(left) * 0.01, i, str(tot), va="center", fontsize=7.5, color=INK)
    ax.set_xlim(0, max(left) * 1.12)
    ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
    ax.set_xlabel("Findings rated Low or above (Info excluded)")
    ax.legend(ncol=4, frameon=False, loc="lower right", bbox_to_anchor=(1.0, 1.0), fontsize=7.5)
    ax.tick_params(length=0)
    fig.subplots_adjust(left=0.36, right=0.97, top=0.80, bottom=0.14)
    title(fig, ttl, sub)
    save(fig, fname)

props = rd("property_summary.csv")
roles = rd("role_summary.csv")
reg = rd("risk_register.csv")
top = rd("top_findings.csv")
imp = [r for r in rd("impact_scenarios.csv") if r["property"] == "GROUP"]
sens = rd("sensitivity.csv")

# 1 severity by property
N_SYS = len(reg)
ch = sum(int(p["critical"]) + int(p["high"]) for p in props) or 1
co = max(props, key=lambda p: int(p["critical"]) + int(p["high"]))
share = round(100 * (int(co["critical"]) + int(co["high"])) / ch)
rows = sorted(props, key=lambda p: -(int(p["critical"]) * 1000 + int(p["high"]) * 100 + int(p["medium"])))
for r in rows:
    r["lab"] = "%s (%s %s)" % (SHORT.get(r["property_label"], r["property_label"]), r["systems_scanned"], "system" if r["systems_scanned"] == "1" else "systems")
stacked(rows, "lab", "fig_severity_by_property.png",
        "%s holds %d percent of the Critical and High findings across the group" % (co["property_label"], share),
        "Evidence: %d distinct systems from the Nessus exports; systems scanned per property differ" % N_SYS, 3.6)

# 2 severity by role
rows = sorted(roles, key=lambda r: -(int(r["critical"]) * 1000 + int(r["high"]) * 100 + int(r["medium"])))
for r in rows:
    r["lab"] = "%s (%s)" % (r["role_group"].replace("Other desktops and managers", "Other desktops"), r["systems"])
sq = [r for r in roles if r["role_group"].startswith("SQL")][0]
stacked(rows, "lab", "fig_severity_by_role.png",
        "SQL servers carry %s of the %s Critical findings" % (sq["critical"], sum(int(r["critical"]) for r in roles)),
        "Evidence: role groups with the number of systems in brackets", 4.3)

# 3 top findings
t10 = top[:10]
fig, ax = plt.subplots(figsize=(6.5, 4.1))
labs = []
for r in t10:
    n = r["finding"].replace("Microsoft ", "")
    labs.append("\n".join(textwrap.wrap(n, 44)[:2]))
vals = [int(r["systems_affected"]) for r in t10]
ax.barh(labs[::-1], vals[::-1], color=[SEV[r["severity"]] for r in t10][::-1], height=0.62, edgecolor="white")
for i, (v, r) in enumerate(zip(vals[::-1], t10[::-1])):
    ax.text(v + 0.3, i, "%d systems" % v, va="center", fontsize=7.5)
ax.set_xlim(0, max(vals) * 1.25)
ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
ax.set_xlabel("Systems affected (of %d)" % N_SYS)
ax.tick_params(axis="y", length=0, labelsize=7)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=SEV[s], label=s) for s in ("Critical", "High", "Medium")], ncol=3, frameon=False,
          loc="lower right", bbox_to_anchor=(1.0, 1.0), fontsize=7.5)
fig.subplots_adjust(left=0.50, right=0.96, top=0.80, bottom=0.13)
lo, hi = min(vals[1:6]), max(vals[:6])
title(fig, "The six most widespread high contribution findings affect %d to %d of %d systems" % (min(vals[:6]), max(vals[:6]), N_SYS),
      "Evidence: ten findings with the highest tier weighted risk contribution, bar colour is the Nessus severity")
save(fig, "fig_top_findings.png")

# 4 risk ranking top 12
t12 = reg[:12]
fig, ax = plt.subplots(figsize=(6.5, 4.0))
labs = ["%s" % r["system_id"] for r in t12][::-1]
vals = [int(r["risk_score"]) for r in t12][::-1]
ax.barh(labs, vals, color=[BAND[r["risk_band"]] for r in t12][::-1], height=0.62, edgecolor="white")
for i, (v, r) in enumerate(zip(vals, t12[::-1])):
    ax.text(v + max(vals) * 0.01, i, "%d" % v, va="center", fontsize=7.5)
ax.set_xlim(0, max(vals) * 1.12)
ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
ax.set_xlabel("Risk score R = technical severity score x tier weight (tiers assumed)")
ax.tick_params(axis="y", length=0, labelsize=7)
ax.legend(handles=[Patch(color=BAND[b], label=b) for b in ("Critical", "High", "Medium")], ncol=3, frameon=False,
          loc="lower right", bbox_to_anchor=(1.0, 1.0), fontsize=7.5)
total = sum(int(r["risk_score"]) for r in reg)
fig.subplots_adjust(left=0.27, right=0.96, top=0.80, bottom=0.14)
title(fig, "%s holds %d percent of the group's total risk score" % (reg[0]["system_id"], round(100 * int(reg[0]["risk_score"]) / max(total, 1))),
      "Top %d of %d systems by risk score; bar colour is the risk band (thresholds 250 and 100)" % (len(t12), N_SYS))
save(fig, "fig_risk_ranking.png")

# 5 property risk index
rows = sorted(props, key=lambda p: -float(p["property_risk_index"]))
fig, ax = plt.subplots(figsize=(6.5, 3.4))
labs = ["%s (%s)" % (SHORT.get(p["property_label"], p["property_label"]), p["systems_scanned"]) for p in rows][::-1]
vals = [float(p["property_risk_index"]) for p in rows][::-1]
ax.barh(labs, vals, color=BLUE, height=0.58, edgecolor="white")
for i, v in enumerate(vals):
    ax.text(v + 1.2, i, "%.1f" % v, va="center", fontsize=7.5)
ax.set_xlim(0, 115)
ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
ax.set_xlabel("Property risk index (highest property = 100)")
ax.tick_params(axis="y", length=0)
fig.subplots_adjust(left=0.30, right=0.96, top=0.80, bottom=0.17)
title(fig, "%s sets the property risk index; %s is next at %.0f" % (rows[0]["property_label"], rows[1]["property_label"], float(rows[1]["property_risk_index"])),
      "Systems scanned in brackets; a property with few scanned systems has an index that reflects limited coverage")
save(fig, "fig_property_risk_index.png")

# 6 impact scenarios
fig, ax = plt.subplots(figsize=(6.5, 3.5))
names = ["\n".join(textwrap.wrap("%s %s" % (r["scenario_id"], r["scenario"]), 18)) + "\n(%s h)" % r["duration_hours"] for r in imp]
base = [int(r["cost_base_inr"]) / 1e6 for r in imp]
lo = [int(r["cost_low_inr"]) / 1e6 for r in imp]
hi = [int(r["cost_high_inr"]) / 1e6 for r in imp]
ax.bar(names, base, color=ORANGE, width=0.55, edgecolor="white", label="Base case (65 percent occupancy)")
ax.errorbar(names, base, yerr=[[b - l for b, l in zip(base, lo)], [h - b for b, h in zip(base, hi)]], fmt="none",
            ecolor=INK, capsize=4, linewidth=1, label="Low to high (55 to 75 percent)")
for i, (b, l, h) in enumerate(zip(base, lo, hi)):
    ax.text(i, h + 0.05, "%.2f\n(%.2f to %.2f)" % (b, l, h), ha="center", va="bottom", fontsize=7)
ax.set_ylim(0, max(hi) * 1.28)
ax.yaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
ax.set_ylabel("INR million (assumed)")
ax.tick_params(axis="x", length=0, labelsize=7)
ax.legend(frameon=False, fontsize=7.5, loc="upper right")
fig.subplots_adjust(left=0.11, right=0.97, bottom=0.2)
title(fig, "Assumed: the %s hour %s scenario costs the group about INR %.1f million" % (imp[0]["duration_hours"], imp[0]["scenario"], base[0]),
      "Assumed values only: rooms, ADR, occupancy, food and beverage uplift and revenue dependence are not measured")
save(fig, "fig_impact_scenarios.png")

# 7 sensitivity
rk = [r for r in sens if r["analysis"] in ("severity_weights", "tier_weights") and "(control)" not in r["case"]]
rk = sorted(rk, key=lambda r: float(r["spearman_rho"]))
cost = [r for r in sens if r["analysis"] == "downtime_cost"]
fig = plt.figure(figsize=(6.5, 7.4))
gs = fig.add_gridspec(2, 1, height_ratios=[3.4, 1.35], hspace=0.42, left=0.36, right=0.96, top=0.865, bottom=0.085)
ax = fig.add_subplot(gs[0])
y = list(range(len(rk)))
ax.scatter([float(r["spearman_rho"]) for r in rk], y, s=26, zorder=3,
           color=[BLUE if r["top5_set_stable"] == "True" else ORANGE for r in rk])
ax.set_yticks(y); ax.set_yticklabels([r["case"].replace(" weight", "").replace("Every system", "All systems") for r in rk], fontsize=6.5)
ax.axvline(1.0, color=MUTE, linewidth=0.8, linestyle=":")
ax.set_xlim(0.975, 1.003)
ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
ax.set_xlabel("Spearman rank correlation with the base ranking (%d systems)" % N_SYS)
ax.tick_params(axis="y", length=0)
ax.set_title("A. Ranking stability, %d perturbations" % len(rk), loc="left", fontsize=8.5, color=INK)
ax.legend(handles=[plt.Line2D([], [], marker="o", ls="", color=BLUE, label="Top 5 set unchanged"),
                   plt.Line2D([], [], marker="o", ls="", color=ORANGE, label="Top 5 set changes")],
          frameon=False, fontsize=7, loc="center left", bbox_to_anchor=(0.0, 0.25))
ax2 = fig.add_subplot(gs[1])
sc = sorted({r["scenario"] for r in cost})
labs, mins, maxs, bases = [], [], [], []
for s in sc:
    v = [int(r["group_cost_inr"]) / 1e6 for r in cost if r["scenario"] == s]
    b = [int(r["group_cost_inr"]) / 1e6 for r in cost if r["scenario"] == s and r["case"] == "ADR x1.0, occupancy 65%"][0]
    labs.append(s); mins.append(min(v)); maxs.append(max(v)); bases.append(b)
ax2.barh(labs[::-1], [h - l for l, h in zip(mins, maxs)][::-1], left=mins[::-1], color="#c9d6e6", height=0.5, edgecolor="white")
ax2.scatter(bases[::-1], labs[::-1], color=ORANGE, zorder=3, s=22)
for i, (l, h) in enumerate(zip(mins[::-1], maxs[::-1])):
    ax2.text(h + 0.04, i, "%.2f to %.2f" % (l, h), va="center", fontsize=7)
ax2.set_xlim(0, max(maxs) * 1.25)
ax2.xaxis.grid(True, color=GRID, linewidth=0.6); ax2.set_axisbelow(True)
ax2.set_xlabel("Group cost, INR million (assumed)\nADR minus and plus 20 percent, occupancy 55 to 75 percent")
ax2.set_title("B. Downtime cost range (dot = base case)", loc="left", fontsize=8.5, color=INK)
ax2.tick_params(axis="y", length=0)
_s1 = [int(r["group_cost_inr"]) for r in cost if r["scenario"] == sc[0]]
_b1 = [int(r["group_cost_inr"]) for r in cost if r["scenario"] == sc[0] and r["case"] == "ADR x1.0, occupancy 65%"][0]
title(fig, "Ranking correlation stays at or above %.2f when weights and tiers change; cost estimates move %d percent lower to %d percent higher" % (
          min(float(r["spearman_rho"]) for r in rk), round(100 * (1 - min(_s1) / _b1)), round(100 * (max(_s1) / _b1 - 1))),
      "Severity weights plus and minus 20 percent, tier weights plus and minus one level; ADR and occupancy are assumed")
save(fig, "fig_sensitivity.png")
