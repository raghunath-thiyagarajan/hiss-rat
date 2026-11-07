"""Downtime and guest impact model for scenarios S1 to S4.

Every parameter is an ASSUMED input from config/assumptions.yaml (A01 to A05). Nothing here is
measured. Cost formula for one property and one scenario:

    room revenue per hour  = rooms x occupancy x ADR / 24
    total revenue per hour = room revenue per hour x (1 + F and B uplift)
    cost                   = total revenue per hour x revenue dependence x duration hours

Low, base and high cases use occupancy 55, 65 and 75 percent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import OUT_DIR, load_config, write_csv  # noqa: E402

IMPACT_FIELDS = ["property", "property_label", "size_class", "rooms", "adr_inr", "scenario_id", "scenario",
                 "duration_hours", "revenue_dependence", "hourly_loss_base_inr", "cost_low_inr",
                 "cost_base_inr", "cost_high_inr", "assumed_rto_hours", "hours_beyond_rto", "basis"]
GUEST_FIELDS = ["scenario_id", "scenario", "check_in_delay", "billing_errors", "key_card_failure",
                "payment_failure", "privacy_exposure", "note", "basis"]

# Qualitative guest impact (assumed, A11 and A09 and A10). Levels: None, Low, Medium, High.
GUEST_IMPACT = [
    {"scenario_id": "S1", "check_in_delay": "High", "billing_errors": "High", "key_card_failure": "Medium",
     "payment_failure": "Medium", "privacy_exposure": "High",
     "note": "Manual registration and folios; new key cards depend on the PMS while existing keys keep working; "
             "standalone card terminals still work; ID scans and Form C records are exposed if data is stolen."},
    {"scenario_id": "S2", "check_in_delay": "Medium", "billing_errors": "Medium", "key_card_failure": "Low",
     "payment_failure": "Low", "privacy_exposure": "High",
     "note": "Logon failures slow front desk and POS use; stolen directory credentials open file shares and "
             "the PMS database."},
    {"scenario_id": "S3", "check_in_delay": "Low", "billing_errors": "High", "key_card_failure": "High",
     "payment_failure": "Medium", "privacy_exposure": "Low",
     "note": "POS charges stop posting to room folios and the key encoder link breaks; guests are affected "
             "at check in and check out."},
    {"scenario_id": "S4", "check_in_delay": "None", "billing_errors": "None", "key_card_failure": "None",
     "payment_failure": "None", "privacy_exposure": "Low",
     "note": "In room entertainment, casting and service requests fail; compensation and complaints rise; "
             "cleartext FTP and SMTP content is a minor leakage path."},
]


def hourly_total_revenue(rooms, occupancy, adr, uplift):
    return rooms * occupancy * adr / 24.0 * (1.0 + uplift)


def scenario_cost(rooms, occupancy, adr, uplift, dependence, hours):
    return hourly_total_revenue(rooms, occupancy, adr, uplift) * dependence * hours


def compute(cfg=None, adr_factor=1.0, occupancy_override=None):
    cfg = cfg or load_config()
    occ = occupancy_override or cfg["occupancy"]
    rows = []
    for code, p in cfg["properties"].items():
        sc = cfg["size_classes"][p["size_class"]]
        adr = sc["adr_inr"] * adr_factor
        for sid, s in cfg["scenarios"].items():
            costs = {k: scenario_cost(sc["rooms"], occ[k], adr, cfg["fb_uplift"],
                                      s["revenue_dependence"], s["duration_hours"])
                     for k in ("low", "base", "high")}
            rto = cfg["tiers"][s["affected_tier"]]["rto_hours"]
            rows.append({
                "property": code, "property_label": p["label"], "size_class": p["size_class"],
                "rooms": sc["rooms"], "adr_inr": round(adr), "scenario_id": sid, "scenario": s["name"],
                "duration_hours": s["duration_hours"], "revenue_dependence": s["revenue_dependence"],
                "hourly_loss_base_inr": round(hourly_total_revenue(sc["rooms"], occ["base"], adr,
                                                                    cfg["fb_uplift"]) * s["revenue_dependence"]),
                "cost_low_inr": round(costs["low"]), "cost_base_inr": round(costs["base"]),
                "cost_high_inr": round(costs["high"]),
                "assumed_rto_hours": rto, "hours_beyond_rto": max(0, s["duration_hours"] - rto),
                "basis": "assumed",
            })
    group = []
    for sid, s in cfg["scenarios"].items():
        mine = [r for r in rows if r["scenario_id"] == sid]
        group.append({
            "property": "GROUP", "property_label": "Group total (6 properties)", "size_class": "",
            "rooms": sum(r["rooms"] for r in mine), "adr_inr": "", "scenario_id": sid,
            "scenario": s["name"], "duration_hours": s["duration_hours"],
            "revenue_dependence": s["revenue_dependence"],
            "hourly_loss_base_inr": sum(r["hourly_loss_base_inr"] for r in mine),
            "cost_low_inr": sum(r["cost_low_inr"] for r in mine),
            "cost_base_inr": sum(r["cost_base_inr"] for r in mine),
            "cost_high_inr": sum(r["cost_high_inr"] for r in mine),
            "assumed_rto_hours": cfg["tiers"][s["affected_tier"]]["rto_hours"],
            "hours_beyond_rto": max(0, s["duration_hours"] - cfg["tiers"][s["affected_tier"]]["rto_hours"]),
            "basis": "assumed",
        })
    guest = []
    for g in GUEST_IMPACT:
        guest.append(dict(g, scenario=cfg["scenarios"][g["scenario_id"]]["name"], basis="assumed"))
    return {"rows": rows, "group": group, "guest": guest}


def write_outputs(res, out_dir=None):
    out_dir = out_dir or OUT_DIR
    write_csv(os.path.join(out_dir, "impact_scenarios.csv"), res["rows"] + res["group"], IMPACT_FIELDS)
    write_csv(os.path.join(out_dir, "guest_impact.csv"), res["guest"], GUEST_FIELDS)


def main():
    res = compute()
    write_outputs(res)
    print("Group downtime cost, INR (assumed): low / base / high")
    for g in res["group"]:
        print("%s %-32s %12s %12s %12s" % (g["scenario_id"], g["scenario"], format(g["cost_low_inr"], ","),
                                           format(g["cost_base_inr"], ","), format(g["cost_high_inr"], ",")))


if __name__ == "__main__":
    main()
