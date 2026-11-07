#!/usr/bin/env python3
"""Run the whole HISS-RAT pipeline in order.

    python run_all.py                       use the committed synthetic sample data/systems_normalised.csv
    python run_all.py --data-dir "<folder>" parse the Nessus HTML exports first (set HISS_DATA_DIR instead if preferred)
    python run_all.py --tests               also run the unit tests and save outputs/test_results.txt
    python run_all.py --iso-xlsx "<file>"   also check mapped ISO control titles against an ISO control sheet

Order: parse, score, impact, standards mapping, sensitivity, report (all output files and the dashboard).
"""
import argparse
import io
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

import common  # noqa: E402


def sync_json_config():
    """Keep config/assumptions.json identical to the YAML file when PyYAML is available."""
    try:
        import yaml
    except ImportError:
        return
    with open(os.path.join(common.CONFIG_DIR, "assumptions.yaml"), encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    with open(os.path.join(common.CONFIG_DIR, "assumptions.json"), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


def step(name, fn, *a):
    t = time.time()
    print("\n=== %s ===" % name)
    rc = fn(*a)
    print("(%s done in %.1f s)" % (name, time.time() - t))
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default=os.environ.get("HISS_DATA_DIR"))
    ap.add_argument("--iso-xlsx", default=os.environ.get("HISS_ISO_XLSX"))
    ap.add_argument("--tests", action="store_true")
    a = ap.parse_args()

    import impact, map_standards, parse_nessus, report, score, sensitivity  # noqa: E401
    sync_json_config()
    if a.data_dir:
        if step("1 parse Nessus exports", parse_nessus.main, ["--data-dir", a.data_dir]) not in (0, None):
            return 2
    else:
        print("No data folder given: using the committed synthetic sample in data/systems_normalised.csv")
    step("2 score", score.main)
    step("3 impact", impact.main)
    margs = ["--iso-xlsx", a.iso_xlsx] if a.iso_xlsx else []
    step("4 standards mapping", map_standards.main, margs)
    step("5 sensitivity", sensitivity.main)
    step("6 report and dashboard", report.main)
    if a.tests:
        print("\n=== 7 unit tests ===")
        env = dict(os.environ)
        if a.data_dir:
            env["HISS_DATA_DIR"] = a.data_dir
        p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        print(p.stdout)
        with open(os.path.join(common.OUT_DIR, "test_results.txt"), "w", encoding="utf-8") as fh:
            fh.write("HISS-RAT\n\n" + p.stdout)
        return p.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
