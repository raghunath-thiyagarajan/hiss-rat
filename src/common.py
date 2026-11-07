"""Shared helpers for HISS-RAT: paths, configuration loading and small CSV utilities.

Standard library only. PyYAML is used when installed; otherwise the toolkit falls back
to config/assumptions.json, which is kept identical to the YAML file (a unit test checks this).
"""
import csv
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(ROOT, "config")
DATA_DIR = os.path.join(ROOT, "data")
OUT_DIR = os.path.join(ROOT, "outputs")

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def load_config(name="assumptions"):
    """Load config/<name>.yaml with PyYAML if available, else config/<name>.json."""
    ypath = os.path.join(CONFIG_DIR, name + ".yaml")
    jpath = os.path.join(CONFIG_DIR, name + ".json")
    try:
        import yaml  # type: ignore
        with open(ypath, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except ImportError:
        with open(jpath, encoding="utf-8") as fh:
            cfg = json.load(fh)
    return normalise_config(cfg)


def normalise_config(cfg):
    """Make YAML and JSON loads identical (JSON turns integer keys into strings)."""
    if isinstance(cfg, dict) and "tiers" in cfg:
        cfg["tiers"] = {int(k): v for k, v in cfg["tiers"].items()}
    return cfg


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path, rows, fieldnames):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=True)


def to_int(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default
