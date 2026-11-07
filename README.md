# HISS-RAT: Hotel Information Security Risk Assessment Toolkit

HISS-RAT is a small Python toolkit for turning Nessus HTML scan exports of a multi property hotel group into a ranked, explainable risk register. It reads the exports, removes duplicates, scores every system by the severity of its findings and the criticality of its role, estimates guest impact and downtime cost with an explicit assumption model, maps recurring finding families to ISO/IEC 27001:2022 Annex A, PCI DSS v4.0.x and GDPR and tests how stable the ranking is when the weights change.

It was written for a Capstone 1 project in MS Cyber Security at REVA University. **This repository contains synthetic sample data only.** No real scan data, host names, addresses or property names are included (see `docs/PRIVACY_NOTE.md`). The numbers you get from the sample describe invented hosts and say nothing about any real hotel.

Licence: MIT (see `LICENSE`).

## Quick start

Requirements: Python 3.8 or later (developed and tested with Python 3.10). The toolkit uses the Python standard library only. PyYAML and matplotlib are optional: PyYAML reads the YAML copy of the configuration (a JSON copy is used when it is missing) and matplotlib is needed only to redraw the charts.

One command, on the bundled synthetic sample:

```
git clone https://github.com/raghunath-thiyagarajan/hiss-rat.git
cd hiss-rat
python3 run_all.py
```

On Windows use `py` instead of `python3`. The command scores the committed sample data and writes every table, `results.json` and `outputs/dashboard.html` to the `outputs` folder. Open the dashboard in any browser. It works offline and on a phone.

Run the tests (27 tests, all on synthetic fixtures):

```
python3 -m unittest discover -s tests -v
python3 run_all.py --tests          # also saves outputs/test_results.txt
```

Run the whole chain from the raw HTML stage on the synthetic sample (parse, score, impact, mapping, sensitivity, dashboard):

```
python3 tools/make_sample_data.py                          # rewrites sample_data/nessus_html/ (19 invented exports)
python3 run_all.py --data-dir sample_data/nessus_html
```

Expected result on the sample: 19 files read, 1 byte identical copy and 2 alternative exports dropped, 16 distinct systems with 11 Critical, 19 High, 39 Medium, 15 Low and 65 Info findings. The highest risk system is PROP-C-SQL-01 (technical score 91, tier weight 5, risk score 455) and the group index is 23.1.

## What it does

1. Parses every Nessus HTML export in a folder, removes byte identical copies and alternative exports of the same system and counts findings at summary level (one row per plugin per host).
2. Scores each system: technical severity score, role criticality tier, risk score, 0 to 100 index and risk band.
3. Aggregates to a property risk index and a group index.
4. Estimates downtime cost for four scenarios (S1 to S4) in low, base and high cases and gives a qualitative guest impact table.
5. Maps twelve finding families to ISO/IEC 27001:2022 Annex A, PCI DSS v4.0.x and GDPR with a one line rationale.
6. Tests how stable the ranking is when weights and tiers change and how far the downtime cost moves when ADR and occupancy change.
7. Writes CSV tables, `results.json` and a self contained HTML dashboard (inline CSS and JavaScript, no external libraries).

## The method in plain terms

Each finding has a Nessus severity. Weighting severe findings more heavily gives a technical severity score for the system. Systems that matter more to hotel operations (the property management system, the database and the domain controller) get a higher tier weight, so the same findings count for more there. The product is the risk score.

```
TS = 10 x Critical + 6 x High + 3 x Medium + 1 x Low             (Info findings score 0)
R  = TS x tier weight                                              (Tier 1 = 5, Tier 2 = 3, Tier 3 = 2, Tier 4 = 1)
System index   = 100 x R / highest R among all systems
Property index = 100 x (sum of R in the property) / (highest property sum)
Group index    = mean system index over all scanned systems
```

Risk bands apply to the absolute risk score R, so that one extreme system does not push every other system into the lowest band.

| Band | Risk score R |
|---|---|
| Critical | 250 or more |
| High | 100 to 249 |
| Medium | 30 to 99 |
| Low | 1 to 29 |
| None | 0 (informational findings only) |

Downtime cost for one property and one scenario:

```
room revenue per hour  = rooms x occupancy x ADR / 24
total revenue per hour = room revenue per hour x (1 + food and beverage uplift)
cost                   = total revenue per hour x revenue dependence x duration in hours
```

Low, base and high cases use occupancy of 55, 65 and 75 percent. Rooms, ADR, uplift, revenue dependence, durations and tiers are assumed values (register A01 to A05 in `config/assumptions.yaml`) and every output that depends on them is labelled assumed.

Sensitivity analysis moves each severity weight by 20 percent in turn, moves tier weights and tier assignments by one level and reports the Spearman rank correlation with the base ranking, whether the top 5 set changes and the range of the group downtime cost for ADR plus and minus 20 percent.

## Using your own exports

Put the Nessus HTML exports in a folder outside this repository and run `python3 run_all.py --data-dir "<folder>"` (or set `HISS_DATA_DIR`). The folder is searched recursively. The parser takes the property and the role from the file or folder name, so name the files like the sample: `PROP-A_PMS_<six character suffix>.html`. Property labels are PROP-A to PROP-F and the role keywords are listed in `src/labels.py`, which you can edit. The parser reads host headings only in memory to recognise duplicates and never writes them out. Keep real exports and anything derived from them out of version control (the `.gitignore` blocks `.nessus` files and HTML files outside the sample and output folders).

Three export layouts are recognised: the summary layout (one row per plugin per host), the detailed host layout (one section per plugin and port, counted as distinct plugin ids so the numbers match the summary layout) and the plugin grouped layout (read but never preferred).

## Folder layout

```
hiss-rat/
  run_all.py              runs the whole pipeline in order
  README.md  LICENSE  CITATION.cff  .gitignore
  config/
    assumptions.yaml      assumption register A01 to A05 as parameters (assumed values)
    assumptions.json      identical copy for machines without PyYAML
    standards_map.json    finding families, patterns and mappings to ISO 27001, PCI DSS and GDPR
  src/
    parse_nessus.py       parser, deduplication and anonymisation
    labels.py             property and role labels from file names
    score.py              TS, R, system index, bands, property and group index
    impact.py             downtime and guest impact model
    map_standards.py      finding family classification and standards mapping
    sensitivity.py        ranking stability and downtime cost range
    report.py             all outputs and the dashboard
    make_figures.py       optional charts (needs matplotlib)
    common.py             paths, configuration loading and CSV helpers
  tools/
    make_sample_data.py   generates the synthetic Nessus style exports
  sample_data/nessus_html/  19 synthetic exports (documentation address ranges, labels PROP-A to PROP-F)
  data/                   normalised CSV produced from the synthetic sample
  outputs/                tables, results.json, dashboard.html, figures and the test log
  tests/                  unittest suite
  docs/PRIVACY_NOTE.md    what is and is not in this repository
```

## Outputs

| File | Content |
|---|---|
| systems_normalised.csv | one row per distinct system with severity counts, role group, plugin list and CVE ids |
| risk_register.csv | systems ranked by risk score with tier, index and band |
| property_summary.csv | severity totals, risk index and mean system index per property |
| role_summary.csv | the same by role group |
| top_findings.csv | Low and above findings ranked by risk contribution |
| impact_scenarios.csv | downtime cost per property and group for S1 to S4 (assumed) |
| guest_impact.csv | qualitative guest impact per scenario (assumed) |
| standards_mapping.csv | finding family to ISO 27001:2022, PCI DSS and GDPR |
| sensitivity.csv and sensitivity_summary.txt | ranking stability and cost range |
| results.json | all key results in one file |
| dashboard.html | self contained dashboard |
| test_results.txt | output of the unit test run |
| figures/*.png | seven charts, written by `python3 src/make_figures.py` (optional) |

`data/` holds `systems_normalised.csv`, `findings_normalised.csv` (one row per plugin per system), `parse_log.csv` (deduplication decisions) and `parse_summary.json` (reconciliation counts).

## Limitations

- Scan counts are evidence of what a scanner reported. Everything that turns counts into money or criticality is assumed: property size classes and rooms (A01), occupancy, ADR and food and beverage uplift (A01 and A02), revenue dependence by outage type (A03), asset tiers and recovery targets (A04) and the four downtime scenarios (A05). Validate them with the hotel before relying on any cost or tier.
- Tiers, band thresholds (250, 100, 30 and 1) and severity weights are design choices, not measurements. The indices are relative to the worst case in the data set and are not absolute measures of exposure.
- Scans run without credentials do not assess missing patches or local settings. A missing patch finding does not mean a system is patched.
- Property and role come from file names. A wrong file name gives a wrong label.
- Detailed host exports list each affected port, so their raw counts are higher. The toolkit counts distinct plugin ids per host for those files and checks that the result equals the summary export when both exist.
- PCI DSS requirement numbers marked "to be verified" in `outputs/standards_mapping.csv` were not confirmed against the standard text. GDPR article numbers were not re-checked against the regulation text. CVE ids are listed where the plugin name or a detailed export carries them, so coverage is partial.
- The parser was written against three Nessus HTML layouts. Other versions or layouts may need changes to the regular expressions in `src/parse_nessus.py`.
- The toolkit supports a risk assessment. It does not replace a professional assessment or a penetration test.

## Citation

See `CITATION.cff`. Author: Raghunath Thiyagarajan, MS Cyber Security, REVA University.

## Licence

MIT. Copyright (c) Raghunath Thiyagarajan. See `LICENSE`.
