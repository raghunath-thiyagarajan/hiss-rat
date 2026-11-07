"""Unit tests for HISS-RAT. Run from the repository root:  python -m unittest discover -s tests -v

All inputs are synthetic. Small HTML files are generated on the fly for the parser and dedup tests.
The script tools/make_sample_data.py provides the full invented sample (hosts in the documentation address
ranges 192.0.2.0/24 and 198.51.100.0/24, labels PROP-A to PROP-F). No real scan data is needed.
"""
import csv
import filecmp
import ipaddress
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import common  # noqa: E402
import impact  # noqa: E402
import make_sample_data  # noqa: E402
import map_standards  # noqa: E402
import parse_nessus  # noqa: E402
import score  # noqa: E402
import sensitivity  # noqa: E402

COLOURS = {"Critical": "#91243E", "High": "#DD4B50", "Medium": "#F18C43", "Low": "#F8C851", "Info": "#67ACE1"}
SEVS = ["Critical", "High", "Medium", "Low", "Info"]


def summary_html(host, rows):
    """Minimal Nessus summary style export: tiles plus one plugin row per finding."""
    counts = {s: sum(1 for r in rows if r[0] == s) for s in SEVS}
    tiles = "".join('<td><div style="font-size: 45px; font-weight: 300;">%d</div></td>' % counts[s] for s in SEVS)
    trs = ""
    for i, (sev, name) in enumerate(rows):
        trs += ('<tr class="plugin-row"><td></td><td><span style="display: inline-block; width: 60px; '
                'text-transform: uppercase; background: %s; font-size: 10px;">%s</span></td><td></td><td>5.0</td>'
                '<td></td><td>-</td><td></td><td><a href="/plugins/nessus/%d"> %d</a></td>'
                '<td>%s</td></tr>' % (COLOURS[sev], sev, 1000 + i, 1000 + i, name))
    return ('<html><body><h6>Vulnerabilities by Host</h6><div xmlns="" id="id2" style="font-size: 22px;">%s'
            '<div class="clear"></div></div><table><tr>%s</tr></table><table>%s'
            '<tr class="plugin-row"><td>* footnote</td></tr></table></body></html>' % (host, tiles, trs))


def detail_html(host, plugins):
    """Minimal detailed host export: plugin id may repeat (one section per port)."""
    secs = ""
    for i, (pid, sev, name) in enumerate(plugins):
        secs += ('<div xmlns="" id="id%d" style="box-sizing: border-box; background: %s; font-weight: 700;" class="" '
                 "onclick=\"toggleSection('id%d-container');\">%d - %s<div id=\"id%d-toggletext\"></div></div>"
                 '<div id="id%d-container">text</div>' % (10 + i, COLOURS[sev], 10 + i, pid, name, 10 + i, 10 + i))
    return ('<html><body><h6>Vulnerabilities by Host</h6><div xmlns="" id="id2">%s<div class="clear"></div></div>'
            '%s</body></html>' % (host, secs))


def write(dirpath, name, text):
    with open(os.path.join(dirpath, name), "w", encoding="utf-8") as fh:
        fh.write(text)


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        return parse_nessus.build(self.d)

    def test_byte_identical_files_collapse(self):
        h = summary_html("host-a", [("High", "Plugin one"), ("Medium", "Plugin two"), ("Info", "Plugin three")])
        write(self.d, "PROP-F_AD_aaaaaa.html", h)
        write(self.d, "PROP-F_AD_bbbbbb.html", h)
        sys_rows, _, log, summ = self.build()
        self.assertEqual(len(sys_rows), 1)
        self.assertEqual(summ["byte_identical_files_dropped"], 1)

    def test_alternative_export_same_property_and_role(self):
        write(self.d, "PROP-C_SQL_aaaaaa.html", summary_html("host-b", [("Critical", "A"), ("Info", "B")]))
        write(self.d, "PROP-C_SQL_bbbbbb.html", summary_html("host-b", [("Critical", "A"), ("Info", "B"), ("Info", "C")]))
        sys_rows, _, _, summ = self.build()
        self.assertEqual(len(sys_rows), 1)
        self.assertEqual(summ["alternative_exports_dropped"], 1)
        self.assertEqual(sys_rows[0]["info"], 2)   # the fuller export is kept

    def test_distinct_roles_are_distinct_systems(self):
        write(self.d, "PROP-F_AD_aaaaaa.html", summary_html("host-c", [("High", "A")]))
        write(self.d, "PROP-F_ACCOUNTING_bbbbbb.html", summary_html("host-d", [("High", "A")]))
        sys_rows, _, _, _ = self.build()
        self.assertEqual(len(sys_rows), 2)
        self.assertEqual({r["system_id"] for r in sys_rows}, {"PROP-F-AD-01", "PROP-F-ACCT-01"})

    def test_summary_export_preferred_and_detail_counted_at_summary_level(self):
        plugins = [(101, "High", "P1"), (101, "High", "P1"), (102, "Medium", "P2"), (103, "Info", "P3"),
                   (103, "Info", "P3"), (103, "Info", "P3")]
        write(self.d, "PROP-D_ACCOUNTS_aaaaaa.html", detail_html("host-e", plugins))
        _, _, _, _ = self.build()
        sys_rows, _, _, _ = self.build()
        self.assertEqual((sys_rows[0]["high"], sys_rows[0]["medium"], sys_rows[0]["info"]), (1, 1, 1))
        write(self.d, "PROP-D_ACCOUNTS_bbbbbb.html", summary_html("host-e", [("High", "P1"), ("Medium", "P2"),
                                                                         ("Info", "P3")]))
        sys_rows, _, _, summ = self.build()
        self.assertEqual(len(sys_rows), 1)
        self.assertEqual(sys_rows[0]["source_format"], "summary")
        self.assertTrue(all(c.get("detail_summary_level_matches_summary", True) for c in summ["internal_checks"]))

    def test_output_has_no_raw_identifiers(self):
        write(self.d, "PROP-F_AD_aaaaaa.html", summary_html("host-sentinel-xyz", [("High", "Plugin one")]))
        sys_rows, find_rows, log, _ = self.build()
        blob = repr(sys_rows) + repr(find_rows) + repr(log)
        self.assertNotIn("host-sentinel-xyz", blob)

    def test_label_resolution(self):
        import labels
        self.assertEqual(labels.resolve_property("x/Interfaceserver_PROP-C_abc123.html")[0], "PROP-C")
        self.assertEqual(labels.resolve_property("_unzipped/PROP-F/accounts_abc124.html")[0], "PROP-F")
        self.assertEqual(labels.resolve_property("Frontdesk2_prop_e_abc125.html")[0], "PROP-E")
        self.assertEqual(labels.resolve_property("unlabelled_export_abc129.html"), (None, "unresolved"))
        self.assertEqual(labels.resolve_role("PROP-E_FRONTDESK2_abc125.html"), ("frontdesk", 2))
        self.assertEqual(labels.resolve_role("PROP-C_SQLBACKUP_abc126.html"), ("sqlbackup", None))
        self.assertEqual(labels.resolve_role("PROP-A_ADMIN_abc127.html"), ("admin", None))
        self.assertEqual(labels.resolve_role("PROP-A_AD_abc128.html"), ("ad", None))
        self.assertEqual(labels.resolve_role("PROP-B_scan_abc129.html"), None)

    def test_role_hidden_in_file_name_is_resolved_from_host_fingerprint(self):
        write(self.d, "PROP-C_SQLBACKUP_aaaaaa.html", summary_html("host-f", [("High", "A"), ("Info", "B")]))
        write(self.d, "PROP-C_scan_bbbbbb.html", detail_html("host-f", [(1, "High", "A"), (1, "High", "A"), (2, "Info", "B")]))
        sys_rows, _, _, summ = self.build()
        self.assertEqual(summ["unresolved_property_or_role"], 0)
        self.assertEqual([r["system_id"] for r in sys_rows], ["PROP-C-SQLBK-01"])
        self.assertEqual(sys_rows[0]["exports_merged"], 2)


class ReconciliationTests(unittest.TestCase):
    """Parser results against the figures defined by tools/make_sample_data.py (synthetic sample)."""

    EXPECT_TOTALS = {"critical": 11, "high": 19, "medium": 39, "low": 15, "info": 65}
    EXPECT_BY_PROPERTY = {"PROP-A": 4, "PROP-B": 2, "PROP-C": 4, "PROP-D": 2, "PROP-E": 2, "PROP-F": 2}

    def check(self, rows):
        self.assertEqual(len(rows), 16)
        for k, v in self.EXPECT_TOTALS.items():
            self.assertEqual(sum(int(r[k]) for r in rows), v, k)
        self.assertEqual(sum(int(r["low_plus"]) for r in rows), 84)
        by = {}
        for r in rows:
            by[r["property"]] = by.get(r["property"], 0) + 1
        self.assertEqual(by, self.EXPECT_BY_PROPERTY)
        self.assertEqual(len({r["system_id"] for r in rows}), 16)

    def test_committed_normalised_csv(self):
        self.check(common.read_csv(os.path.join(common.DATA_DIR, "systems_normalised.csv")))

    def test_prop_c_sql_is_the_worst_host(self):
        rows = {r["system_id"]: r for r in common.read_csv(os.path.join(common.DATA_DIR, "systems_normalised.csv"))}
        r = rows["PROP-C-SQL-01"]
        self.assertEqual((r["critical"], r["high"], r["medium"], r["low"]), ("4", "5", "6", "3"))
        self.assertEqual(r["low_plus"], "18")

    def test_parse_of_generated_sample(self):
        with tempfile.TemporaryDirectory() as d:
            make_sample_data.generate(d)
            rows, _, log, summ = parse_nessus.build(d)
        self.check([{k: str(v) for k, v in r.items()} for r in rows])
        self.assertEqual(summ["html_files_read"], 19)
        self.assertEqual(summ["byte_identical_files_dropped"], 1)
        self.assertEqual(summ["alternative_exports_dropped"], 2)
        self.assertEqual(summ["unresolved_property_or_role"], 0)
        self.assertTrue(all(c.get("tiles_match_rows", True) and c.get("detail_summary_level_matches_summary", True)
                            for c in summ["internal_checks"]))


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.cfg = common.load_config()

    def sys_row(self, c, h, m, l, role="sql"):
        return {"system_id": "T-%s-01" % role, "property": "PROP-F", "role_key": role, "role": role,
                "role_group": "x", "critical": c, "high": h, "medium": m, "low": l, "info": 0, "low_plus": c + h + m + l}

    def test_hand_calculated_score(self):
        # 1 Critical + 2 High + 3 Medium + 4 Low = 10 + 12 + 9 + 4 = 35; Tier 1 weight 5 -> R = 175
        s = score.score_systems([self.sys_row(1, 2, 3, 4)], self.cfg)[0]
        self.assertEqual(s["technical_score"], 35)
        self.assertEqual(s["tier"], 1)
        self.assertEqual(s["risk_score"], 175)

    def test_tier_weights_by_role(self):
        for role, tier, weight in (("pms", 1, 5), ("accounting", 2, 3), ("inroom", 3, 2), ("desktop", 4, 1)):
            s = score.score_systems([self.sys_row(0, 1, 0, 0, role)], self.cfg)[0]
            self.assertEqual((s["tier"], s["tier_weight"], s["risk_score"]), (tier, weight, 6 * weight))

    def test_monotonic_in_severity(self):
        a = score.score_systems([self.sys_row(0, 1, 1, 1)], self.cfg)[0]["risk_score"]
        b = score.score_systems([self.sys_row(1, 1, 1, 1)], self.cfg)[0]["risk_score"]
        self.assertGreater(b, a)

    def test_index_normalised_and_ranked(self):
        res = score.compute()
        reg = res["register"]
        self.assertEqual(reg[0]["system_index"], 100.0)
        self.assertEqual(reg[0]["system_id"], "PROP-C-SQL-01")
        self.assertTrue(all(0 <= s["system_index"] <= 100 for s in reg))
        self.assertEqual([s["risk_score"] for s in reg], sorted((s["risk_score"] for s in reg), reverse=True))
        self.assertEqual(max(p["property_risk_index"] for p in res["properties"]), 100.0)
        self.assertEqual(sum(1 for s in reg if s["risk_band"] == "None"), 1)

    def test_band_thresholds(self):
        b = self.cfg["risk_bands"]
        self.assertEqual([score.band_for(x, b) for x in (0, 1, 29, 30, 99, 100, 249, 250)],
                         ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical"])


class ImpactTests(unittest.TestCase):
    def test_worked_example_class_s_domain_controller(self):
        # Class S: 60 rooms, ADR 3,500, occupancy 65 percent, F and B uplift 45 percent, S2 dependence 20 percent, 48 h
        # rooms sold per day = 60 x 0.65 = 39; room revenue per day = 39 x 3,500 = 136,500; per hour = 5,687.50
        # with uplift = 5,687.50 x 1.45 = 8,246.875; cost = 8,246.875 x 0.20 x 48 = 79,170.00
        cost = impact.scenario_cost(60, 0.65, 3500, 0.45, 0.20, 48)
        self.assertAlmostEqual(cost, 79170.0, places=6)

    def test_model_matches_worked_example_for_a_class_s_property(self):
        res = impact.compute()
        row = [r for r in res["rows"] if r["property"] == "PROP-F" and r["scenario_id"] == "S2"][0]
        self.assertEqual(row["cost_base_inr"], 79170)
        self.assertEqual(row["basis"], "assumed")

    def test_cases_ordered_and_group_is_sum(self):
        res = impact.compute()
        for r in res["rows"]:
            self.assertLess(r["cost_low_inr"], r["cost_base_inr"])
            self.assertLess(r["cost_base_inr"], r["cost_high_inr"])
        for g in res["group"]:
            mine = [r for r in res["rows"] if r["scenario_id"] == g["scenario_id"]]
            self.assertEqual(g["cost_base_inr"], sum(r["cost_base_inr"] for r in mine))
        self.assertEqual({g["scenario_id"] for g in res["guest"]}, {"S1", "S2", "S3", "S4"})


class StandardsAndSensitivityTests(unittest.TestCase):
    def test_every_family_has_all_three_standards(self):
        m = map_standards.load_map()
        self.assertEqual(len(m["families"]), 12)
        for f in m["families"]:
            self.assertTrue(f["iso"].startswith("A."))
            self.assertTrue(f["pci"] and f["gdpr"].startswith("Art."))
            self.assertIn(f["pci_status"], ("verified", "to be verified"))

    def test_all_low_or_above_findings_have_a_family(self):
        res = map_standards.compute()
        missing = [r["plugin_name"] for r in res["findings"] if r["severity"] != "Info" and not r["family"]]
        self.assertEqual(missing, [])

    def test_sample_covers_all_twelve_families(self):
        res = map_standards.compute()
        empty = [f["family_key"] for f in res["families"] if f["systems_affected"] == 0]
        self.assertEqual(empty, [])

    def test_spearman(self):
        self.assertAlmostEqual(sensitivity.spearman([1, 2, 3, 4], [1, 2, 3, 4]), 1.0)
        self.assertAlmostEqual(sensitivity.spearman([1, 2, 3, 4], [4, 3, 2, 1]), -1.0)
        self.assertEqual(sensitivity.average_ranks([5, 5, 1]), [1.5, 1.5, 3.0])

    def test_uniform_scaling_cannot_change_ranking(self):
        res = sensitivity.run()
        for r in res["ranking"]:
            if "(control)" in r["case"]:
                self.assertEqual(r["spearman_rho"], 1.0)
        self.assertEqual(len(res["base_top"]), 5)


class ConfigAndPrivacyTests(unittest.TestCase):
    def test_yaml_and_json_configs_match(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        import json
        with open(os.path.join(common.CONFIG_DIR, "assumptions.yaml"), encoding="utf-8") as fh:
            y = common.normalise_config(yaml.safe_load(fh))
        with open(os.path.join(common.CONFIG_DIR, "assumptions.json"), encoding="utf-8") as fh:
            j = common.normalise_config(json.load(fh))
        self.assertEqual(y, j)

    TEXT_EXT = (".py", ".md", ".json", ".yaml", ".yml", ".csv", ".html", ".txt", ".cff", ".gitignore", ".gitattributes")
    DOC_NETS = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"))

    def repo_text_files(self):
        for dp, dns, fns in os.walk(ROOT):
            dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
            for fn in fns:
                if fn.endswith(self.TEXT_EXT) or fn == "LICENSE":
                    yield os.path.join(dp, fn)

    def test_no_raw_identifiers_in_published_files(self):
        ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        mac = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
        dom = re.compile(r"\b[a-z0-9-]+\.(?:local|lan|hosp|corp|internal|com|org|net|in|io|edu)\b", re.I)
        allowed_domains = {"github.com"}   # repository link in README and CITATION.cff
        bad = []
        for p in self.repo_text_files():
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            rel = os.path.relpath(p, ROOT).replace("\\", "/")
            for m in ipv4.finditer(text):
                try:
                    ip = ipaddress.ip_address(m.group(0))
                except ValueError:
                    continue
                if not any(ip in net for net in self.DOC_NETS):
                    bad.append((rel, m.group(0)))
            for m in mac.finditer(text):
                bad.append((rel, m.group(0)))
            for m in dom.finditer(text):
                if m.group(0).lower() not in allowed_domains:
                    bad.append((rel, m.group(0)))
        self.assertEqual(bad, [])

    def test_sample_exports_use_documentation_addresses_only(self):
        found = set()
        sample = os.path.join(ROOT, "sample_data", "nessus_html")
        for fn in os.listdir(sample):
            with open(os.path.join(sample, fn), encoding="utf-8") as fh:
                found.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", fh.read()))
        self.assertTrue(found)
        for a in found:
            ip = ipaddress.ip_address(a)
            self.assertTrue(any(ip in net for net in self.DOC_NETS), a)

    def test_sample_generator_is_deterministic_and_matches_committed_sample(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            n1 = make_sample_data.generate(d1)
            n2 = make_sample_data.generate(d2)
            self.assertEqual(n1, n2)
            self.assertTrue(all(filecmp.cmp(os.path.join(d1, n), os.path.join(d2, n), shallow=False) for n in n1))
            rows, _, _, _ = parse_nessus.build(d1)
        committed = common.read_csv(os.path.join(common.DATA_DIR, "systems_normalised.csv"))
        self.assertEqual([r["system_id"] for r in rows], [r["system_id"] for r in committed])
        self.assertEqual([str(r["low_plus"]) for r in rows], [r["low_plus"] for r in committed])


if __name__ == "__main__":
    unittest.main(verbosity=2)
