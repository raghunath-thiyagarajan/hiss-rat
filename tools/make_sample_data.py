#!/usr/bin/env python3
"""Generate SYNTHETIC Nessus style HTML exports for the HISS-RAT demo and tests.

Nothing here comes from a real network. The hosts are invented, their addresses sit in the
documentation ranges 192.0.2.0/24 and 198.51.100.0/24 (RFC 5737) and the files carry neutral
property labels (PROP-A to PROP-F) and role keywords. The plugin names are generic scanner
check names. Which finding appears on which invented host is arbitrary.

The output is deterministic, so running the script twice gives identical files.

    python tools/make_sample_data.py                 writes sample_data/nessus_html/
    python tools/make_sample_data.py --out <folder>  writes somewhere else

Then:  python run_all.py --data-dir sample_data/nessus_html
"""
import argparse
import html
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

COLOURS = {"Critical": "#91243E", "High": "#DD4B50", "Medium": "#F18C43", "Low": "#F8C851", "Info": "#67ACE1"}
SEVS = ["Critical", "High", "Medium", "Low", "Info"]

# key: (plugin id, plugin name, severity, CVSS, CVE ids)
CATALOGUE = {
    "MSMQ": (175373, "Microsoft Message Queuing RCE (CVE-2023-21554, QueueJumper)", "Critical", "9.8", ["CVE-2023-21554"]),
    "SSL23": (20007, "SSL Version 2 and 3 Protocol Detection", "Critical", "9.8", []),
    "SQLUNS": (73756, "Microsoft SQL Server Unsupported Version Detection (remote check)", "Critical", "10.0", []),
    "OSSLZE": (160480, "OpenSSL 1.0.2 < 1.0.2ze Vulnerability", "Critical", "9.8", []),
    "APACHE49": (153584, "Apache < 2.4.49 Multiple Vulnerabilities", "Critical", "9.8", []),
    "SWEET32": (42873, "SSL Medium Strength Cipher Suites Supported (SWEET32)", "High", "7.5", ["CVE-2016-2183"]),
    "WEAKHASH": (35291, "SSL Certificate Signed Using Weak Hashing Algorithm", "High", "7.5", []),
    "RCAGENT": (900001, "Remote Control Agent Public Key Buffer Over-read", "High", "7.4", []),
    "OSSLZD": (158973, "OpenSSL 1.0.2 < 1.0.2zd Vulnerability", "High", "7.5", []),
    "APACHE58": (183391, "Apache 2.4.x < 2.4.58 Multiple Vulnerabilities", "High", "7.5", []),
    "SMBSIGN": (57608, "SMB Signing not required", "Medium", "5.3", []),
    "CERTUNTR": (51192, "SSL Certificate Cannot Be Trusted", "Medium", "6.5", []),
    "SELFSIGN": (57582, "SSL Self-Signed Certificate", "Medium", "6.5", []),
    "TLS10": (104743, "TLS Version 1.0 Protocol Detection", "Medium", "6.5", []),
    "TLS11": (157288, "TLS Version 1.1 Deprecated Protocol", "Medium", "6.5", []),
    "WRONGHOST": (45411, "SSL Certificate with Wrong Hostname", "Medium", "5.3", []),
    "NLA": (58453, "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", "Medium", "4.0", []),
    "ECHO": (10061, "Echo Service Detection", "Medium", "6.5", []),
    "QOTD": (10198, "Quote of the Day (QOTD) Service Detection", "Medium", "6.5", []),
    "TERRAPIN": (187315, "SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)", "Medium", "5.9", ["CVE-2023-48795"]),
    "ICMP": (10114, "ICMP Timestamp Request Remote Date Disclosure", "Low", "2.1", ["CVE-1999-0524"]),
    "POODLE": (78479, "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)", "Low", "3.4", []),
    "LOGJAM": (83875, "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)", "Low", "3.7", []),
}

INFO_POOL = [
    (19506, "Nessus Scan Information"), (11936, "OS Identification"), (22964, "Service Detection"),
    (10863, "SSL Certificate Information"), (21643, "SSL Cipher Suites Supported"),
    (56984, "SSL / TLS Versions Supported"), (25220, "TCP/IP Timestamps Supported"),
    (54615, "Device Type"), (10287, "Traceroute Information"), (45590, "Common Platform Enumeration (CPE)"),
]
# Info rows that the standards mapping recognises; they replace the last Info rows of a system
EXTRA_INFO = {
    "RDP": (10940, "Remote Desktop Protocol Service Detection"),
    "FTP": (10092, "FTP Server Detection"),
    "LLMNR": (900002, "Link-Local Multicast Name Resolution (LLMNR) Detection"),
}

# file role keyword, property, address, finding keys, number of Info rows, extra Info rows
SYSTEMS = [
    ("PMS", "PROP-A", "192.0.2.11", ["MSMQ", "SWEET32", "RCAGENT", "SMBSIGN", "CERTUNTR", "TLS10", "ICMP"], 5, []),
    ("AD", "PROP-A", "192.0.2.12", ["RCAGENT", "SMBSIGN", "NLA", "SELFSIGN", "ICMP"], 4, ["RDP"]),
    ("SQL", "PROP-A", "192.0.2.13", ["SQLUNS", "OSSLZE", "MSMQ", "SWEET32", "WEAKHASH", "OSSLZD", "SMBSIGN",
                                     "CERTUNTR", "TLS10", "TLS11", "ICMP", "LOGJAM"], 6, []),
    ("FRONTDESK2", "PROP-A", "192.0.2.21", ["SMBSIGN", "NLA", "ICMP"], 3, ["RDP"]),
    ("INTERFACE", "PROP-B", "192.0.2.31", ["APACHE49", "APACHE58", "TLS10", "SELFSIGN", "ICMP"], 4, []),
    ("ACCOUNTING", "PROP-B", "192.0.2.32", ["SWEET32", "SMBSIGN", "CERTUNTR"], 3, []),
    ("SQL", "PROP-C", "198.51.100.11", ["MSMQ", "SSL23", "SQLUNS", "OSSLZE", "SWEET32", "WEAKHASH", "RCAGENT",
                                        "OSSLZD", "APACHE58", "SMBSIGN", "CERTUNTR", "SELFSIGN", "TLS10", "TLS11",
                                        "WRONGHOST", "ICMP", "POODLE", "LOGJAM"], 8, []),
    ("SQLBACKUP", "PROP-C", "198.51.100.12", ["SQLUNS", "SWEET32", "OSSLZD", "SMBSIGN", "TLS11", "ICMP"], 5, []),
    ("AD", "PROP-C", "198.51.100.13", ["WEAKHASH", "RCAGENT", "SMBSIGN", "NLA", "CERTUNTR", "SELFSIGN", "ICMP"], 4, ["RDP"]),
    ("GUESTSVC", "PROP-C", "198.51.100.21", ["SMBSIGN", "TLS10", "TLS11", "ICMP"], 3, ["LLMNR"]),
    ("PMS", "PROP-D", "198.51.100.31", ["SSL23", "SWEET32", "SMBSIGN", "TLS10"], 4, []),
    ("INROOM", "PROP-D", "198.51.100.32", ["ECHO", "QOTD", "TERRAPIN", "ICMP", "POODLE"], 3, ["FTP"]),
    ("AD", "PROP-E", "198.51.100.41", ["RCAGENT", "SMBSIGN", "NLA"], 3, ["RDP"]),
    ("DESKTOP", "PROP-E", "198.51.100.42", [], 6, ["LLMNR", "RDP"]),
    ("BACKOFFICE", "PROP-F", "192.0.2.51", ["ICMP"], 2, []),
    ("ACCOUNTS", "PROP-F", "192.0.2.52", ["SMBSIGN"], 2, []),
]


def findings(keys, n_info, extra):
    """Return a list of (plugin id, name, severity, cvss, cves) rows, severe first."""
    rows = [CATALOGUE[k] for k in keys]
    info = [(pid, name, "Info", "", []) for pid, name in INFO_POOL[:n_info]]
    for j, key in enumerate(extra):
        info[-1 - j] = (EXTRA_INFO[key][0], EXTRA_INFO[key][1], "Info", "", [])
    rows.sort(key=lambda r: (SEVS.index(r[2]), r[1]))
    return rows + info


def summary_html(host, rows):
    """Summary style export: severity tiles plus one plugin row per finding."""
    counts = {s: sum(1 for r in rows if r[2] == s) for s in SEVS}
    tiles = "".join('<td><div style="font-size: 45px; font-weight: 300;">%d</div></td>' % counts[s] for s in SEVS)
    trs = ""
    for pid, name, sev, cvss, _cves in rows:
        trs += ('<tr class="plugin-row"><td></td><td><span style="display: inline-block; width: 60px; '
                'text-transform: uppercase; background: %s; font-size: 10px;">%s</span></td><td></td><td>%s</td>'
                '<td></td><td>-</td><td></td><td><a href="/plugins/nessus/%d"> %d</a></td><td>%s</td></tr>\n'
                % (COLOURS[sev], sev, cvss or "", pid, pid, html.escape(name, quote=False)))
    return ('<html><head><meta charset="utf-8"><title>Synthetic scan export</title></head><body>'
            '<h6>Vulnerabilities by Host</h6>\n<div xmlns="" id="id2" style="font-size: 22px;">%s'
            '<div class="clear"></div></div>\n<table><tr>%s</tr></table>\n<table>\n%s'
            '<tr class="plugin-row"><td>* synthetic sample, not a real scan</td></tr></table></body></html>\n'
            % (host, tiles, trs))


def detail_html(host, rows):
    """Detailed host export: one section per plugin and port, so a plugin id can repeat."""
    secs = ""
    n = 10
    for pid, name, sev, cvss, cves in rows:
        ports = ("tcp/443", "tcp/3389") if sev in ("Medium", "High") else ("tcp/445",)
        for port in ports:
            body = "<table><tr><td>Port</td><td>%s</td></tr>" % port
            for c in cves:
                body += '<tr><td>CVE</td><td><a href="/cve/%s">%s</a></td></tr>' % (c, c)
            if cvss and cvss != "N/A":
                body += ('<div>CVSS v3.0 Base Score<div class="clear"></div></div><div>%s</div>' % cvss)
            body += "</table>"
            secs += ('<div xmlns="" id="id%d" style="box-sizing: border-box; background: %s; font-weight: 700;" '
                     'class="" onclick="toggleSection(\'id%d-container\');">%d - %s<div id="id%d-toggletext"></div></div>\n'
                     '<div id="id%d-container">%s</div>\n'
                     % (n, COLOURS[sev], n, pid, html.escape(name, quote=False), n, n, body))
            n += 1
    return ('<html><head><meta charset="utf-8"><title>Synthetic scan export</title></head><body>'
            '<h6>Vulnerabilities by Host</h6>\n<div xmlns="" id="id2">%s<div class="clear"></div></div>\n%s'
            '</body></html>\n' % (host, secs))


def plugin_html(rows):
    """Grouped by plugin, no host totals (read by the parser but never preferred)."""
    secs = "".join("<h3>%d - %s</h3>\n" % (r[0], html.escape(r[1], quote=False)) for r in rows)
    return ('<html><head><meta charset="utf-8"><title>Synthetic scan export</title></head><body>'
            '<h6>Vulnerabilities by Plugin</h6>\n%s</body></html>\n' % secs)


def file_name(prop, role, suffix):
    return "%s_%s_%s.html" % (prop, role, suffix)


def build_files():
    """Return an ordered list of (file name, text) for the whole synthetic export set."""
    out = []
    by_key = {}
    for i, (role, prop, ip, keys, n_info, extra) in enumerate(SYSTEMS):
        rows = findings(keys, n_info, extra)
        suffix = "s%05d" % (i + 1)
        name = file_name(prop, role, suffix)
        text = summary_html(ip, rows)
        out.append((name, text))
        by_key[(prop, role)] = (ip, rows, text)
    # a byte identical second copy of one export
    out.append((file_name("PROP-A", "PMS", "dup001"), by_key[("PROP-A", "PMS")][2]))
    # a detailed export of the same host whose file name hides the role
    ip, rows, _ = by_key[("PROP-C", "SQLBACKUP")]
    out.append(("PROP-C_scan_d3t4il.html", detail_html(ip, rows)))
    # a plugin grouped export of an accounting system
    out.append((file_name("PROP-B", "ACCOUNTING", "plg001"), plugin_html(by_key[("PROP-B", "ACCOUNTING")][1])))
    return out


def generate(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    names = []
    for name, text in build_files():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        names.append(name)
    return names


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "sample_data", "nessus_html"))
    a = ap.parse_args(argv)
    names = generate(a.out)
    print("Wrote %d synthetic export files to %s" % (len(names), os.path.relpath(a.out, os.getcwd())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
