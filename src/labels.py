"""Property and role labelling from file and folder names.

Files are named after a property label and a role, for example PROP-A_PMS_k3x9p2.html. Only generic
keywords are stored here. No host names, addresses, user names or other identifiers are kept in the
toolkit. The result of every rule is a property code and a role key.

To use the toolkit on your own exports, name each file (or its folder) with a property label
(PROP-A to PROP-F) and a role keyword from ROLE_RULES, or edit the two rule lists below.
"""
import os
import re

# Property keyword rules, first match wins. Applied to the lower case file stem or folder path.
PROPERTY_RULES = [
    ("PROP-A", r"prop[ _-]?a(?![a-z0-9])"),
    ("PROP-B", r"prop[ _-]?b(?![a-z0-9])"),
    ("PROP-C", r"prop[ _-]?c(?![a-z0-9])"),
    ("PROP-D", r"prop[ _-]?d(?![a-z0-9])"),
    ("PROP-E", r"prop[ _-]?e(?![a-z0-9])"),
    ("PROP-F", r"prop[ _-]?f(?![a-z0-9])"),
]

# Role definitions: key -> code used in system ids, display label, role group.
ROLES = {
    "ad": {"code": "AD", "label": "AD (domain controller)", "group": "AD"},
    "pms": {"code": "PMS", "label": "PMS (property management system)", "group": "PMS"},
    "sql": {"code": "SQL", "label": "SQL server", "group": "SQL and SQL backup"},
    "sqlbackup": {"code": "SQLBK", "label": "SQL backup server", "group": "SQL and SQL backup"},
    "interface": {"code": "IFS", "label": "Interface server", "group": "Interface server"},
    "accounting": {"code": "ACCT", "label": "Accounting package", "group": "Accounting package"},
    "finance": {"code": "FIN", "label": "Finance and accounts manager", "group": "Finance and accounts"},
    "accounts": {"code": "ACC", "label": "Accounts", "group": "Finance and accounts"},
    "frontdesk": {"code": "FD", "label": "Front desk", "group": "Front desk and front office"},
    "frontoffice": {"code": "FO", "label": "Front office", "group": "Front desk and front office"},
    "fnb_controls": {"code": "FBC", "label": "F and B controls", "group": "Other desktops and managers"},
    "fnb_manager": {"code": "FBM", "label": "F and B manager", "group": "Other desktops and managers"},
    "guestsvc": {"code": "GSS", "label": "Guest services system", "group": "Guest services system"},
    "inroom": {"code": "IRS", "label": "In room entertainment server", "group": "In room entertainment"},
    "inroom_gw": {"code": "IRG", "label": "In room entertainment gateway", "group": "In room entertainment"},
    "hr": {"code": "HR", "label": "HR manager", "group": "Other desktops and managers"},
    "itsystem": {"code": "ITS", "label": "IT system", "group": "Other desktops and managers"},
    "backoffice": {"code": "BO", "label": "Back office", "group": "Other desktops and managers"},
    "desktop": {"code": "DSK", "label": "Desktop", "group": "Other desktops and managers"},
    "admin": {"code": "ADM", "label": "Admin desktop", "group": "Other desktops and managers"},
}
ROLE_ORDER = {k: i for i, k in enumerate(ROLES)}

# Ordered role rules on the normalised file name (letters and digits only, lower case).
ROLE_RULES = [
    ("sqlbackup", r"sqlbackup"),
    ("sql", r"sql"),
    ("pms", r"pms"),
    ("inroom_gw", r"inroomgw"),
    ("inroom", r"inroom"),
    ("interface", r"interface"),
    ("itsystem", r"itsystem"),
    ("fnb_controls", r"fnbcontrols"),
    ("fnb_manager", r"fnbmgr|fnbmanager"),
    ("hr", r"hrmanager"),
    ("finance", r"finance"),
    ("accounts", r"accounts"),
    ("backoffice", r"backoffice"),
    ("frontoffice", r"frontoffice"),
    ("frontdesk", r"frontdesk"),
    ("guestsvc", r"guestsvc"),
    ("accounting", r"accounting"),
    ("admin", r"admin"),
]


def _stem(relpath):
    base = os.path.basename(relpath)
    base = re.sub(r"\.html?$", "", base, flags=re.I)
    base = re.sub(r"_[a-z0-9]{6}$", "", base, flags=re.I)   # random export suffix
    return base


def resolve_property(relpath):
    """Return (property_code, basis). The file name wins over the folder name."""
    low = relpath.lower().replace("\\", "/")
    stem = _stem(relpath).lower()
    for code, rx in PROPERTY_RULES:
        if re.search(rx, stem):
            return code, "file name"
    folders = low.rsplit("/", 1)[0] if "/" in low else ""
    for code, rx in PROPERTY_RULES:
        if folders and re.search(rx, folders):
            return code, "folder name"
    return None, "unresolved"


def resolve_role(relpath):
    """Return (role_key, unit_number_or_None) or None when the name does not reveal the role."""
    stem = _stem(relpath).lower()
    # drop the property label so that its letter cannot be mistaken for part of a role keyword
    stem = re.sub(r"prop[ _-]?[a-f](?![a-z0-9])", " ", stem)
    flat = re.sub(r"[^a-z0-9]", "", stem)
    for key, rx in ROLE_RULES:
        if re.search(rx, flat):
            unit = None
            if key == "frontdesk":
                m = re.search(r"frontdesk(\d)", flat)
                unit = int(m.group(1)) if m else 1
            return (key, unit)
    if re.search(r"(^|[ _-])ad($|[ _-])", stem):
        return ("ad", None)
    if re.search(r"desktop", flat):
        return ("desktop", None)
    return None
