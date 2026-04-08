import os
import re
import socket

from collectors import run_powershell_json


AUTHORIZED_SECTION_HEADERS = (
    "authorized users",
    "approved users",
    "valid users",
    "allowed users",
    "authorized accounts",
    "approved accounts",
    "valid accounts",
    "allowed accounts",
    "authorized user accounts",
    "authorized usernames",
    "authorized administrators",
    "authorized admins",
    "approved administrators",
    "approved admins",
    "valid administrators",
    "allowed administrators",
)

AUTHORIZED_STOP_HEADERS = (
    "unauthorized",
    "password",
    "passwords",
    "service accounts",
    "service account",
    "critical services",
    "services",
    "questions",
    "question",
    "answers",
    "notes",
    "persistence",
    "scheduled task",
    "scheduled tasks",
    "registry",
    "installed programs",
    "applications",
    "apps",
    "findings",
    "results",
    "scoring",
    "score",
    "report",
    "readme",
    "competition info",
    "image download",
    "errata",
    "competition scenario",
)

NOISE_WORDS = {
    "authorized", "approved", "valid", "allowed", "users", "user",
    "accounts", "account", "members", "member", "include", "includes",
    "only", "the", "and", "or", "administrators", "administrator", "admins", "admin",
}


def normalize_identity(value: str) -> str:
    if value is None:
        return ""
    v = str(value).strip().lower().replace("/", "\\")
    v = re.sub(r"\s*\\\s*", r"\\", v)
    v = re.sub(r"\s+", " ", v)
    return v.strip(" ,;:")


def split_identity_parts(value: str):
    v = normalize_identity(value)
    if not v:
        return "", ""

    if "\\" in v:
        domain, name = v.split("\\", 1)
        return domain.strip(), name.strip()

    if "@" in v:
        name, domain = v.split("@", 1)
        return domain.strip(), name.strip()

    return "", v.strip()


def identity_matches(candidate: str, authorized_set: set) -> bool:
    cand = normalize_identity(candidate)
    if not cand:
        return False

    if cand in authorized_set:
        return True

    _, cand_name = split_identity_parts(cand)
    if not cand_name:
        return False

    for auth in authorized_set:
        if cand == normalize_identity(auth):
            return True
        _, auth_name = split_identity_parts(auth)
        if cand_name == auth_name and cand_name:
            return True

    return False


def _clean_user_line(line: str) -> str:
    s = (line or "").strip()
    s = re.sub(r"^\s*(?:[-*•]+|\d+[.)]|[a-z][.)])\s*", "", s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip(" -:\t")
    return s


def _looks_like_authorized_header(line: str) -> bool:
    s = normalize_identity(line).strip(":")
    if not s:
        return False
    return any(h in s for h in AUTHORIZED_SECTION_HEADERS)


def _looks_like_stop_header(line: str) -> bool:
    s = normalize_identity(line).strip(":")
    if not s:
        return False
    return any(stop in s for stop in AUTHORIZED_STOP_HEADERS)


def _line_looks_like_header(line: str) -> bool:
    s = normalize_identity(line).strip(":")
    if not s:
        return False
    if _looks_like_authorized_header(s) or _looks_like_stop_header(s):
        return True
    if len(s) < 80 and re.match(r"^[a-z0-9 _/\-\\():]+:?$", s, re.I):
        words = [w for w in re.split(r"[\s_/\\\-():]+", s) if w]
        if 1 <= len(words) <= 6:
            return True
    return False


def _extract_user_password_prefix(line: str):
    cleaned = _clean_user_line(line)
    if not cleaned:
        return None

    m = re.match(r"^([a-z0-9._$-]+(?:\\[a-z0-9._$-]+)?|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\s*:", cleaned, re.I)
    if m:
        return m.group(1).strip()
    return None


def _extract_identities_from_line(line: str):
    found = []

    up = _extract_user_password_prefix(line)
    if up:
        found.append(up)

    for m in re.findall(r"\b[a-z0-9._-]+\\[a-z0-9._$-]+\b", line, re.I):
        found.append(m)

    for m in re.findall(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", line, re.I):
        found.append(m)

    cleaned = _clean_user_line(line)
    if not cleaned:
        return found

    cleaned = re.sub(r"\([^)]*\)", "", cleaned).strip()
    parts = [p.strip() for p in re.split(r"[,\t;/]|(?:\s{2,})", cleaned) if p.strip()]
    if len(parts) <= 1:
        parts = [cleaned]

    for part in parts:
        p = part.strip("()[]{}<>\"'`")
        p = re.sub(r"\b(?:authorized|approved|valid|allowed)\b", "", p, flags=re.I)
        p = re.sub(r"\b(?:administrators?|admins?|users?|accounts?)\b", "", p, flags=re.I)
        p = re.sub(r"\s+", " ", p).strip(" ,;:-")

        if ":" in p:
            p = p.split(":", 1)[0].strip()

        if not p:
            continue
        if len(p) > 64:
            continue
        if re.search(r"\b(question|password|registry|task|tasks|report|score|scoring|result|mailenable|iis|http|smtp)\b", p, re.I):
            continue

        if re.fullmatch(r"[a-z0-9._$-]+", p, re.I):
            if p.lower() not in NOISE_WORDS:
                found.append(p)
        elif re.fullmatch(r"[a-z0-9._-]+\\[a-z0-9._$-]+", p, re.I):
            found.append(p)
        elif re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", p, re.I):
            found.append(p)

    return found


def extract_authorized_users_from_text(text: str) -> list[str]:
    if not text:
        return []

    lines = text.replace("\r", "").split("\n")
    results = []
    seen = set()

    in_authorized_block = False
    found_any_identity_in_block = False
    blank_run_after_data = 0

    for raw in lines:
        line = raw.strip()
        low = line.lower()

        is_authorized_header = (
            "authorized" in low and
            ("user" in low or "admin" in low or "account" in low)
        )

        if is_authorized_header:
            in_authorized_block = True
            found_any_identity_in_block = False
            blank_run_after_data = 0
            continue

        if not in_authorized_block:
            continue

        # Ignore leading blank lines immediately after header
        if not line and not found_any_identity_in_block:
            continue

        # Once we've started getting names, allow a small amount of blank spacing,
        # but stop if the block clearly ends.
        if not line and found_any_identity_in_block:
            blank_run_after_data += 1
            if blank_run_after_data >= 3:
                in_authorized_block = False
            continue

        blank_run_after_data = 0

        if _looks_like_stop_header(line):
            in_authorized_block = False
            continue

        identities = _extract_identities_from_line(line)
        if identities:
            found_any_identity_in_block = True
            for ident in identities:
                n = normalize_identity(ident)
                if n and n not in seen:
                    seen.add(n)
                    results.append(ident.strip())
            continue

        # If we already started collecting names and now hit another likely section
        # header, stop this block.
        if found_any_identity_in_block and _line_looks_like_header(line):
            in_authorized_block = False

    return results


def get_current_user_inventory() -> dict:
    script = r"""
$ErrorActionPreference = 'Stop'

$cs = Get-CimInstance Win32_ComputerSystem

$localUsers = @()
try {
    $localUsers = Get-LocalUser | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            FullName = $_.FullName
            Enabled = [bool]$_.Enabled
            PrincipalSource = [string]$_.PrincipalSource
            Scope = 'Local'
        }
    }
} catch {
    $localUsers = @()
}

$admins = @()
try {
    $admins = Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            ObjectClass = [string]$_.ObjectClass
            PrincipalSource = [string]$_.PrincipalSource
        }
    }
} catch {
    $admins = @()
}

[pscustomobject]@{
    ComputerName = $cs.Name
    PartOfDomain = [bool]$cs.PartOfDomain
    LocalUsers = @($localUsers)
    Administrators = @($admins)
} | ConvertTo-Json -Depth 6 -Compress
"""
    data = run_powershell_json(script) or {}
    if not isinstance(data, dict):
        data = {}

    data["LocalUsers"] = data.get("LocalUsers") or []
    data["Administrators"] = data.get("Administrators") or []
    return data


def compare_users_against_authorized(readme_text: str) -> dict:
    authorized = extract_authorized_users_from_text(readme_text)
    authorized_set = {normalize_identity(x) for x in authorized if normalize_identity(x)}

    inventory = get_current_user_inventory()
    computer_name = (
        inventory.get("ComputerName")
        or os.environ.get("COMPUTERNAME")
        or socket.gethostname()
        or ""
    )

    admin_identities = set()
    for admin in inventory.get("Administrators", []):
        admin_name = (admin.get("Name") or "").strip()
        norm = normalize_identity(admin_name)
        if norm:
            admin_identities.add(norm)
            _, short_name = split_identity_parts(norm)
            if short_name:
                admin_identities.add(short_name)

    results = []
    represented = set()

    for user in inventory.get("LocalUsers", []):
        name = (user.get("Name") or "").strip()
        if not name:
            continue

        identity = f"{computer_name}\\{name}" if computer_name else name
        is_admin = identity_matches(identity, admin_identities) or identity_matches(name, admin_identities)
        is_authorized = identity_matches(identity, authorized_set) or identity_matches(name, authorized_set)

        row = {
            "Name": name,
            "Identity": identity,
            "Enabled": bool(user.get("Enabled", False)),
            "PrincipalSource": user.get("PrincipalSource") or user.get("Scope") or "Local",
            "IsAdmin": bool(is_admin),
            "Authorized": bool(is_authorized),
            "Unexpected": not bool(is_authorized),
        }
        results.append(row)
        represented.add(normalize_identity(identity))
        represented.add(normalize_identity(name))

    for admin in inventory.get("Administrators", []):
        admin_name = (admin.get("Name") or "").strip()
        if not admin_name:
            continue

        if normalize_identity(admin_name) in represented:
            continue

        _, short_name = split_identity_parts(admin_name)
        if short_name and normalize_identity(short_name) in represented:
            continue

        is_authorized = identity_matches(admin_name, authorized_set) or (short_name and identity_matches(short_name, authorized_set))

        row = {
            "Name": short_name or admin_name,
            "Identity": admin_name,
            "Enabled": True,
            "PrincipalSource": admin.get("PrincipalSource") or admin.get("ObjectClass") or "",
            "IsAdmin": True,
            "Authorized": bool(is_authorized),
            "Unexpected": not bool(is_authorized),
        }
        results.append(row)
        represented.add(normalize_identity(admin_name))
        if short_name:
            represented.add(normalize_identity(short_name))

    results.sort(key=lambda x: (
        not x.get("Unexpected", False),
        not x.get("IsAdmin", False),
        (x.get("Name") or "").lower(),
    ))

    return {
        "AuthorizedUsers": authorized,
        "Inventory": inventory,
        "Results": results,
    }