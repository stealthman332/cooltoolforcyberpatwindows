import os
import re
import socket

from collectors import run_powershell_json


NOISE_WORDS = {
    "authorized", "approved", "valid", "allowed", "users", "user",
    "accounts", "account", "members", "member", "include", "includes",
    "only", "the", "and", "or", "administrators", "administrator", "admins", "admin",
    "environment", "environment.", "date", "team", "points", "image", "computer",
    "policy", "policies", "company", "services", "service", "critical", "password",
    "passwords", "guidelines", "report", "readme", "desktop", "questions",
    "scenario", "competition", "windows", "server", "domain", "machine",
}

STOP_SECTION_PATTERNS = (
    "competition guidelines",
    "critical services",
    "copyright",
    "forensics questions",
    "unique identifier",
    "image download",
    "errata",
)

ROLE_HEADERS = {
    "authorized administrators": "admin",
    "authorized users": "user",
    "authorized administrators and users": "mixed",
    "agents": "agent",
    "clerks": "clerk",
    "their replacements are": "replacement",
}

DELETE_SECTION_MARKERS = (
    "please delete the following",
    "delete the following",
    "remove the following",
    "retired clerks",
    "retired users",
)

REPLACEMENT_SECTION_MARKERS = (
    "their replacements are",
    "replacements are",
    "create accounts for every new clerk",
)

LIKELY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+$", re.I)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", re.I)


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
        auth_norm = normalize_identity(auth)
        if cand == auth_norm:
            return True
        _, auth_name = split_identity_parts(auth_norm)
        if cand_name == auth_name and cand_name:
            return True

    return False


def _clean_user_line(line: str) -> str:
    s = (line or "").strip()
    s = re.sub(r"^\s*(?:[-*•]+|\d+[.)]|[a-z][.)])\s*", "", s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip(" -:\t")
    return s


def _normalize_heading(line: str) -> str:
    return normalize_identity(line).strip(":").strip()


def _looks_like_stop_header(line: str) -> bool:
    s = _normalize_heading(line)
    if not s:
        return False
    return any(marker in s for marker in STOP_SECTION_PATTERNS)


def _is_delete_marker(line: str) -> bool:
    s = _normalize_heading(line)
    return any(marker in s for marker in DELETE_SECTION_MARKERS)


def _is_replacement_marker(line: str) -> bool:
    s = _normalize_heading(line)
    return any(marker in s for marker in REPLACEMENT_SECTION_MARKERS)


def _role_for_heading(line: str):
    s = _normalize_heading(line)
    for heading, role in ROLE_HEADERS.items():
        if heading in s:
            return role
    return None


def _line_looks_like_header(line: str) -> bool:
    s = _normalize_heading(line)
    if not s:
        return False
    if _looks_like_stop_header(s):
        return True
    if _role_for_heading(s):
        return True
    if _is_delete_marker(s) or _is_replacement_marker(s):
        return True
    if len(s) < 90 and re.match(r"^[a-z0-9 _/\-\\():]+:?$", s, re.I):
        words = [w for w in re.split(r"[\s_/\\\-():]+", s) if w]
        if 1 <= len(words) <= 8:
            return True
    return False


def _is_narrative_line(line: str) -> bool:
    s = _clean_user_line(line)
    if not s:
        return False
    if len(s.split()) >= 5:
        return True
    if any(token in s.lower() for token in ("policy", "company", "computer", "environment", "please", "should", "required", "access", "machine")):
        return True
    return False


def _extract_user_password_prefix(line: str):
    cleaned = _clean_user_line(line)
    if not cleaned:
        return None

    m = re.match(r"^([A-Za-z0-9._$-]+(?:\\[A-Za-z0-9._$-]+)?|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*:", cleaned, re.I)
    if m:
        return m.group(1).strip()
    return None


def _extract_identities_from_line(line: str, role_hint: str | None = None):
    found = []

    up = _extract_user_password_prefix(line)
    if up:
        found.append(up)

    for m in re.findall(r"\b[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+\b", line, re.I):
        found.append(m)

    for m in re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", line, re.I):
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
        if ":" in p:
            p = p.split(":", 1)[0].strip()

        p = re.sub(r"\b(?:authorized|approved|valid|allowed)\b", "", p, flags=re.I)
        p = re.sub(r"\b(?:administrators?|admins?|users?|accounts?)\b", "", p, flags=re.I)
        p = re.sub(r"\s+", " ", p).strip(" ,;:-")

        if not p:
            continue
        if len(p) > 64:
            continue
        if p.lower() in NOISE_WORDS:
            continue

        if " " in p:
            if role_hint in {"agent", "clerk", "admin", "replacement"}:
                continue
            if _is_narrative_line(p):
                continue

        if IDENTITY_RE.fullmatch(p) or EMAIL_RE.fullmatch(p):
            found.append(p)
            continue

        if LIKELY_NAME_RE.fullmatch(p):
            found.append(p)

    deduped = []
    seen = set()
    for item in found:
        n = normalize_identity(item)
        if n and n not in seen and n not in NOISE_WORDS:
            seen.add(n)
            deduped.append(item)
    return deduped


def extract_authorized_users_from_text(text: str) -> list[str]:
    print("extract_authorized_users_from_text called")
    print("Aeacus marker present:", "authorized administrators and users" in text.lower())
    if not text:
        return []

    lines = text.replace("\r", "").split("\n")
    lower_text = text.lower()

    # ------------------------------------------------------------
    # Special handling for Aeacus-style README:
    # Authorized Administrators and Users
    #   Authorized Administrators:
    #   Agents
    #   Clerks
    # ... ending at Competition Guidelines
    # ------------------------------------------------------------
    if "authorized administrators and users" in lower_text:
        start = lower_text.find("authorized administrators and users")
        end = lower_text.find("competition guidelines", start)
        if end == -1:
            end = len(text)

        section = text[start:end]
        section_lines = section.replace("\r", "").split("\n")

        results = []
        seen = set()
        current_role = None

        for raw in section_lines:
            line = raw.strip()
            low = line.lower()

            if not line:
                continue

            if "authorized administrators:" in low:
                current_role = "admin"
                continue

            if low == "agents" or low.startswith("agents "):
                current_role = "agent"
                continue

            if low == "clerks" or low.startswith("clerks "):
                current_role = "clerk"
                continue

            if "competition guidelines" in low:
                break

            if current_role not in {"admin", "agent", "clerk"}:
                continue

            # Handle password lines under admin section
            if current_role == "admin" and low.startswith("password:"):
                continue

            candidate = line
            if ":" in candidate:
                candidate = candidate.split(":", 1)[0].strip()

            candidate = re.sub(r"\([^)]*\)", "", candidate).strip()
            candidate = candidate.strip("•-* \t\"'")

            if not candidate:
                continue
            if " " in candidate:
                continue
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", candidate):
                continue

            n = normalize_identity(candidate)
            if n and n not in seen and n not in NOISE_WORDS:
                seen.add(n)
                results.append(candidate)
        print("Aeacus parsed users:", results)
        return results

    # ------------------------------------------------------------
    # Generic fallback logic for other images
    # ------------------------------------------------------------
    authorized = []
    unauthorized = set()
    seen_auth = set()

    current_role = None
    in_delete_block = False
    in_authorized_region = False
    blank_run = 0

    for raw in lines:
        line = raw.strip()
        low = _normalize_heading(line)

        if not line:
            blank_run += 1
            if blank_run >= 2:
                current_role = None
                in_delete_block = False
            continue

        blank_run = 0

        if _looks_like_stop_header(low):
            break

        role = _role_for_heading(low)
        if role:
            current_role = role
            in_authorized_region = True
            in_delete_block = False
            continue

        if _is_delete_marker(low):
            current_role = "delete"
            in_delete_block = True
            continue

        if _is_replacement_marker(low):
            current_role = "replacement"
            in_authorized_region = True
            in_delete_block = False
            continue

        if not in_authorized_region and "authorized" not in low:
            continue

        if _line_looks_like_header(low) and not role and not _is_delete_marker(low) and not _is_replacement_marker(low):
            current_role = None
            in_delete_block = False
            continue

        identities = _extract_identities_from_line(line, current_role)

        if current_role == "delete" or in_delete_block:
            for ident in identities:
                unauthorized.add(normalize_identity(ident))
            continue

        for ident in identities:
            n = normalize_identity(ident)
            if not n or n in unauthorized:
                continue
            if n not in seen_auth:
                seen_auth.add(n)
                authorized.append(ident.strip())

    authorized = [u for u in authorized if normalize_identity(u) not in unauthorized]
    return authorized


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

$domainUsers = @()
$domainGroups = @()
$domainName = [string]$cs.Domain
$isDomainController = $false

try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop

        try {
            $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
            if ($dc) { $isDomainController = $true }
        } catch {
            $isDomainController = $false
        }

        if ($cs.PartOfDomain) {
            $domainUsers = Get-ADUser -Filter * -Properties DisplayName,Enabled,SamAccountName |
                ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.SamAccountName
                        FullName = $_.DisplayName
                        Enabled = [bool]$_.Enabled
                        PrincipalSource = 'Domain'
                        Scope = 'Domain'
                    }
                }
        }

        $adminGroupNames = @(
            'Administrators',
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'DNSAdmins'
        )

        foreach ($groupName in $adminGroupNames) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop
                foreach ($m in $members) {
                    if ($m.objectClass -eq 'user') {
                        $domainGroups += [pscustomobject]@{
                            GroupName = $groupName
                            Name = $m.SamAccountName
                            Identity = "$domainName\$($m.SamAccountName)"
                            PrincipalSource = 'Domain'
                            ObjectClass = 'User'
                        }
                    }
                }
            } catch {
            }
        }
    }
} catch {
    $domainUsers = @()
    $domainGroups = @()
}

[pscustomobject]@{
    ComputerName = $cs.Name
    DomainName = $domainName
    PartOfDomain = [bool]$cs.PartOfDomain
    IsDomainController = [bool]$isDomainController
    LocalUsers = @($localUsers)
    DomainUsers = @($domainUsers)
    Administrators = @($admins)
    DomainAdminCandidates = @($domainGroups)
} | ConvertTo-Json -Depth 6 -Compress
"""
    data = run_powershell_json(script) or {}
    if not isinstance(data, dict):
        data = {}

    data["LocalUsers"] = data.get("LocalUsers") or []
    data["DomainUsers"] = data.get("DomainUsers") or []
    data["Administrators"] = data.get("Administrators") or []
    data["DomainAdminCandidates"] = data.get("DomainAdminCandidates") or []
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
    domain_name = inventory.get("DomainName") or ""

    admin_identities = set()

    for admin in inventory.get("Administrators", []):
        admin_name = (admin.get("Name") or "").strip()
        norm = normalize_identity(admin_name)
        if norm:
            admin_identities.add(norm)
            _, short_name = split_identity_parts(norm)
            if short_name:
                admin_identities.add(short_name)

    for admin in inventory.get("DomainAdminCandidates", []):
        identity = (admin.get("Identity") or "").strip()
        name = (admin.get("Name") or "").strip()
        if identity:
            admin_identities.add(normalize_identity(identity))
        if name:
            admin_identities.add(normalize_identity(name))

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

    for user in inventory.get("DomainUsers", []):
        name = (user.get("Name") or "").strip()
        if not name:
            continue

        identity = f"{domain_name}\\{name}" if domain_name else name
        is_admin = identity_matches(identity, admin_identities) or identity_matches(name, admin_identities)
        is_authorized = identity_matches(identity, authorized_set) or identity_matches(name, authorized_set)

        row = {
            "Name": name,
            "Identity": identity,
            "Enabled": bool(user.get("Enabled", False)),
            "PrincipalSource": user.get("PrincipalSource") or user.get("Scope") or "Domain",
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

    for admin in inventory.get("DomainAdminCandidates", []):
        admin_name = (admin.get("Name") or "").strip()
        admin_identity = (admin.get("Identity") or "").strip()
        key_identity = normalize_identity(admin_identity or admin_name)
        if not admin_name or key_identity in represented:
            continue

        is_authorized = identity_matches(admin_identity or admin_name, authorized_set) or identity_matches(admin_name, authorized_set)

        row = {
            "Name": admin_name,
            "Identity": admin_identity or admin_name,
            "Enabled": True,
            "PrincipalSource": admin.get("PrincipalSource") or "Domain",
            "IsAdmin": True,
            "Authorized": bool(is_authorized),
            "Unexpected": not bool(is_authorized),
        }
        results.append(row)
        represented.add(key_identity)
        represented.add(normalize_identity(admin_name))

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