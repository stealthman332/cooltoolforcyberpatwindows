import re
from dataclasses import dataclass
from typing import List, Dict, Any

from collectors import run_powershell_json
from readme_parser import parse_readme, ReadmePolicy


@dataclass
class PrincipalRow:
    Name: str
    Identity: str
    PrincipalSource: str
    IsAdmin: bool
    Enabled: bool
    Authorized: bool
    Unexpected: bool


def _get_local_and_domain_inventory() -> Dict[str, Any]:
    """
    Collect local users and local Administrators, plus basic domain context.
    """
    script = r"""
$ErrorActionPreference = 'Stop'

$cs = Get-CimInstance Win32_ComputerSystem
$domainName = [string]$cs.Domain
$partOfDomain = [bool]$cs.PartOfDomain

$localUsers = @()
try {
    $localUsers = Get-LocalUser | ForEach-Object {
        [pscustomobject]@{
            Name      = $_.Name
            Enabled   = [bool]$_.Enabled
            Sid       = [string]$_.SID
            PrincipalSource = [string]$_.PrincipalSource
        }
    }
} catch {
    $localUsers = @()
}

$localAdmins = @()
try {
    $localAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name      = $_.Name
            ObjectClass = $_.ObjectClass
            PrincipalSource = [string]$_.PrincipalSource
            Sid       = [string]$_.SID
        }
    }
} catch {
    $localAdmins = @()
}

$domainUsers = @()
$domainAdminCandidates = @()
$isDC = $false

try {
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -eq 2 -or $os.ProductType -eq 3) {
        $isDC = $true
    }
} catch {
    $isDC = $false
}

# Best-effort domain group info; may fail on workgroup or limited environments
try {
    if ($partOfDomain) {
        try {
            $domainUsers = Get-ADUser -Filter * -ResultSetSize 50 | Select-Object -First 200 | ForEach-Object {
                [pscustomobject]@{
                    SamAccountName = $_.SamAccountName
                    Name           = $_.Name
                    Enabled        = $true
                }
            }
        } catch {
            $domainUsers = @()
        }

        try {
            $da = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Name           = $_.Name
                    SamAccountName = $_.SamAccountName
                }
            }
            $domainAdminCandidates = $da
        } catch {
            $domainAdminCandidates = @()
        }
    }
} catch {
    $domainUsers = @()
    $domainAdminCandidates = @()
}

[pscustomobject]@{
    PartOfDomain          = $partOfDomain
    DomainName            = $domainName
    IsDomainController    = $isDC
    LocalUsers            = @($localUsers)
    LocalAdministrators   = @($localAdmins)
    DomainUsers           = @($domainUsers)
    DomainAdminCandidates = @($domainAdminCandidates)
} | ConvertTo-Json -Depth 6 -Compress
"""
    data = run_powershell_json(script) or {}
    if not isinstance(data, dict):
        return {
            "PartOfDomain": False,
            "DomainName": "",
            "IsDomainController": False,
            "LocalUsers": [],
            "LocalAdministrators": [],
            "DomainUsers": [],
            "DomainAdminCandidates": [],
        }

    def _ensure_list(value):
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        return []

    data["LocalUsers"] = _ensure_list(data.get("LocalUsers"))
    data["LocalAdministrators"] = _ensure_list(data.get("LocalAdministrators"))
    data["DomainUsers"] = _ensure_list(data.get("DomainUsers"))
    data["DomainAdminCandidates"] = _ensure_list(data.get("DomainAdminCandidates"))
    return data


def _normalize_identity(name: str) -> str:
    """
    Normalize user identity for comparison (strip domain prefixes, case-insensitive).
    """
    if not name:
        return ""
    s = str(name).strip()
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s.lower()


def compare_users_against_authorized(readme_text: str) -> Dict[str, Any]:
    """
    Main entry point used by app.py:
      - parse README for AuthorizedUsers / AuthorizedAdministrators
      - collect local/domain inventory
      - return Results list shaped for the Users tab
    """
    policy: ReadmePolicy = parse_readme(readme_text)

    authorized_admins = [u.lower() for u in policy.AuthorizedAdministrators]
    authorized_users = [u.lower() for u in policy.AuthorizedUsers]

    inventory = _get_local_and_domain_inventory()

    local_users = inventory.get("LocalUsers", [])
    local_admins = inventory.get("LocalAdministrators", [])

    admin_identities = set()
    for admin in local_admins:
        name = admin.get("Name", "") or ""
        norm = _normalize_identity(name)
        if norm:
            admin_identities.add(norm)

    rows: List[PrincipalRow] = []

    for user in local_users:
        name = user.get("Name", "") or ""
        enabled = bool(user.get("Enabled", False))
        principal_source = user.get("PrincipalSource", "") or ""
        identity = _normalize_identity(name)

        is_admin = identity in admin_identities

        is_authorized_admin = identity in authorized_admins
        is_authorized_user = identity in authorized_users

        authorized = is_authorized_admin or is_authorized_user
        unexpected = enabled and not authorized

        rows.append(
            PrincipalRow(
                Name=name,
                Identity=identity,
                PrincipalSource=principal_source,
                IsAdmin=is_admin,
                Enabled=enabled,
                Authorized=authorized,
                Unexpected=unexpected,
            )
        )

    results = [
        {
            "Name": r.Name,
            "Identity": r.Identity,
            "PrincipalSource": r.PrincipalSource,
            "IsAdmin": r.IsAdmin,
            "Enabled": r.Enabled,
            "Authorized": r.Authorized,
            "Unexpected": r.Unexpected,
        }
        for r in sorted(rows, key=lambda x: (not x.Unexpected, not x.IsAdmin, x.Name.lower()))
    ]

    return {
        "Policy": {
            "AuthorizedUsers": policy.AuthorizedUsers,
            "AuthorizedAdministrators": policy.AuthorizedAdministrators,
            "CriticalServices": policy.CriticalServices,
            "RequiredSoftware": policy.RequiredSoftware,
            "MinimumPasswordLength": policy.MinimumPasswordLength,
        },
        "AuthorizedUsers": policy.AuthorizedUsers,
        "Inventory": inventory,
        "Results": results,
    }