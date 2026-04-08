import re
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox

import xml.etree.ElementTree as ET

import traceback
from ttkbootstrap.widgets.scrolled import ScrolledText

import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from collectors import get_installed_programs, get_registry_entries, get_tasks, run_powershell_json
from reports import (
    fetch_url_text,
    find_report_candidates_in_directory,
    html_to_text,
    looks_like_report_candidate,
    resolve_lnk_shortcut,
    resolve_url_shortcut,
)
from users_audit import compare_users_against_authorized

APP_TITLE = "Windows Forensics Workbench"
APP_THEME = "superhero"

DEFAULT_GPO_NAMES = {
    "default domain policy",
    "default domain controllers policy",
}

GPO_NAME_KEYWORDS_BASELINE = (
    "baseline",
    "hardening",
    "security",
    "cis",
    "microsoft baseline",
)


@dataclass
class ActionRecipe:
    id: str
    title: str
    description: str
    scope: str
    severity: str
    safe_default: bool
    powershell: str


ACTION_RECIPES = {
    "task_disable": ActionRecipe(
        id="task_disable",
        title="Disable suspicious scheduled task",
        description="Disable the scheduled task so it no longer runs automatically.",
        scope="Task",
        severity="High",
        safe_default=False,
        powershell=r"Disable-ScheduledTask -TaskPath '{task_path}' -TaskName '{task_name}' -ErrorAction Stop",
    ),
    "registry_remove_value": ActionRecipe(
        id="registry_remove_value",
        title="Remove suspicious autorun registry value",
        description="Delete the suspicious persistence value from the registry.",
        scope="Registry",
        severity="High",
        safe_default=False,
        powershell=r"Remove-ItemProperty -Path '{registry_path}' -Name '{value_name}' -ErrorAction Stop",
    ),
    "user_disable": ActionRecipe(
        id="user_disable",
        title="Disable unexpected local user",
        description="Disable the unexpected local account without deleting it.",
        scope="User",
        severity="High",
        safe_default=False,
        powershell=r"Disable-LocalUser -Name '{user_name}' -ErrorAction Stop",
    ),
    "user_remove_admin": ActionRecipe(
        id="user_remove_admin",
        title="Remove unexpected user from Administrators",
        description="Remove the account from the local Administrators group.",
        scope="User",
        severity="High",
        safe_default=False,
        powershell=r"Remove-LocalGroupMember -Group 'Administrators' -Member '{identity}' -ErrorAction Stop",
    ),
    "enable_firewall": ActionRecipe(
        id="enable_firewall",
        title="Re-enable Windows Defender Firewall",
        description="Turn on the firewall for Domain, Private, and Public profiles.",
        scope="Computer",
        severity="High",
        safe_default=True,
        powershell=r"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop",
    ),
    "enable_defender_realtime": ActionRecipe(
        id="enable_defender_realtime",
        title="Enable Defender real-time protection",
        description="Re-enable Microsoft Defender real-time monitoring.",
        scope="Computer",
        severity="High",
        safe_default=True,
        powershell=r"Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop",
    ),
    "enable_uac_admin_approval": ActionRecipe(
        id="enable_uac_admin_approval",
        title="Enable UAC Admin Approval Mode",
        description="Restore Admin Approval Mode for administrators.",
        scope="Computer",
        severity="High",
        safe_default=True,
        powershell=r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord -ErrorAction Stop",
    ),
    "set_rdp_nla": ActionRecipe(
        id="set_rdp_nla",
        title="Require NLA for RDP",
        description="Keep RDP available but require Network Level Authentication.",
        scope="Computer",
        severity="Medium",
        safe_default=True,
        powershell=r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord -ErrorAction Stop",
    ),
    "disable_rdp": ActionRecipe(
        id="disable_rdp",
        title="Disable Remote Desktop",
        description="Disable incoming Remote Desktop connections on this system.",
        scope="Computer",
        severity="Medium",
        safe_default=False,
        powershell=r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord -ErrorAction Stop",
    ),
    "set_execpolicy_remotesigned": ActionRecipe(
        id="set_execpolicy_remotesigned",
        title="Harden PowerShell script execution",
        description="Set the local PowerShell execution policy to RemoteSigned.",
        scope="Computer",
        severity="Medium",
        safe_default=False,
        powershell=r"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop",
    ),
    "require_smb_client_signing": ActionRecipe(
        id="require_smb_client_signing",
        title="Require SMB client signing",
        description="Require SMB signing for the SMB client.",
        scope="Computer",
        severity="Medium",
        safe_default=True,
        powershell=r"Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop",
    ),
    "require_smb_server_signing": ActionRecipe(
        id="require_smb_server_signing",
        title="Require SMB server signing",
        description="Require SMB signing for the SMB server.",
        scope="Computer",
        severity="Medium",
        safe_default=True,
        powershell=r"Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop",
    ),
    "disable_anonymous_everyone": ActionRecipe(
        id="disable_anonymous_everyone",
        title="Disallow Everyone permissions for anonymous users",
        description="Restore the setting so Everyone permissions do not apply to anonymous users.",
        scope="Computer",
        severity="High",
        safe_default=True,
        powershell=r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord -ErrorAction Stop",
    ),
    "disable_anonymous_enumeration": ActionRecipe(
        id="disable_anonymous_enumeration",
        title="Block anonymous SAM/share enumeration",
        description="Prevent anonymous enumeration of SAM accounts and shares.",
        scope="Computer",
        severity="High",
        safe_default=True,
        powershell=r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord -ErrorAction Stop",
    ),
    "set_min_password_length_12": ActionRecipe(
        id="set_min_password_length_12",
        title="Set minimum password length to 12",
        description="Increase minimum password length to 12 characters.",
        scope="Computer",
        severity="High",
        safe_default=False,
        powershell=r"net accounts /minpwlen:12",
    ),
    "enable_password_complexity": ActionRecipe(
        id="enable_password_complexity",
        title="Enable password complexity",
        description="Enable password complexity requirements.",
        scope="Computer",
        severity="High",
        safe_default=False,
        powershell=r"secedit /export /cfg $env:TEMP\secpol.cfg | Out-Null; (Get-Content $env:TEMP\secpol.cfg) -replace 'PasswordComplexity\s*=\s*0','PasswordComplexity = 1' | Set-Content $env:TEMP\secpol.cfg; secedit /configure /db $env:windir\security\database\secedit.sdb /cfg $env:TEMP\secpol.cfg /areas SECURITYPOLICY",
    ),
    "set_lockout_threshold_10": ActionRecipe(
        id="set_lockout_threshold_10",
        title="Set account lockout threshold to 10",
        description="Reduce account lockout threshold to 10 failed sign-in attempts.",
        scope="Computer",
        severity="Medium",
        safe_default=False,
        powershell=r"net accounts /lockoutthreshold:10",
    ),
    "misc_reg_keys": ActionRecipe(
        id="misc_reg_keys",
        title="Misc Registry Keys (by john)",
        description="Set multiple security-related registry values: RunAsPPL, DisableWebPnPDownload, NoDriveTypeAutoRun, and WUA service startup.",
        scope="Computer",
        severity="Medium",
        safe_default=True,
        powershell=r"New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force -ErrorAction SilentlyContinue | Out-Null; New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord -ErrorAction Stop; Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Value 1 -Type DWord -ErrorAction Stop; Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -ErrorAction Stop; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv' -Name 'Start' -Value 2 -Type DWord -ErrorAction Stop",
    ),
    "install_gemini_cli": ActionRecipe(
        id="install_gemini_cli",
        title="Install Gemini CLI",
        description="Check/install Node.js and npm, update npm, then install Google Gemini CLI globally.",
        scope="Computer",
        severity="Medium",
        safe_default=False,
        powershell=r"if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Write-Host 'npm not found, installing Node.js...'; winget install -e --id OpenJS.NodeJS -ErrorAction SilentlyContinue | Out-Null; if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'Node.js installation failed' } }; Write-Host 'Updating npm...'; npm install -g npm --ErrorAction Stop | Out-Null; Write-Host 'Installing Gemini CLI...'; if (-not $env:GOOGLE_API_KEY) { throw 'GOOGLE_API_KEY environment variable not set' }; npm install -g @google/gemini-cli -ErrorAction Stop",
    ),
}


def get_bool_text(value):
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value or "")


def looks_like_default_gpo(name: str) -> bool:
    return (name or "").strip().lower() in DEFAULT_GPO_NAMES


def looks_like_baseline_gpo(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in GPO_NAME_KEYWORDS_BASELINE)


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _iter_xml_nodes(root, local_name: str):
    for elem in root.iter():
        if _xml_local_name(elem.tag) == local_name:
            yield elem


def _text_or_empty(elem):
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def _find_all_text_pairs(root):
    rows = []
    for ext in _iter_xml_nodes(root, "ExtensionData"):
        texts = []
        for elem in ext.iter():
            txt = _text_or_empty(elem)
            if txt:
                texts.append(txt)
        if texts:
            rows.append(" | ".join(texts))
    return rows




def analyze_gpo_xml_report(xml_text: str) -> dict:
    findings = []
    settings_blob = ""
    root = None

    try:
        root = ET.fromstring(xml_text)
        settings_lines = _find_all_text_pairs(root)
        settings_blob = "\n".join(settings_lines)
    except Exception:
        settings_blob = xml_text or ""

    blob = settings_blob.lower()

    def add_finding(severity, title, detail):
        findings.append(
            {
                "Severity": severity,
                "Title": title,
                "Detail": detail,
            }
        )

    m = re.search(r"minimum password length[^0-9]{0,20}(\d+)", blob, re.I)
    if m:
        length = int(m.group(1))
        if length < 12:
            add_finding(
                "High",
                "Weak password length",
                f"Minimum password length appears to be {length}.",
            )

    if re.search(
        r"password must meet complexity requirements[^a-z]{0,20}(disabled|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Password complexity disabled",
            "Password complexity appears disabled.",
        )

    m = re.search(r"account lockout threshold[^0-9]{0,20}(\d+)", blob, re.I)
    if m:
        threshold = int(m.group(1))
        if threshold == 0:
            add_finding(
                "High",
                "No account lockout",
                "Account lockout threshold appears to be 0.",
            )
        elif threshold > 10:
            add_finding(
                "Medium",
                "Weak account lockout threshold",
                f"Account lockout threshold appears high at {threshold}.",
            )

    if re.search(
        r"windows defender firewall[^a-z]{0,40}(disabled|off|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Firewall disabled",
            "Windows Defender Firewall appears disabled by policy.",
        )

    if re.search(
        r"turn off microsoft defender antivirus[^a-z]{0,40}(enabled|true|yes)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Defender disabled",
            "Policy appears to turn off Microsoft Defender Antivirus.",
        )

    if re.search(
        r"real-time protection[^a-z]{0,40}(disabled|off|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Real-time protection disabled",
            "Defender real-time protection appears disabled.",
        )

    if re.search(
        r"user account control: run all administrators in admin approval mode[^a-z]{0,40}(disabled|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "UAC weakened",
            "Admin Approval Mode appears disabled.",
        )

    if re.search(
        r"allow users to connect remotely using remote desktop services[^a-z]{0,40}(enabled|true|yes)",
        blob,
        re.I,
    ):
        if re.search(
            r"require user authentication for remote connections by using network level authentication[^a-z]{0,40}(disabled|false|no)",
            blob,
            re.I,
        ):
            add_finding(
                "High",
                "RDP without NLA",
                "RDP appears enabled while NLA appears disabled.",
            )
        else:
            add_finding(
                "Low",
                "RDP enabled",
                "RDP access appears enabled by policy.",
            )

    if re.search(
        r"network security: lan manager authentication level[^|\n]*send lm & ntlm responses",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Weak LAN Manager auth",
            "LAN Manager authentication level appears to allow LM/NTLM responses.",
        )

    if re.search(
        r"microsoft network client: digitally sign communications \(always\)[^a-z]{0,40}(disabled|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "Medium",
            "SMB client signing not required",
            "SMB client signing does not appear required.",
        )

    if re.search(
        r"microsoft network server: digitally sign communications \(always\)[^a-z]{0,40}(disabled|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "Medium",
            "SMB server signing not required",
            "SMB server signing does not appear required.",
        )

    if re.search(
        r"network access: do not allow anonymous enumeration of sam accounts and shares[^a-z]{0,40}(disabled|false|no)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Anonymous enumeration allowed",
            "Anonymous enumeration protections appear disabled.",
        )

    if re.search(
        r"network access: let everyone permissions apply to anonymous users[^a-z]{0,40}(enabled|true|yes)",
        blob,
        re.I,
    ):
        add_finding(
            "High",
            "Anonymous users overly permitted",
            "Everyone permissions appear to apply to anonymous users.",
        )

    m = re.search(
        r"interactive logon: number of previous logons to cache[^0-9]{0,20}(\d+)",
        blob,
        re.I,
    )
    if m:
        cached = int(m.group(1))
        if cached > 10:
            add_finding(
                "Medium",
                "Many cached logons",
                f"Cached interactive logons appears set to {cached}.",
            )

    if re.search(
        r"turn on script execution[^|\n]*(allow all scripts|enabled)",
        blob,
        re.I,
    ):
        add_finding(
            "Medium",
            "Permissive PowerShell execution",
            "PowerShell script execution appears permissive.",
        )

    if re.search(r"executionpolicy[^\n]{0,80}(bypass|unrestricted)", blob, re.I):
        add_finding(
            "Medium",
            "Permissive PowerShell execution",
            "ExecutionPolicy appears configured to Bypass or Unrestricted in a GPO.",
        )

    if "turn on script execution" in blob and "allow all scripts" in blob:
        add_finding(
            "Medium",
            "PowerShell scripts allowed",
            "Policy 'Turn on Script Execution' is present with language allowing all scripts.",
        )

    if "advanced audit policy configuration" not in blob and "audit policy" not in blob:
        add_finding(
            "Low",
            "No obvious audit policy settings",
            "No obvious audit policy settings were found in this GPO report.",
        )

    risk_score = 0
    for f in findings:
        if f["Severity"] == "High":
            risk_score += 3
        elif f["Severity"] == "Medium":
            risk_score += 2
        elif f["Severity"] == "Low":
            risk_score += 1

    if risk_score >= 6:
        risk = "High"
    elif risk_score >= 3:
        risk = "Medium"
    elif risk_score >= 1:
        risk = "Low"
    else:
        risk = "Info"

    return {
        "Risk": risk,
        "RiskScore": risk_score,
        "Findings": findings,
        "SettingsBlob": settings_blob,
    }


def get_gpo_inventory():
    script = r'''
$ErrorActionPreference = 'Stop'

try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error = "GroupPolicy module is not available."
        Gpos = @()
    } | ConvertTo-Json -Depth 6 -Compress
    return
}

$cs = Get-CimInstance Win32_ComputerSystem
$domainName = [string]$cs.Domain
$partOfDomain = [bool]$cs.PartOfDomain

if (-not $partOfDomain) {
    [pscustomobject]@{
        Error = "Computer is not joined to a domain."
        Gpos = @()
    } | ConvertTo-Json -Depth 6 -Compress
    return
}

$gpoList = @()

try {
    $gpos = Get-GPO -All -ErrorAction Stop
} catch {
    [pscustomobject]@{
        Error = ("Failed to query GPOs: " + $_.Exception.Message)
        Gpos = @()
    } | ConvertTo-Json -Depth 6 -Compress
    return
}

foreach ($g in $gpos) {
    $xml = $null
    $links = @()
    $wmiFilterName = ""
    $domainLinked = $false
    $dcLinked = $false
    $enforced = $false

    try {
        $xml = Get-GPOReport -Guid $g.Id -ReportType Xml -ErrorAction Stop
    } catch {
        $xml = ""
    }

    try {
        if ($xml) {
            [xml]$doc = $xml

            $linkNodes = $doc.SelectNodes("//*[local-name()='LinksTo']")
            foreach ($ln in $linkNodes) {
                $somPath = ""
                $somName = ""
                $enabled = ""
                $noOverride = ""

                foreach ($child in $ln.ChildNodes) {
                    switch ($child.LocalName) {
                        "SOMPath" { $somPath = [string]$child.InnerText }
                        "SOMName" { $somName = [string]$child.InnerText }
                        "Enabled" { $enabled = [string]$child.InnerText }
                        "NoOverride" { $noOverride = [string]$child.InnerText }
                    }
                }

                $targetText = $somPath
                if (-not $targetText) { $targetText = $somName }

                if ($targetText) {
                    $links += [pscustomobject]@{
                        Target = $targetText
                        Enabled = $enabled
                        Enforced = $noOverride
                    }

                    if ($targetText -ieq $domainName -or $targetText -match ("DC=" + ($domainName -replace '\.', ',DC='))) {
                        $domainLinked = $true
                    }

                    if ($targetText -match 'OU=Domain Controllers' -or $targetText -match 'Domain Controllers') {
                        $dcLinked = $true
                    }

                    if ($noOverride -match 'true') {
                        $enforced = $true
                    }
                }
            }

            $wmiNode = $doc.SelectSingleNode("//*[local-name()='WMIFilter']/*[local-name()='Name']")
            if ($wmiNode) {
                $wmiFilterName = [string]$wmiNode.InnerText
            }
        }
    } catch {
    }

    $gpoList += [pscustomobject]@{
        DisplayName = $g.DisplayName
        Id = [string]$g.Id
        Owner = $g.Owner
        CreationTime = $g.CreationTime
        ModificationTime = $g.ModificationTime
        GpoStatus = [string]$g.GpoStatus
        Description = $g.Description
        XmlReport = $xml
        Links = @($links)
        LinkTargets = @($links | ForEach-Object { $_.Target })
        DomainLinked = [bool]$domainLinked
        DomainControllersLinked = [bool]$dcLinked
        Enforced = [bool]$enforced
        WmiFilter = $wmiFilterName
    }
}

[pscustomobject]@{
    Error = ""
    DomainName = $domainName
    PartOfDomain = $partOfDomain
    Gpos = @($gpoList)
} | ConvertTo-Json -Depth 8 -Compress
'''
    data = run_powershell_json(script) or {}

    if not isinstance(data, dict):
        return {
            "Error": "Unexpected response while collecting GPO data.",
            "DomainName": "",
            "PartOfDomain": False,
            "Gpos": [],
        }

    raw_gpos = data.get("Gpos") or []
    if isinstance(raw_gpos, dict):
        raw_gpos = [raw_gpos]

    results = []
    for gpo in raw_gpos:
        name = gpo.get("DisplayName", "")
        analysis = analyze_gpo_xml_report(gpo.get("XmlReport", "") or "")
        link_targets = gpo.get("LinkTargets") or []
        if isinstance(link_targets, str):
            link_targets = [link_targets]

        row = {
            "DisplayName": name,
            "Id": gpo.get("Id", ""),
            "Owner": gpo.get("Owner", ""),
            "CreationTime": gpo.get("CreationTime", ""),
            "ModificationTime": gpo.get("ModificationTime", ""),
            "GpoStatus": gpo.get("GpoStatus", ""),
            "Description": gpo.get("Description", ""),
            "IsDefault": looks_like_default_gpo(name),
            "LooksLikeBaseline": looks_like_baseline_gpo(name),
            "Risk": analysis["Risk"],
            "RiskScore": analysis["RiskScore"],
            "Findings": analysis["Findings"],
            "SettingsBlob": analysis["SettingsBlob"],
            "Links": gpo.get("Links") or [],
            "LinkTargets": link_targets,
            "Linked": bool(link_targets),
            "DomainLinked": bool(gpo.get("DomainLinked", False)),
            "DomainControllersLinked": bool(gpo.get("DomainControllersLinked", False)),
            "Enforced": bool(gpo.get("Enforced", False)),
            "WmiFilter": gpo.get("WmiFilter", "") or "",
        }
        results.append(row)

    results.sort(key=lambda x: (
        not x["DomainControllersLinked"],
        not x["DomainLinked"],
        not x["Linked"],
        x["IsDefault"],
        -x["RiskScore"],
        x["DisplayName"].lower(),
    ))

    return {
        "Error": data.get("Error", "") or "",
        "DomainName": data.get("DomainName", "") or "",
        "PartOfDomain": bool(data.get("PartOfDomain", False)),
        "Gpos": results,
    }


class StatCard(ttk.Frame):
    def __init__(self, parent, title, value="0", bootstyle="secondary"):
        super().__init__(parent, padding=16, bootstyle=bootstyle)
        self.value_var = ttk.StringVar(value=value)
        self.title_var = ttk.StringVar(value=title)

        ttk.Label(self, textvariable=self.title_var, font=("Segoe UI", 11, "bold"), bootstyle="light").pack(anchor="w")
        ttk.Label(self, textvariable=self.value_var, font=("Segoe UI", 28, "bold"), bootstyle="light").pack(anchor="w", pady=(10, 0))

    def set_value(self, value):
        self.value_var.set(str(value))


class ForensicsToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1500x930")
        self.root.minsize(1260, 800)

        self.questions = []
        self.reports = []
        self.tasks = []
        self.registry_entries = []
        self.apps = []
        self.user_audit = {}
        self.gpos = []
        self.actions = []

        self.manual_readme_text = ""
        self.manual_readme_path = ""

        self.debug_messages = []
        self.debug_window = None
        self.debug_text = None

        self.style = ttk.Style(theme=APP_THEME)
        self.configure_styles()
        self.build_ui()

    def build_gpo_tab(self):
        ttk.Label(self.gpo_tab, text="Group Policy Audit", style="Section.TLabel", bootstyle="primary").pack(anchor="w", pady=(0, 8))

        topbar = ttk.Frame(self.gpo_tab)
        topbar.pack(fill=X, pady=(0, 10))

        ttk.Button(topbar, text="Analyze GPOs", command=self.analyze_gpos, bootstyle=PRIMARY).pack(side=LEFT)

        self.gpo_summary_var = ttk.StringVar(value="No GPO audit run yet.")
        ttk.Label(topbar, textvariable=self.gpo_summary_var, bootstyle="secondary").pack(side=LEFT, padx=12)

        upper = ttk.Frame(self.gpo_tab)
        upper.pack(fill=BOTH, expand=YES)

        self.gpo_tree = self.build_tree_with_scrollbars(
            upper,
            ("risk", "custom", "linked", "dc_linked", "baseline", "name", "status", "findings"),
            [
                ("risk", "Risk", 80),
                ("custom", "Custom", 80),
                ("linked", "Linked", 80),
                ("dc_linked", "DC Linked", 90),
                ("baseline", "Baseline-like", 100),
                ("name", "GPO Name", 300),
                ("status", "Status", 130),
                ("findings", "Findings", 430),
            ],
            bootstyle="primary",
        )
        self.apply_tree_tags(self.gpo_tree)
        self.gpo_tree.bind("<<TreeviewSelect>>", self.on_gpo_selected)

        detail_frame = ttk.Labelframe(self.gpo_tab, text="GPO Findings", padding=12, bootstyle="primary")
        detail_frame.pack(fill=BOTH, expand=YES, pady=(12, 0))

        self.gpo_detail_text = tk.Text(
            detail_frame,
            wrap="word",
            height=12,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.gpo_detail_text.pack(fill=BOTH, expand=YES)
        self.gpo_detail_text.configure(state="disabled")

    def analyze_gpos(self):
        try:
            self.status_var.set("Collecting Group Policy data...")
            self.root.update_idletasks()

            gpo_data = get_gpo_inventory()
            self.gpos = gpo_data.get("Gpos", [])

            for item in self.gpo_tree.get_children():
                self.gpo_tree.delete(item)

            error_text = gpo_data.get("Error", "") or ""
            if error_text and not self.gpos:
                self.gpo_summary_var.set(error_text)
                self.status_var.set("GPO audit complete")
                self.populate_actions()
                return

            risky = 0
            custom = 0
            linked = 0
            dc_linked = 0

            for idx, gpo in enumerate(self.gpos):
                findings = gpo.get("Findings", [])
                finding_titles = "; ".join(f["Title"] for f in findings[:3]) if findings else "No obvious insecure settings found"

                if not gpo.get("IsDefault"):
                    custom += 1
                if gpo.get("Risk") in {"Medium", "High"}:
                    risky += 1
                if gpo.get("Linked"):
                    linked += 1
                if gpo.get("DomainControllersLinked"):
                    dc_linked += 1

                if gpo.get("Risk") == "High":
                    tag = "High"
                elif gpo.get("Risk") == "Medium":
                    tag = "Medium"
                elif gpo.get("DomainControllersLinked"):
                    tag = "Low"
                else:
                    tag = "Info"

                self.gpo_tree.insert(
                    "",
                    "end",
                    iid=f"gpo_{idx}",
                    values=(
                        gpo.get("Risk", "Info"),
                        "No" if gpo.get("IsDefault") else "Yes",
                        "Yes" if gpo.get("Linked") else "No",
                        "Yes" if gpo.get("DomainControllersLinked") else "No",
                        "Yes" if gpo.get("LooksLikeBaseline") else "No",
                        gpo.get("DisplayName", ""),
                        gpo.get("GpoStatus", ""),
                        finding_titles,
                    ),
                    tags=(tag,),
                )

            self.gpo_summary_var.set(
                f"Total GPOs: {len(self.gpos)} | "
                f"Custom GPOs: {custom} | "
                f"Risky GPOs: {risky} | "
                f"Linked GPOs: {linked} | "
                f"DC-linked: {dc_linked}"
            )

            self.status_var.set("GPO audit complete")
            self.populate_actions()
        except Exception as ex:
            self.status_var.set("GPO audit failed")
            messagebox.showerror("GPO audit failed", str(ex))

    def on_gpo_selected(self, _event=None):
        if not self.gpo_tree.selection():
            return

        iid = self.gpo_tree.selection()[0]
        try:
            idx = int(iid.split("_", 1)[1])
        except Exception:
            return

        if idx < 0 or idx >= len(self.gpos):
            return

        gpo = self.gpos[idx]

        lines = [
            f"Name: {gpo.get('DisplayName', '')}",
            f"ID: {gpo.get('Id', '')}",
            f"Default: {'Yes' if gpo.get('IsDefault') else 'No'}",
            f"Baseline-like: {'Yes' if gpo.get('LooksLikeBaseline') else 'No'}",
            f"Risk: {gpo.get('Risk', '')}",
            f"Status: {gpo.get('GpoStatus', '')}",
            f"Owner: {gpo.get('Owner', '')}",
            f"Created: {gpo.get('CreationTime', '')}",
            f"Modified: {gpo.get('ModificationTime', '')}",
            f"Linked anywhere: {'Yes' if gpo.get('Linked') else 'No'}",
            f"Linked to domain root: {'Yes' if gpo.get('DomainLinked') else 'No'}",
            f"Linked to Domain Controllers: {'Yes' if gpo.get('DomainControllersLinked') else 'No'}",
            f"Enforced somewhere: {'Yes' if gpo.get('Enforced') else 'No'}",
            f"WMI Filter: {gpo.get('WmiFilter', '') or 'None'}",
            "",
            "Link targets:",
        ]

        link_targets = gpo.get("LinkTargets", [])
        if link_targets:
            for target in link_targets:
                lines.append(f"- {target}")
        else:
            lines.append("- None")

        lines.append("")
        lines.append("Findings:")

        findings = gpo.get("Findings", [])
        if findings:
            for f in findings:
                lines.append(f"- [{f['Severity']}] {f['Title']}: {f['Detail']}")
        else:
            lines.append("- No obvious insecure settings found by quick audit.")

        self.gpo_detail_text.configure(state="normal")
        self.gpo_detail_text.delete("1.0", "end")
        self.gpo_detail_text.insert("1.0", "\n".join(lines))
        self.gpo_detail_text.configure(state="disabled")

    def log_debug(self, message: str):
        text = str(message)
        self.debug_messages.append(text)

        if self.debug_text is not None:
            try:
                self.debug_text.insert("end", text + "\n")
                self.debug_text.see("end")
            except Exception:
                pass

    def open_debug_window(self):
        if self.debug_window is not None and self.debug_window.winfo_exists():
            self.debug_window.lift()
            self.debug_window.focus_force()
            return

        self.debug_window = ttk.Toplevel(self.root)
        self.debug_window.title("Debug Log")
        self.debug_window.geometry("1000x600")

        frame = ttk.Frame(self.debug_window, padding=10)
        frame.pack(fill=BOTH, expand=YES)

        btnbar = ttk.Frame(frame)
        btnbar.pack(fill=X, pady=(0, 8))

        ttk.Button(btnbar, text="Clear", command=self.clear_debug_log, bootstyle=(SECONDARY, OUTLINE)).pack(side=LEFT)
        ttk.Button(btnbar, text="Copy All", command=self.copy_debug_log, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=8)

        self.debug_text = ScrolledText(frame, height=30, autohide=False, bootstyle="info")
        self.debug_text.pack(fill=BOTH, expand=YES)

        try:
            self.debug_text.delete("1.0", "end")
            if self.debug_messages:
                self.debug_text.insert("end", "\n".join(self.debug_messages) + "\n")
                self.debug_text.see("end")
        except Exception:
            pass

    def clear_debug_log(self):
        self.debug_messages.clear()
        if self.debug_text is not None:
            try:
                self.debug_text.delete("1.0", "end")
            except Exception:
                pass

    def copy_debug_log(self):
        all_text = "\n".join(self.debug_messages)
        self.root.clipboard_clear()
        self.root.clipboard_append(all_text)
        self.status_var.set("Debug log copied to clipboard")

    def configure_styles(self):
        self.style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        self.style.configure("SubTitle.TLabel", font=("Segoe UI", 11))
        self.style.configure("Section.TLabel", font=("Segoe UI", 13, "bold"))
        self.style.configure("Treeview", rowheight=30)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def build_ui(self):
        shell = ttk.Frame(self.root, padding=16)
        shell.pack(fill=BOTH, expand=YES)

        hero = ttk.Frame(shell)
        hero.pack(fill=X, pady=(0, 12))
        ttk.Label(hero, text=APP_TITLE, style="Title.TLabel").pack(side=LEFT)
        ttk.Label(
            hero,
            text="Windows persistence review + questions + advanced report resolver",
            style="SubTitle.TLabel",
            bootstyle="secondary",
        ).pack(side=LEFT, padx=14, pady=(7, 0))

        actions = ttk.Frame(shell)
        actions.pack(fill=X, pady=(0, 12))
        ttk.Button(actions, text="Scan All", command=self.scan_all, bootstyle=SUCCESS).pack(side=LEFT)
        ttk.Button(actions, text="Reload Questions", command=self.load_question_files, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=8)
        ttk.Button(actions, text="Reload Reports", command=self.load_report_files, bootstyle=(PRIMARY, OUTLINE)).pack(side=LEFT, padx=8)
        ttk.Button(actions, text="Switch Theme", command=self.toggle_theme, bootstyle=(SECONDARY, OUTLINE)).pack(side=LEFT)
        ttk.Button(actions, text="Debug", command=self.open_debug_window, bootstyle=(WARNING, OUTLINE)).pack(side=LEFT, padx=8)
        self.status_var = ttk.StringVar(value="Ready")
        ttk.Label(actions, textvariable=self.status_var, bootstyle="warning").pack(side=RIGHT)

        self.notebook = ttk.Notebook(shell, bootstyle="primary")
        self.notebook.pack(fill=BOTH, expand=YES)

        self.overview_tab = ttk.Frame(self.notebook, padding=18)
        self.tasks_tab = ttk.Frame(self.notebook, padding=14)
        self.registry_tab = ttk.Frame(self.notebook, padding=14)
        self.apps_tab = ttk.Frame(self.notebook, padding=14)
        self.users_tab = ttk.Frame(self.notebook, padding=14)
        self.actions_tab = ttk.Frame(self.notebook, padding=14)
        self.questions_tab = ttk.Frame(self.notebook, padding=14)
        self.reports_tab = ttk.Frame(self.notebook, padding=14)
        self.gpo_tab = ttk.Frame(self.notebook, padding=14)

        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.tasks_tab, text="Tasks")
        self.notebook.add(self.registry_tab, text="Registry")
        self.notebook.add(self.apps_tab, text="Apps")
        self.notebook.add(self.users_tab, text="Users")
        self.notebook.add(self.actions_tab, text="Actions")
        self.notebook.add(self.questions_tab, text="Questions")
        self.notebook.add(self.reports_tab, text="Reports")
        self.notebook.add(self.gpo_tab, text="GPOs")

        self.build_overview_tab()
        self.build_tasks_tab()
        self.build_registry_tab()
        self.build_apps_tab()
        self.build_users_tab()
        self.build_actions_tab()
        self.build_questions_tab()
        self.build_reports_tab()
        self.build_gpo_tab()

    def build_overview_tab(self):
        ttk.Label(self.overview_tab, text="Analyst Overview", style="Section.TLabel", bootstyle="info").pack(anchor="w")
        cards = ttk.Frame(self.overview_tab)
        cards.pack(fill=X, pady=(14, 14))

        self.card_questions = StatCard(cards, "Questions", "0", "info")
        self.card_questions.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.card_reports = StatCard(cards, "Reports", "0", "primary")
        self.card_reports.grid(row=0, column=1, sticky="nsew", padx=(0, 10))
        self.card_tasks = StatCard(cards, "Suspicious Tasks", "0", "danger")
        self.card_tasks.grid(row=0, column=2, sticky="nsew", padx=(0, 10))
        self.card_registry = StatCard(cards, "Suspicious Registry", "0", "warning")
        self.card_registry.grid(row=0, column=3, sticky="nsew", padx=(0, 10))
        self.card_apps = StatCard(cards, "Likely Non-Default Apps", "0", "success")
        self.card_apps.grid(row=0, column=4, sticky="nsew", padx=(0, 10))
        self.card_users = StatCard(cards, "Unexpected Users", "0", "secondary")
        self.card_users.grid(row=0, column=5, sticky="nsew")

        for i in range(6):
            cards.columnconfigure(i, weight=1)

        summary_frame = ttk.Labelframe(self.overview_tab, text="Summary", padding=12, bootstyle="primary")
        summary_frame.pack(fill=BOTH, expand=YES)

        self.summary_text = tk.Text(
            summary_frame,
            wrap="word",
            height=20,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.summary_text.pack(fill=BOTH, expand=YES)
        self.summary_text.insert("1.0", "Click Scan All to collect data.")
        self.summary_text.configure(state="disabled")

    def build_tree_with_scrollbars(self, parent, columns, headings, bootstyle="primary"):
        container = ttk.Frame(parent)
        container.pack(fill=BOTH, expand=YES)
        tree = ttk.Treeview(container, columns=columns, show="headings", bootstyle=bootstyle)
        vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview, bootstyle=bootstyle)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=tree.xview, bootstyle=bootstyle)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for col, title, width in headings:
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor="w")

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        return tree

    def apply_tree_tags(self, tree):
        tree.tag_configure("High", background="#5a1d1d", foreground="#ffd7d7")
        tree.tag_configure("Medium", background="#5a4316", foreground="#ffe7b3")
        tree.tag_configure("Low", background="#163b5a", foreground="#cfe8ff")
        tree.tag_configure("Info", background="#2f3542", foreground="#dfe6ee")
        tree.tag_configure("Likely", background="#1f4d2e", foreground="#d8ffe1")
        tree.tag_configure("Default", background="#2f3542", foreground="#dfe6ee")

    def build_tasks_tab(self):
        ttk.Label(self.tasks_tab, text="Scheduled Tasks", style="Section.TLabel", bootstyle="danger").pack(anchor="w", pady=(0, 8))
        self.tasks_tree = self.build_tree_with_scrollbars(
            self.tasks_tab,
            ("severity", "score", "name", "path", "user", "command"),
            [
                ("severity", "Severity", 90),
                ("score", "Score", 70),
                ("name", "Task Name", 220),
                ("path", "Task Path", 220),
                ("user", "User", 180),
                ("command", "Command", 520),
            ],
            bootstyle="danger",
        )
        self.apply_tree_tags(self.tasks_tree)

    def build_registry_tab(self):
        ttk.Label(self.registry_tab, text="Registry Persistence", style="Section.TLabel", bootstyle="warning").pack(anchor="w", pady=(0, 8))
        self.registry_tree = self.build_tree_with_scrollbars(
            self.registry_tab,
            ("severity", "score", "path", "name", "data"),
            [
                ("severity", "Severity", 90),
                ("score", "Score", 70),
                ("path", "Registry Path", 320),
                ("name", "Value Name", 180),
                ("data", "Value Data", 560),
            ],
            bootstyle="warning",
        )
        self.apply_tree_tags(self.registry_tree)

    def build_apps_tab(self):
        ttk.Label(self.apps_tab, text="Installed Programs", style="Section.TLabel", bootstyle="success").pack(anchor="w", pady=(0, 8))
        self.apps_tree = self.build_tree_with_scrollbars(
            self.apps_tab,
            ("flag", "name", "version", "publisher", "location"),
            [
                ("flag", "Likely Non-Default", 140),
                ("name", "Display Name", 320),
                ("version", "Version", 110),
                ("publisher", "Publisher", 260),
                ("location", "Install Location", 340),
            ],
            bootstyle="success",
        )
        self.apply_tree_tags(self.apps_tree)

    def on_user_selected(self, _event=None):
        if not self.users_tree.selection():
            return

        item_id = self.users_tree.selection()[0]
        item_index = self.users_tree.index(item_id)

        results = self.user_audit.get("Results", [])
        if item_index < 0 or item_index >= len(results):
            return

        row = results[item_index]

        lines = [
            f"Name: {row.get('Name', '')}",
            f"Identity: {row.get('Identity', '')}",
            f"Principal Source: {row.get('PrincipalSource', '')}",
            f"Enabled: {'Yes' if row.get('Enabled') else 'No'}",
            f"Authorized: {'Yes' if row.get('Authorized') else 'No'}",
            f"Unexpected: {'Yes' if row.get('Unexpected') else 'No'}",
            f"Admin: {'Yes' if row.get('IsAdmin') else 'No'}",
        ]

        if row.get("Unexpected") and row.get("IsAdmin"):
            lines.append("")
            lines.append("Assessment: Unexpected administrator account.")
        elif row.get("Unexpected"):
            lines.append("")
            lines.append("Assessment: Unexpected account.")
        elif row.get("IsAdmin"):
            lines.append("")
            lines.append("Assessment: Authorized account with administrator access.")
        else:
            lines.append("")
            lines.append("Assessment: Authorized standard account or expected account state.")

        self.user_detail_text.configure(state="normal")
        self.user_detail_text.delete("1.0", "end")
        self.user_detail_text.insert("1.0", "\n".join(lines))
        self.user_detail_text.configure(state="disabled")

    def build_users_tab(self):
        ttk.Label(self.users_tab, text="Authorized vs Current Users", style="Section.TLabel", bootstyle="primary").pack(anchor="w", pady=(0, 8))

        topbar = ttk.Frame(self.users_tab)
        topbar.pack(fill=X, pady=(0, 10))

        ttk.Button(topbar, text="Analyze Users", command=self.analyze_users_from_readme, bootstyle=PRIMARY).pack(side=LEFT)
        ttk.Button(topbar, text="Load README File", command=self.load_manual_readme_file, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=8)

        self.user_summary_var = ttk.StringVar(value="No user audit run yet.")
        ttk.Label(topbar, textvariable=self.user_summary_var, bootstyle="secondary").pack(side=LEFT, padx=12)

        self.user_readme_source_var = ttk.StringVar(value="README source not identified yet")
        ttk.Label(topbar, textvariable=self.user_readme_source_var, bootstyle="info").pack(side=LEFT, padx=12)

        upper = ttk.Frame(self.users_tab)
        upper.pack(fill=BOTH, expand=YES)

        self.users_tree = self.build_tree_with_scrollbars(
            upper,
            ("unexpected", "admin", "authorized", "enabled", "name", "identity", "source"),
            [
                ("unexpected", "Unexpected", 110),
                ("admin", "Admin", 90),
                ("authorized", "Authorized", 100),
                ("enabled", "Enabled", 90),
                ("name", "Name", 180),
                ("identity", "Identity", 300),
                ("source", "Principal Source", 180),
            ],
            bootstyle="primary",
        )
        self.apply_tree_tags(self.users_tree)
        self.users_tree.bind("<<TreeviewSelect>>", self.on_user_selected)

        detail_frame = ttk.Labelframe(self.users_tab, text="User Details", padding=12, bootstyle="primary")
        detail_frame.pack(fill=BOTH, expand=YES, pady=(12, 0))

        self.user_detail_text = tk.Text(
            detail_frame,
            wrap="word",
            height=12,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.user_detail_text.pack(fill=BOTH, expand=YES)
        self.user_detail_text.insert("1.0", "Select a user row to view details.")
        self.user_detail_text.configure(state="disabled")

    def load_manual_readme_file(self):
        file_path = filedialog.askopenfilename(
            title="Select README file",
            filetypes=[("README files", "*.url *.lnk *.html *.htm *.txt *.md *.text"), ("All files", "*")],
        )
        if not file_path:
            return

        try:
            text = self._resolve_manual_readme(Path(file_path))
        except Exception as ex:
            messagebox.showerror("Load failed", str(ex))
            return

        self.manual_readme_text = text
        self.manual_readme_path = file_path
        self.user_readme_source_var.set(f"README source: {Path(file_path).name}")
        self.log_debug(f"Loaded manual README file: {file_path}")
        messagebox.showinfo("README loaded", f"Loaded README from:\n{file_path}")

    def _resolve_manual_readme(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix in (".html", ".htm"):
            raw = path.read_text(encoding="utf-8", errors="ignore")
            return html_to_text(raw)
        if suffix in (".txt", ".md", ".text"):
            return path.read_text(encoding="utf-8", errors="ignore")

        if suffix == ".url":
            kind, resolved = resolve_url_shortcut(path)
            if kind == "local" and resolved:
                if resolved.is_file():
                    raw = resolved.read_text(encoding="utf-8", errors="ignore")
                    return html_to_text(raw) if resolved.suffix.lower() in (".html", ".htm") else raw
                if resolved.is_dir():
                    for candidate in find_report_candidates_in_directory(resolved):
                        if candidate.suffix.lower() in (".html", ".htm", ".txt", ".md", ".text"):
                            raw = candidate.read_text(encoding="utf-8", errors="ignore")
                            return html_to_text(raw) if candidate.suffix.lower() in (".html", ".htm") else raw
            if kind == "remote" and resolved:
                return fetch_url_text(resolved)
            raise ValueError("Unable to resolve README .url shortcut to usable content.")

        if suffix == ".lnk":
            resolved = resolve_lnk_shortcut(path)
            if not resolved:
                raise ValueError("Unable to resolve README shortcut target.")

            target = (resolved.get("target") or "").strip()
            args = (resolved.get("args") or "").strip()
            working_dir = (resolved.get("working_dir") or "").strip()

            if target:
                target_path = Path(target)
                if target_path.is_file() and target_path.suffix.lower() in (".html", ".htm", ".txt", ".md", ".text"):
                    raw = target_path.read_text(encoding="utf-8", errors="ignore")
                    return html_to_text(raw) if target_path.suffix.lower() in (".html", ".htm") else raw

            combined = f"{target} {args} {working_dir}".strip()
            m = re.search(r'([A-Za-z]:\\[^\s"]+\\(?:index|report|results|score|scoring)[^\s"]*\.(?:html?|htm))', combined, re.I)
            if m:
                possible = Path(m.group(1))
                if possible.is_file():
                    raw = possible.read_text(encoding="utf-8", errors="ignore")
                    return html_to_text(raw)

            raise ValueError("Unable to resolve README .lnk shortcut to usable content.")

        return path.read_text(encoding="utf-8", errors="ignore")

    def build_actions_tab(self):
        ttk.Label(self.actions_tab, text="Remediation Actions", style="Section.TLabel", bootstyle="warning").pack(anchor="w", pady=(0, 8))

        topbar = ttk.Frame(self.actions_tab)
        topbar.pack(fill=X, pady=(0, 10))

        ttk.Button(topbar, text="Refresh Actions", command=self.populate_actions, bootstyle=PRIMARY).pack(side=LEFT)
        ttk.Button(topbar, text="Run Selected", command=self.run_selected_actions, bootstyle=WARNING).pack(side=LEFT, padx=8)
        ttk.Button(topbar, text="Run All Safe", command=self.run_all_safe_actions, bootstyle=SUCCESS).pack(side=LEFT)
        ttk.Button(topbar, text="Copy Command", command=self.copy_selected_action_command, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=8)

        self.hide_readme_required_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            topbar,
            text="Hide README-required options",
            variable=self.hide_readme_required_var,
            command=self.populate_actions,
            bootstyle="round-toggle",
        ).pack(side=LEFT, padx=14)

        self.actions_summary_var = ttk.StringVar(value="No actions generated yet.")
        ttk.Label(topbar, textvariable=self.actions_summary_var, bootstyle="secondary").pack(side=LEFT, padx=12)

        # Create sub-tab notebook for different action categories
        upper = ttk.Frame(self.actions_tab)
        upper.pack(fill=BOTH, expand=YES)

        self.actions_notebook = ttk.Notebook(upper, bootstyle="warning")
        self.actions_notebook.pack(fill=BOTH, expand=YES)

        # Create tabs for each source category
        self.action_tabs = {}
        self.action_trees = {}

        categories = ["Users", "Tasks", "Other", "Prebake"]
        for category in categories:
            tab_frame = ttk.Frame(self.actions_notebook, padding=10)
            self.actions_notebook.add(tab_frame, text=category)
            self.action_tabs[category] = tab_frame

            tree = self.build_tree_with_scrollbars(
                tab_frame,
                ("severity", "safe", "source", "title", "reason"),
                [
                    ("severity", "Severity", 90),
                    ("safe", "Safe", 70),
                    ("source", "Source", 220),
                    ("title", "Action", 300),
                    ("reason", "Reason", 520),
                ],
                bootstyle="warning",
            )
            self.apply_tree_tags(tree)
            tree.bind("<<TreeviewSelect>>", self.on_action_selected)
            self.action_trees[category] = tree

        detail_frame = ttk.Labelframe(self.actions_tab, text="Action Details", padding=12, bootstyle="warning")
        detail_frame.pack(fill=BOTH, expand=YES, pady=(12, 0))

        self.action_detail_text = tk.Text(
            detail_frame,
            wrap="word",
            height=12,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.action_detail_text.pack(fill=BOTH, expand=YES)
        self.action_detail_text.configure(state="disabled")

    def build_questions_tab(self):
        outer = ttk.Frame(self.questions_tab)
        outer.pack(fill=BOTH, expand=YES)
        left_card = ttk.Labelframe(outer, text="Question Files", padding=10, bootstyle="info")
        left_card.pack(side=LEFT, fill=Y)
        right_card = ttk.Labelframe(outer, text="Question Editor", padding=12, bootstyle="primary")
        right_card.pack(side=LEFT, fill=BOTH, expand=YES, padx=(12, 0))

        self.question_list = tk.Listbox(
            left_card,
            width=42,
            height=28,
            bg="#132238",
            fg="#e8f1ff",
            selectbackground="#2a9fd6",
            selectforeground="white",
            relief="flat",
            highlightthickness=0,
        )
        self.question_list.pack(fill=Y, expand=NO)
        self.question_list.bind("<<ListboxSelect>>", self.on_question_selected)

        ttk.Label(right_card, text="Question", style="Section.TLabel", bootstyle="info").pack(anchor="w")
        self.question_text = tk.Text(
            right_card,
            wrap="word",
            height=20,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.question_text.pack(fill=BOTH, expand=YES, pady=(8, 12))
        self.question_text.configure(state="disabled")

        ttk.Label(right_card, text="Answer", style="Section.TLabel", bootstyle="success").pack(anchor="w")
        self.answer_var = ttk.StringVar()
        self.answer_entry = ttk.Entry(right_card, textvariable=self.answer_var, bootstyle="success")
        self.answer_entry.pack(fill=X, pady=(8, 10))
        self.answer_entry.bind("<Return>", self.save_current_answer)

        btns = ttk.Frame(right_card)
        btns.pack(fill=X)
        ttk.Button(btns, text="Save Answer", command=self.save_current_answer, bootstyle=SUCCESS).pack(side=LEFT)
        ttk.Button(btns, text="Clear", command=lambda: self.answer_var.set(""), bootstyle=(SECONDARY, OUTLINE)).pack(side=LEFT, padx=8)

        self.question_path_var = ttk.StringVar(value="")
        ttk.Label(right_card, textvariable=self.question_path_var, bootstyle="secondary").pack(anchor="w", pady=(12, 0))

    def build_reports_tab(self):
        outer = ttk.Frame(self.reports_tab)
        outer.pack(fill=BOTH, expand=YES)

        left_card = ttk.Labelframe(outer, text="Report Files", padding=10, bootstyle="primary")
        left_card.pack(side=LEFT, fill=Y)

        right_card = ttk.Labelframe(outer, text="Report Viewer", padding=12, bootstyle="primary")
        right_card.pack(side=LEFT, fill=BOTH, expand=YES, padx=(12, 0))

        self.report_list = tk.Listbox(
            left_card,
            width=42,
            height=28,
            bg="#132238",
            fg="#e8f1ff",
            selectbackground="#2a9fd6",
            selectforeground="white",
            relief="flat",
            highlightthickness=0,
        )
        self.report_list.pack(fill=Y, expand=NO)
        self.report_list.bind("<<ListboxSelect>>", self.on_report_selected)

        meta = ttk.Frame(right_card)
        meta.pack(fill=X, pady=(0, 8))
        self.report_kind_var = ttk.StringVar(value="Type: ")
        self.report_source_var = ttk.StringVar(value="Source: ")
        ttk.Label(meta, textvariable=self.report_kind_var, bootstyle="info").pack(anchor="w")
        ttk.Label(meta, textvariable=self.report_source_var, bootstyle="secondary").pack(anchor="w")

        self.report_text = tk.Text(
            right_card,
            wrap="word",
            height=20,
            bg="#122033",
            fg="#e9f2ff",
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        self.report_text.pack(fill=BOTH, expand=YES, pady=(8, 12))
        self.report_text.configure(state="disabled")

        self.report_path_var = ttk.StringVar(value="")
        ttk.Label(right_card, textvariable=self.report_path_var, bootstyle="secondary").pack(anchor="w")

    def toggle_theme(self):
        current = self.style.theme.name
        next_theme = "cyborg" if current == "superhero" else "superhero"
        self.style.theme_use(next_theme)
        self.status_var.set(f"Theme changed to {next_theme}")

    def set_summary(self, text: str):
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", text)
        self.summary_text.configure(state="disabled")

    def get_desktop_paths(self):
        paths = []
        user_desktop = Path.home() / "Desktop"
        public_desktop = Path(r"C:\Users\Public\Desktop")
        if user_desktop.exists():
            paths.append(user_desktop)
        if public_desktop.exists():
            paths.append(public_desktop)
        return paths

    def load_question_files(self):
        self.questions.clear()
        self.question_list.delete(0, "end")
        patterns = ("*.txt", "*.md", "*.text")

        for desktop in self.get_desktop_paths():
            for pattern in patterns:
                for file_path in desktop.glob(pattern):
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    lower_text = text.lower()
                    lower_name = file_path.name.lower()
                    if "this is a forensics question" in lower_text or "answer:" in lower_text or "forensics question" in lower_name:
                        self.questions.append({"path": file_path, "name": file_path.name, "content": text})
                        self.question_list.insert("end", file_path.name)
        self.card_questions.set_value(len(self.questions))

    def add_report_record(self, name, kind, source, content, origin):
        text_content = content if isinstance(content, str) else str(content or "")
        self.reports.append({
            "name": name,
            "kind": kind,
            "source": str(source),
            "content": text_content,
            "origin": str(origin),
            "content_length": len(text_content.strip()),
            "is_error": kind.lower() == "error",
        })
        self.report_list.insert("end", name)

    def load_report_files(self):
        self.reports.clear()
        self.report_list.delete(0, "end")
        seen_names = set()
        desktop_patterns = ("*.html", "*.htm", "*.url", "*.lnk")

        for desktop in self.get_desktop_paths():
            for pattern in desktop_patterns:
                for file_path in desktop.glob(pattern):
                    try:
                        suffix = file_path.suffix.lower()

                        if suffix in (".html", ".htm"):
                            if not looks_like_report_candidate(file_path.name, str(file_path)):
                                continue

                            raw = file_path.read_text(encoding="utf-8", errors="ignore")
                            name = file_path.stem
                            if name not in seen_names:
                                self.add_report_record(name, "Local HTML", file_path, html_to_text(raw), file_path)
                                seen_names.add(name)
                            continue

                        if suffix == ".url":
                            kind, resolved = resolve_url_shortcut(file_path)

                            if kind == "remote":
                                if not looks_like_report_candidate(file_path.name, resolved):
                                    continue

                                content = fetch_url_text(resolved)
                                name = file_path.stem
                                if name not in seen_names:
                                    self.add_report_record(name, "Remote URL", resolved, content, file_path)
                                    seen_names.add(name)

                            elif kind == "local":
                                if not looks_like_report_candidate(file_path.name, resolved):
                                    continue

                                if resolved.is_file() and resolved.suffix.lower() in (".html", ".htm", ".txt", ".md", ".text"):
                                    raw = resolved.read_text(encoding="utf-8", errors="ignore")
                                    content = html_to_text(raw) if resolved.suffix.lower() in (".html", ".htm") else raw
                                    name = file_path.stem
                                    if name not in seen_names:
                                        self.add_report_record(name, "Resolved URL Shortcut", resolved, content, file_path)
                                        seen_names.add(name)

                                elif resolved.is_dir():
                                    for candidate in find_report_candidates_in_directory(resolved):
                                        if not looks_like_report_candidate(candidate.name, str(candidate)):
                                            continue

                                        raw = candidate.read_text(encoding="utf-8", errors="ignore")
                                        name = f"{file_path.stem} -> {candidate.name}"
                                        if name not in seen_names:
                                            self.add_report_record(name, "Shortcut Directory Candidate", candidate, html_to_text(raw), file_path)
                                            seen_names.add(name)

                            else:
                                if not looks_like_report_candidate(file_path.name):
                                    continue

                                raw = file_path.read_text(encoding="utf-8", errors="ignore")
                                name = f"{file_path.stem} [unresolved .url]"
                                if name not in seen_names:
                                    self.add_report_record(name, "Unresolved URL Shortcut", file_path, raw, file_path)
                                    seen_names.add(name)

                            continue

                        if suffix == ".lnk":
                            resolved = resolve_lnk_shortcut(file_path)
                            if not resolved:
                                if not looks_like_report_candidate(file_path.name):
                                    continue

                                name = f"{file_path.stem} [unresolved .lnk]"
                                if name not in seen_names:
                                    self.add_report_record(name, "Unresolved LNK", file_path, "Unable to resolve shortcut target.", file_path)
                                    seen_names.add(name)
                                continue

                            target = (resolved.get("target") or "").strip()
                            args = (resolved.get("args") or "").strip()
                            working_dir = (resolved.get("working_dir") or "").strip()

                            if not looks_like_report_candidate(file_path.name, target, args, working_dir):
                                continue

                            name = file_path.stem

                            if target.lower().endswith((".html", ".htm", ".txt", ".md", ".text")) and Path(target).exists():
                                target_path = Path(target)
                                raw = target_path.read_text(encoding="utf-8", errors="ignore")
                                content = html_to_text(raw) if target_path.suffix.lower() in (".html", ".htm") else raw
                                if name not in seen_names:
                                    self.add_report_record(name, "Resolved LNK File", target_path, content, file_path)
                                    seen_names.add(name)

                            elif target and Path(target).is_dir():
                                for candidate in find_report_candidates_in_directory(Path(target)):
                                    if not looks_like_report_candidate(candidate.name, str(candidate)):
                                        continue

                                    raw = candidate.read_text(encoding="utf-8", errors="ignore")
                                    candidate_name = f"{name} -> {candidate.name}"
                                    if candidate_name not in seen_names:
                                        self.add_report_record(candidate_name, "LNK Directory Candidate", candidate, html_to_text(raw), file_path)
                                        seen_names.add(candidate_name)

                            elif target.lower().endswith(("msedge.exe", "chrome.exe", "firefox.exe", "opera.exe")):
                                possible = None
                                combined = f"{target} {args} {working_dir}".strip()
                                m = re.search(r'([A-Za-z]:\\[^\s"]+\\(?:index|report|results|score|scoring)[^\s"]*\.html?)', combined, re.I)
                                if m:
                                    possible = Path(m.group(1))

                                if possible and possible.exists():
                                    raw = possible.read_text(encoding="utf-8", errors="ignore")
                                    if name not in seen_names:
                                        self.add_report_record(name, "Browser Shortcut to Local Report", possible, html_to_text(raw), file_path)
                                        seen_names.add(name)
                                else:
                                    diagnostic = f"Shortcut target: {target}\nArguments: {args}\nWorking Dir: {working_dir}"
                                    if name not in seen_names:
                                        self.add_report_record(name, "Browser Shortcut", file_path, diagnostic, file_path)
                                        seen_names.add(name)

                            else:
                                diagnostic = f"Shortcut target: {target}\nArguments: {args}\nWorking Dir: {working_dir}"
                                if name not in seen_names:
                                    self.add_report_record(name, "Resolved LNK", file_path, diagnostic, file_path)
                                    seen_names.add(name)

                    except Exception as ex:
                        if looks_like_report_candidate(file_path.name):
                            name = f"{file_path.stem} [error]"
                            if name not in seen_names:
                                self.add_report_record(name, "Error", file_path, str(ex), file_path)
                                seen_names.add(name)

        self.card_reports.set_value(len(self.reports))


    def looks_like_valid_readme_content(self, text: str) -> bool:
            t = (text or "").strip()
            if not t:
                return False

            lower = t.lower()

            known_error_markers = (
                "<urlopen error",
                "getaddrinfo failed",
                "name or service not known",
                "temporary failure in name resolution",
                "404 not found",
                "403 forbidden",
                "500 internal server error",
                "unable to resolve shortcut target",
                "traceback (most recent call last)",
            )
            if any(marker in lower for marker in known_error_markers):
                return False

            if len(t) < 80:
                return False

            readme_markers = (
                "authorized users",
                "approved users",
                "valid users",
                "allowed users",
                "authorized accounts",
                "approved accounts",
                "allowed accounts",
                "authorized administrators",
                "scenario",
                "readme",
                "questions",
            )

            return any(marker in lower for marker in readme_markers)

    def score_readme_report(self, report: dict) -> int:
            score = 0
            name = (report.get("name") or "").lower()
            kind = (report.get("kind") or "").lower()
            content = report.get("content") or ""
            lower = content.lower()

            if "readme" in name:
                score += 60
            if kind in {"local html", "resolved url shortcut", "resolved lnk file", "shortcut directory candidate", "lnk directory candidate"}:
                score += 25
            if kind == "remote url":
                score += 10
            if report.get("is_error"):
                score -= 1000
            if "[error]" in name or "unresolved" in name:
                score -= 250

            if "authorized users" in lower:
                score += 80
            if "approved users" in lower or "allowed users" in lower or "authorized accounts" in lower:
                score += 60
            if "authorized administrators" in lower:
                score += 35
            if "scenario" in lower:
                score += 15

            score += min(len(content.strip()) // 40, 40)

            if not self.looks_like_valid_readme_content(content):
                score -= 300

            return score

    def looks_like_scoring_or_results_report(self, text: str) -> bool:
        t = (text or "").lower()
        if not t.strip():
            return False

        scoring_markers = (
            "score",
            "scoring",
            "results",
            "scorecard",
            "total score",
            "risk score",
            "assessment",
            "hours",
        )

        if any(marker in t for marker in scoring_markers):
            if self.looks_like_valid_readme_content(text):
                return False
            return True

        return False

    def get_readme_report_text(self) -> str:
        if self.manual_readme_text.strip():
            self.log_debug("Using manually loaded README text")
            return self.manual_readme_text

        if not self.reports:
            self.log_debug("get_readme_report_text: no reports loaded")
            return ""

        self.log_debug(f"get_readme_report_text: reports loaded = {len(self.reports)}")

        ranked = []

        for report in self.reports:
            name = report.get("name", "")
            kind = report.get("kind", "")
            content = report.get("content", "") or ""
            lower_name = name.lower()
            lower_kind = kind.lower()
            lower_content = content.lower()

            score = 0

            if "error" in lower_name or lower_kind == "error":
                score -= 1000
            if "unresolved" in lower_name or "unable to resolve shortcut target" in lower_content:
                score -= 1000
            if len(content.strip()) < 80:
                score -= 300

            if "readme" in lower_name:
                score += 500
            if "instruction" in lower_name or "instructions" in lower_name:
                score += 250
            if "authorized users" in lower_content:
                score += 400
            if "approved users" in lower_content or "allowed users" in lower_content:
                score += 250
            if "authorized accounts" in lower_content or "allowed accounts" in lower_content:
                score += 250
            if "local users" in lower_content or "domain users" in lower_content:
                score += 120
            if "administrators" in lower_content:
                score += 80

            if self.looks_like_scoring_or_results_report(content):
                score -= 500

            self.log_debug(f"Report candidate: name={name} kind={kind} len={len(content)} score={score}")
            ranked.append((score, report))

        ranked.sort(key=lambda x: x[0], reverse=True)

        for score, report in ranked:
            name = report.get("name", "")
            kind = report.get("kind", "")
            content = report.get("content", "") or ""
            if score <= 0:
                self.log_debug(f"Rejected README candidate: {name} ({kind}) score={score}")
                continue
            if self.looks_like_scoring_or_results_report(content):
                self.log_debug(f"Rejected README candidate: {name} ({kind}) looks like scoring/results content")
                continue

            self.user_readme_source_var.set(f"README source: {name}")
            self.log_debug(f"Selected README candidate: {name} ({kind}) score={score}")
            return content

        self.log_debug("No valid README report matched after scoring and validation")
        self.user_readme_source_var.set("README source: none found")
        return ""

    def readme_indicates_rdp_required(self) -> bool:
        text = (self.get_readme_report_text() or "").lower()
        if not text.strip():
            return False

        positive_patterns = (
            r"\brdp\b.*\b(required|needed|must be enabled|should be enabled|enable)\b",
            r"\bremote desktop\b.*\b(required|needed|must be enabled|should be enabled|enable)\b",
            r"\bconnect remotely\b.*\b(required|needed)\b",
        )
        negative_patterns = (
            r"\brdp\b.*\b(disabled|disable|must be disabled|should be disabled)\b",
            r"\bremote desktop\b.*\b(disabled|disable|must be disabled|should be disabled)\b",
        )

        if any(re.search(p, text, re.I) for p in negative_patterns):
            return False
        return any(re.search(p, text, re.I) for p in positive_patterns)

    def analyze_users_from_readme(self):
        self.user_summary_var.set("Analyzing users...")
        self.root.update_idletasks()
        self.log_debug("=== Analyze Users clicked ===")

        try:
            readme_text = self.get_readme_report_text()
            self.log_debug(f"README text length: {len(readme_text)}")

            if not readme_text.strip():
                self.user_summary_var.set("No valid README report found.")
                self.card_users.set_value(0)
                self.log_debug("No valid README report text found.")
                messagebox.showwarning(
                    "README not found",
                    "No valid README/instructions file with authorized users could be found.\n\n"
                    "Use 'Load README File' on the Users tab and select the real README manually."
                )
                return

            if self.looks_like_scoring_or_results_report(readme_text):
                self.user_summary_var.set("Selected file looks like a scoring report, not a README.")
                self.card_users.set_value(0)
                self.log_debug("Rejected selected README text because it looks like scoring/results content.")
                messagebox.showwarning(
                    "Wrong file type",
                    "The selected content looks like a scoring/results report, not a README with authorized users.\n\n"
                    "Load the actual README or instructions file."
                )
                return

            preview = "\n".join(readme_text.splitlines()[:40])
            self.log_debug("README preview:")
            self.log_debug(preview)
            self.log_debug("README tail preview:")
            self.log_debug("\n".join(readme_text.splitlines()[40:90]))

            audit = compare_users_against_authorized(readme_text)
            self.user_audit = audit

            self.log_debug(f"DomainUsers count: {len(audit.get('Inventory', {}).get('DomainUsers', []))}")
            self.log_debug(f"IsDomainController: {audit.get('Inventory', {}).get('IsDomainController')}")
            self.log_debug(f"DomainAdminCandidates count: {len(audit.get('Inventory', {}).get('DomainAdminCandidates', []))}")
            self.log_debug(f"Authorized users parsed: {audit.get('AuthorizedUsers', [])}")
            self.log_debug(f"LocalUsers count: {len(audit.get('Inventory', {}).get('LocalUsers', []))}")
            self.log_debug(f"Administrators count: {len(audit.get('Inventory', {}).get('Administrators', []))}")

            for item in self.users_tree.get_children():
                self.users_tree.delete(item)

            results = audit.get("Results", [])
            inventory = audit.get("Inventory", {})
            authorized = audit.get("AuthorizedUsers", [])

            if not authorized:
                self.user_summary_var.set("README found, but no authorized users were parsed.")
                self.card_users.set_value(0)
                self.log_debug("Authorized list is empty after parsing a valid README.")
                messagebox.showwarning(
                    "No authorized users parsed",
                    "A README candidate was found, but no authorized users were extracted.\n"
                    "This usually means the parser rules in users_audit.py need to be broadened."
                )
                return

            unexpected_users = 0
            unexpected_admins = 0

            for row in results:
                if row.get("Unexpected"):
                    unexpected_users += 1
                if row.get("Unexpected") and row.get("IsAdmin"):
                    unexpected_admins += 1

                if row.get("Unexpected") and row.get("IsAdmin"):
                    tag = "High"
                elif row.get("Unexpected"):
                    tag = "Medium"
                elif row.get("IsAdmin"):
                    tag = "Low"
                else:
                    tag = "Info"

                self.users_tree.insert(
                    "",
                    "end",
                    values=(
                        "Yes" if row.get("Unexpected") else "No",
                        "Yes" if row.get("IsAdmin") else "No",
                        "Yes" if row.get("Authorized") else "No",
                        "Yes" if row.get("Enabled") else "No",
                        row.get("Name", ""),
                        row.get("Identity", ""),
                        row.get("PrincipalSource", ""),
                    ),
                    tags=(tag,),
                )

            self.user_summary_var.set(
                f"Authorized in README: {len(authorized)} | "
                f"Accounts analysed: {len(results)} | "
                f"Unexpected users: {unexpected_users} | "
                f"Unexpected admins: {unexpected_admins} | "
                f"Domain joined: {bool(inventory.get('PartOfDomain', False))} | "
                f"Domain users: {len(inventory.get('DomainUsers', []))}"
            )

            self.card_users.set_value(unexpected_users)
            self.status_var.set("User audit complete")
            self.populate_actions()

            if not results:
                self.log_debug("No user inventory rows returned.")
                messagebox.showwarning(
                    "No user inventory returned",
                    "Authorized users were parsed, but no current users/admins were returned from PowerShell."
                )

        except Exception as ex:
            self.user_summary_var.set("User audit failed.")
            self.status_var.set("User audit failed")
            self.log_debug("EXCEPTION in analyze_users_from_readme:")
            self.log_debug(str(ex))
            self.log_debug(traceback.format_exc())
            messagebox.showerror("User audit failed", str(ex))

    def on_question_selected(self, _event=None):
        if not self.question_list.curselection():
            return
        idx = self.question_list.curselection()[0]
        q = self.questions[idx]
        content = q["content"]
        question_body = content
        answer_text = ""
        m = re.search(r"(?ms)^(.*?)(?:^ANSWER:\s*(.*)\s*$)", content)
        if m:
            question_body = m.group(1).rstrip()
            answer_text = m.group(2).strip()
        self.question_text.configure(state="normal")
        self.question_text.delete("1.0", "end")
        self.question_text.insert("1.0", question_body)
        self.question_text.configure(state="disabled")
        self.answer_var.set(answer_text)
        self.question_path_var.set(str(q["path"]))

    def on_report_selected(self, _event=None):
        if not self.report_list.curselection():
            return
        idx = self.report_list.curselection()[0]
        report = self.reports[idx]
        self.report_kind_var.set(f"Type: {report['kind']}")
        self.report_source_var.set(f"Source: {report['source']}")
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", report["content"])
        self.report_text.configure(state="disabled")
        self.report_path_var.set(f"Origin: {report['origin']}")

    def save_current_answer(self, _event=None):
        if not self.question_list.curselection():
            messagebox.showwarning("No question selected", "Select a question first.")
            return
        idx = self.question_list.curselection()[0]
        q = self.questions[idx]
        answer = self.answer_var.get()
        try:
            original = q["path"].read_text(encoding="utf-8", errors="ignore")
            if re.search(r"(?m)^ANSWER:.*$", original):
                updated = re.sub(r"(?m)^ANSWER:.*$", f"ANSWER: {answer}", original)
            else:
                updated = original.rstrip() + f"\n\nANSWER: {answer}\n"
            q["path"].write_text(updated, encoding="utf-8")
            q["content"] = updated
            self.status_var.set(f"Saved answer to {q['name']}")
            messagebox.showinfo("Saved", f"Updated:\n{q['path']}")
        except Exception as ex:
            messagebox.showerror("Save failed", str(ex))

    def populate_tasks(self):
        for item in self.tasks_tree.get_children():
            self.tasks_tree.delete(item)
        for task in sorted(self.tasks, key=lambda x: x.get("Score", 0), reverse=True):
            sev = task.get("Severity", "Info")
            self.tasks_tree.insert(
                "",
                "end",
                values=(
                    task.get("Severity", ""),
                    task.get("Score", ""),
                    task.get("TaskName", ""),
                    task.get("TaskPath", ""),
                    task.get("UserId", ""),
                    task.get("CommandLine", ""),
                ),
                tags=(sev,),
            )
        self.card_tasks.set_value(sum(1 for t in self.tasks if t.get("Severity") in {"Medium", "High"}))

    def populate_registry(self):
        for item in self.registry_tree.get_children():
            self.registry_tree.delete(item)
        for entry in sorted(self.registry_entries, key=lambda x: x.get("Score", 0), reverse=True):
            sev = entry.get("Severity", "Info")
            self.registry_tree.insert(
                "",
                "end",
                values=(
                    entry.get("Severity", ""),
                    entry.get("Score", ""),
                    entry.get("RegistryPath", ""),
                    entry.get("ValueName", ""),
                    entry.get("ValueData", ""),
                ),
                tags=(sev,),
            )
        self.card_registry.set_value(sum(1 for r in self.registry_entries if r.get("Suspicious")))

    def populate_apps(self):
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)
        for app in sorted(self.apps, key=lambda x: (not x.get("LikelyNonDefault", False), x.get("DisplayName", ""))):
            tag = "Likely" if app.get("LikelyNonDefault") else "Default"
            self.apps_tree.insert(
                "",
                "end",
                values=(
                    "Yes" if app.get("LikelyNonDefault") else "No",
                    app.get("DisplayName", ""),
                    app.get("DisplayVersion", ""),
                    app.get("Publisher", ""),
                    app.get("InstallLocation", ""),
                ),
                tags=(tag,),
            )
        self.card_apps.set_value(sum(1 for a in self.apps if a.get("LikelyNonDefault")))

    def render_recipe_command(self, recipe_id: str, **kwargs) -> str:
        recipe = ACTION_RECIPES.get(recipe_id)
        if not recipe:
            return ""
        try:
            return recipe.powershell.format(**kwargs)
        except Exception:
            return recipe.powershell

    def add_action(self, bucket: list, recipe_id: str, source: str, source_name: str, reason: str, severity=None, safe_default=None, readme_required=False, **kwargs):
        recipe = ACTION_RECIPES.get(recipe_id)
        if not recipe:
            return
        bucket.append({
            "RecipeId": recipe.id,
            "Source": source,
            "SourceName": source_name,
            "Severity": severity or recipe.severity,
            "Title": recipe.title,
            "Description": recipe.description,
            "PowerShell": self.render_recipe_command(recipe_id, **kwargs),
            "SafeDefault": recipe.safe_default if safe_default is None else safe_default,
            "Reason": reason,
            "ReadmeRequired": bool(readme_required),
        })

    def build_actions_from_findings(self):
        actions = []
        rdp_required = self.readme_indicates_rdp_required()

        # Add prebake actions
        self.add_action(
            actions,
            "misc_reg_keys",
            source="Prebake",
            source_name="Misc Registry Keys",
            reason="Apply security hardening registry settings: LSA protection, printer web PnP, autorun restrictions, and Windows Update automatic startup.",
            severity="Medium",
            safe_default=True,
        )

        self.add_action(
            actions,
            "install_gemini_cli",
            source="Prebake",
            source_name="Gemini CLI",
            reason="Install Node.js and npm if needed, update npm, then install Google Gemini CLI globally with API credentials.",
            severity="Medium",
            safe_default=False,
        )

        for task in self.tasks:
            if task.get("Suspicious"):
                self.add_action(
                    actions,
                    "task_disable",
                    source="Task",
                    source_name=f"{task.get('TaskPath', '')}{task.get('TaskName', '')}",
                    reason=f"Suspicious scheduled task: {task.get('CommandLine', '')}",
                    severity=task.get("Severity", "High"),
                    safe_default=False,
                    task_path=task.get("TaskPath", "\\"),
                    task_name=task.get("TaskName", ""),
                )

        for entry in self.registry_entries:
            if entry.get("Suspicious"):
                path = entry.get("RegistryPath", "")
                name = entry.get("ValueName", "")
                if path and name:
                    self.add_action(
                        actions,
                        "registry_remove_value",
                        source="Registry",
                        source_name=f"{path} :: {name}",
                        reason=f"Suspicious persistence value: {entry.get('ValueData', '')}",
                        severity=entry.get("Severity", "High"),
                        safe_default=False,
                        registry_path=path,
                        value_name=name,
                    )

        for row in self.user_audit.get("Results", []):
            if not row.get("Unexpected"):
                continue

            if row.get("IsAdmin"):
                self.add_action(
                    actions,
                    "user_remove_admin",
                    source="User",
                    source_name=row.get("Name", "") or row.get("Identity", ""),
                    reason="Unexpected account is a local administrator.",
                    severity="High",
                    safe_default=False,
                    identity=row.get("Identity", row.get("Name", "")),
                )

            if row.get("PrincipalSource", "").lower() != "activedirectory":
                self.add_action(
                    actions,
                    "user_disable",
                    source="User",
                    source_name=row.get("Name", "") or row.get("Identity", ""),
                    reason="Unexpected local account found during README comparison.",
                    severity="High" if row.get("IsAdmin") else "Medium",
                    safe_default=False,
                    user_name=row.get("Name", ""),
                )

        for gpo in self.gpos:
            for finding in gpo.get("Findings", []):
                title = (finding.get("Title") or "").lower()
                detail = finding.get("Detail", "")
                src_name = gpo.get("DisplayName", "")

                if "firewall disabled" in title:
                    self.add_action(actions, "enable_firewall", "GPO", src_name, detail)

                elif "defender disabled" in title or "real-time protection disabled" in title:
                    self.add_action(actions, "enable_defender_realtime", "GPO", src_name, detail)

                elif "uac weakened" in title:
                    self.add_action(actions, "enable_uac_admin_approval", "GPO", src_name, detail)

                elif "rdp without nla" in title:
                    self.add_action(actions, "set_rdp_nla", "GPO", src_name, detail, readme_required=rdp_required)
                    if not rdp_required:
                        self.add_action(actions, "disable_rdp", "GPO", src_name, "RDP is enabled; disabling it is an optional stronger remediation.", safe_default=False)

                elif title == "rdp enabled":
                    self.add_action(actions, "set_rdp_nla", "GPO", src_name, detail, readme_required=rdp_required, safe_default=True)
                    if not rdp_required:
                        self.add_action(actions, "disable_rdp", "GPO", src_name, "RDP is enabled by policy; disabling it is optional.", safe_default=False)

                elif "weak lan manager auth" in title:
                    pass

                elif "smb client signing not required" in title:
                    self.add_action(actions, "require_smb_client_signing", "GPO", src_name, detail)

                elif "smb server signing not required" in title:
                    self.add_action(actions, "require_smb_server_signing", "GPO", src_name, detail)

                elif "anonymous enumeration allowed" in title:
                    self.add_action(actions, "disable_anonymous_enumeration", "GPO", src_name, detail)

                elif "anonymous users overly permitted" in title:
                    self.add_action(actions, "disable_anonymous_everyone", "GPO", src_name, detail)

                elif "weak password length" in title:
                    self.add_action(actions, "set_min_password_length_12", "GPO", src_name, detail, safe_default=False)

                elif "password complexity disabled" in title:
                    self.add_action(actions, "enable_password_complexity", "GPO", src_name, detail, safe_default=False)

                elif "no account lockout" in title or "weak account lockout threshold" in title:
                    self.add_action(actions, "set_lockout_threshold_10", "GPO", src_name, detail, safe_default=False)

                elif "permissive powershell execution" in title or "powershell scripts allowed" in title:
                    self.add_action(actions, "set_execpolicy_remotesigned", "GPO", src_name, detail, safe_default=False)

        deduped = []
        seen = set()
        for a in actions:
            key = (a["RecipeId"], a["Source"], a["SourceName"], a["PowerShell"])
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        if self.hide_readme_required_var.get():
            deduped = [a for a in deduped if not a.get("ReadmeRequired")]

        deduped.sort(key=lambda x: (
            x.get("Severity") != "High",
            not x.get("SafeDefault", False),
            x.get("Source", ""),
            x.get("Title", "").lower(),
        ))
        return deduped

    def get_action_category(self, action):
        """Determine which category tab an action belongs to."""
        source = action.get("Source", "")
        if source == "User":
            return "Users"
        elif source == "Task":
            return "Tasks"
        elif source == "Prebake":
            return "Prebake"
        else:
            return "Other"

    def populate_actions(self):
        self.actions = self.build_actions_from_findings()

        # Clear all trees
        for tree in self.action_trees.values():
            for item in tree.get_children():
                tree.delete(item)

        # Organize actions into categories
        categorized = {cat: [] for cat in ["Users", "Tasks", "Other", "Prebake"]}
        for idx, action in enumerate(self.actions):
            cat = self.get_action_category(action)
            categorized[cat].append((idx, action))

        # Populate each category's tree
        for category, items in categorized.items():
            tree = self.action_trees[category]
            for idx, action in items:
                sev = action.get("Severity", "Info")
                tag = "High" if sev == "High" else "Medium" if sev == "Medium" else "Low" if sev == "Low" else "Info"
                tree.insert(
                    "",
                    "end",
                    iid=f"action_{idx}",
                    values=(
                        action.get("Severity", ""),
                        "Yes" if action.get("SafeDefault") else "No",
                        action.get("SourceName", action.get("Source", "")),
                        action.get("Title", ""),
                        action.get("Reason", ""),
                    ),
                    tags=(tag,),
                )

        safe_count = sum(1 for a in self.actions if a.get("SafeDefault"))
        self.actions_summary_var.set(f"Actions: {len(self.actions)} | Safe-by-default: {safe_count}")

        self.action_detail_text.configure(state="normal")
        self.action_detail_text.delete("1.0", "end")
        self.action_detail_text.insert("1.0", "Select an action to see details.")
        self.action_detail_text.configure(state="disabled")

    def on_action_selected(self, _event=None):
        # Find which tree has a selection
        selected_iid = None
        for tree in self.action_trees.values():
            if tree.selection():
                selected_iid = tree.selection()[0]
                break

        if not selected_iid:
            return

        try:
            idx = int(selected_iid.split("_", 1)[1])
        except Exception:
            return

        if idx < 0 or idx >= len(self.actions):
            return

        a = self.actions[idx]
        lines = [
            f"Title: {a.get('Title', '')}",
            f"Severity: {a.get('Severity', '')}",
            f"Source: {a.get('Source', '')}",
            f"Source Name: {a.get('SourceName', '')}",
            f"Safe by default: {'Yes' if a.get('SafeDefault') else 'No'}",
            f"Hidden when README-required: {'Yes' if a.get('ReadmeRequired') else 'No'}",
            "",
            "Reason:",
            a.get("Reason", ""),
            "",
            "Description:",
            a.get("Description", ""),
            "",
            "PowerShell:",
            a.get("PowerShell", ""),
        ]

        self.action_detail_text.configure(state="normal")
        self.action_detail_text.delete("1.0", "end")
        self.action_detail_text.insert("1.0", "\n".join(lines))
        self.action_detail_text.configure(state="disabled")

    def get_selected_action_indexes(self):
        indices = []
        # Check all trees in each category
        for tree in self.action_trees.values():
            for iid in tree.selection():
                try:
                    indices.append(int(iid.split("_", 1)[1]))
                except Exception:
                    continue
        return [i for i in indices if 0 <= i < len(self.actions)]

    def copy_selected_action_command(self):
        indices = self.get_selected_action_indexes()
        if not indices:
            messagebox.showwarning("No action selected", "Select an action first.")
            return
        cmd = self.actions[indices[0]].get("PowerShell", "")
        if not cmd.strip():
            messagebox.showwarning("No command", "The selected action has no command text.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        self.status_var.set("Action command copied to clipboard")

    def run_powershell_action(self, script_text: str) -> tuple[bool, str]:
        try:
            script = rf"""
$ErrorActionPreference = 'Stop'
try {{
    {script_text}
    [pscustomobject]@{{
        Success = $true
        Message = 'OK'
    }} | ConvertTo-Json -Depth 4 -Compress
}} catch {{
    [pscustomobject]@{{
        Success = $false
        Message = $_.Exception.Message
    }} | ConvertTo-Json -Depth 4 -Compress
}}
"""
            result = run_powershell_json(script)
            if isinstance(result, dict):
                return bool(result.get("Success", False)), str(result.get("Message", ""))
            return False, "Unexpected response from PowerShell helper."
        except Exception as ex:
            return False, str(ex)

    def run_selected_actions(self):
        indices = self.get_selected_action_indexes()
        if not indices:
            messagebox.showwarning("No selection", "Select one or more actions first.")
            return

        if not messagebox.askyesno(
            "Confirm remediation",
            f"Run {len(indices)} selected remediation action(s)?\n\nThese actions will modify the current Windows system.",
        ):
            return

        ok = 0
        failed = 0
        for idx in indices:
            action = self.actions[idx]
            success, message = self.run_powershell_action(action.get("PowerShell", ""))
            if success:
                ok += 1
                self.log_debug(f"[ACTION OK] {action.get('Title')} :: {message}")
            else:
                failed += 1
                self.log_debug(f"[ACTION FAIL] {action.get('Title')} :: {message}")

        self.status_var.set(f"Remediation complete: {ok} succeeded, {failed} failed")
        messagebox.showinfo("Remediation complete", f"Succeeded: {ok}\nFailed: {failed}\n\nSee Debug for details.")

    def run_all_safe_actions(self):
        safe_indices = [i for i, a in enumerate(self.actions) if a.get("SafeDefault")]
        if not safe_indices:
            messagebox.showinfo("No safe actions", "There are no safe-by-default actions available.")
            return

        if not messagebox.askyesno(
            "Confirm safe remediation",
            f"Run all {len(safe_indices)} safe-by-default remediation action(s)?",
        ):
            return

        ok = 0
        failed = 0
        for idx in safe_indices:
            action = self.actions[idx]
            success, message = self.run_powershell_action(action.get("PowerShell", ""))
            if success:
                ok += 1
                self.log_debug(f"[ACTION OK] {action.get('Title')} :: {message}")
            else:
                failed += 1
                self.log_debug(f"[ACTION FAIL] {action.get('Title')} :: {message}")

        self.status_var.set(f"Safe remediation complete: {ok} succeeded, {failed} failed")
        messagebox.showinfo("Safe remediation complete", f"Succeeded: {ok}\nFailed: {failed}\n\nSee Debug for details.")

    def scan_all(self):
        try:
            self.status_var.set("Loading question files...")
            self.root.update_idletasks()
            self.load_question_files()

            self.status_var.set("Loading report files...")
            self.root.update_idletasks()
            self.load_report_files()

            self.status_var.set("Collecting scheduled tasks...")
            self.root.update_idletasks()
            self.tasks = get_tasks()

            self.status_var.set("Collecting registry persistence...")
            self.root.update_idletasks()
            self.registry_entries = get_registry_entries()

            self.status_var.set("Collecting installed programs...")
            self.root.update_idletasks()
            self.apps = get_installed_programs()

            self.populate_tasks()
            self.populate_registry()
            self.populate_apps()

            try:
                self.analyze_users_from_readme()
            except Exception:
                pass

            suspicious_tasks = sum(1 for t in self.tasks if t.get("Suspicious"))
            suspicious_registry = sum(1 for r in self.registry_entries if r.get("Suspicious"))
            likely_non_default = sum(1 for a in self.apps if a.get("LikelyNonDefault"))
            unexpected_users = sum(1 for r in self.user_audit.get("Results", []) if r.get("Unexpected"))

            summary = (
                f"Questions found: {len(self.questions)}\n"
                f"Reports found: {len(self.reports)}\n"
                f"Scheduled tasks: {len(self.tasks)} total, {suspicious_tasks} suspicious\n"
                f"Registry persistence entries: {len(self.registry_entries)} total, {suspicious_registry} suspicious\n"
                f"Installed programs: {len(self.apps)} total, {likely_non_default} likely non-default\n"
                f"User audit: {unexpected_users} unexpected accounts\n\n"
                f"Notes:\n"
                f"- Reports support remote .url targets, local HTML, and .lnk shortcut resolution.\n"
                f"- Browser shortcuts may display diagnostic metadata if a local HTML path cannot be extracted.\n"
                f"- Task and registry scores are heuristic.\n"
                f"- Installed-program filtering is an approximation, not a guarantee.\n"
                f"- User audit compares README-authorized users to local accounts and Administrators membership."
            )
            self.set_summary(summary)
            self.status_var.set("Scan complete")
        except Exception as ex:
            self.status_var.set("Scan failed")
            messagebox.showerror("Scan failed", str(ex))

        try:
            self.analyze_gpos()
        except Exception:
            pass

        try:
            self.populate_actions()
        except Exception:
            pass


def main():
    root = ttk.Window(themename=APP_THEME)
    ForensicsToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()