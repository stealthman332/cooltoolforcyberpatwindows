import json
import re
import subprocess


DEFAULT_PUBLISHER_PATTERNS = [
    r"^Microsoft( Corporation)?$",
    r"^Microsoft Windows$",
    r"^NVIDIA Corporation$",
    r"^Intel( Corporation)?$",
    r"^Advanced Micro Devices, Inc\.?$",
    r"^Realtek",
    r"^Qualcomm",
    r"^Dell",
    r"^HP",
    r"^Lenovo",
    r"^ASUSTeK",
    r"^Acer",
    r"^MSI",
    r"^LG Electronics",
    r"^Synaptics",
    r"^OEM",
    r"^Canon",
    r"^EPSON",
    r"^Brother",
]
KNOWN_GOOD_TASK_PATTERNS = [
    r"^\\Microsoft\\Windows\\Application Experience\\.*$",
    r"^\\Microsoft\\Windows\\AppID\\.*$",
    r"^\\Microsoft\\Windows\\AppxDeploymentClient\\.*$",
    r"^\\Microsoft\\Windows\\Autochk\\.*$",
    r"^\\Microsoft\\Windows\\BitLocker\\.*$",
    r"^\\Microsoft\\Windows\\CertificateServicesClient\\.*$",
    r"^\\Microsoft\\Windows\\Chkdsk\\.*$",
    r"^\\Microsoft\\Windows\\Customer Experience Improvement Program\\.*$",
    r"^\\Microsoft\\Windows\\Data Integrity Scan\\.*$",
    r"^\\Microsoft\\Windows\\Defrag\\.*$",
    r"^\\Microsoft\\Windows\\Diagnosis\\.*$",
    r"^\\Microsoft\\Windows\\DiskCleanup\\.*$",
    r"^\\Microsoft\\Windows\\DiskDiagnostic\\.*$",
    r"^\\Microsoft\\Windows\\FileHistory\\.*$",
    r"^\\Microsoft\\Windows\\Maintenance\\.*$",
    r"^\\Microsoft\\Windows\\MemoryDiagnostic\\.*$",
    r"^\\Microsoft\\Windows\\Mobile Broadband Accounts\\.*$",
    r"^\\Microsoft\\Windows\\NetTrace\\.*$",
    r"^\\Microsoft\\Windows\\PLA\\.*$",
    r"^\\Microsoft\\Windows\\Plug and Play\\.*$",
    r"^\\Microsoft\\Windows\\Power Efficiency Diagnostics\\.*$",
    r"^\\Microsoft\\Windows\\Registry\\.*$",
    r"^\\Microsoft\\Windows\\RemoteAssistance\\.*$",
    r"^\\Microsoft\\Windows\\Servicing\\.*$",
    r"^\\Microsoft\\Windows\\SettingSync\\.*$",
    r"^\\Microsoft\\Windows\\SharedPC\\.*$",
    r"^\\Microsoft\\Windows\\SoftwareInventoryLogging\\.*$",
    r"^\\Microsoft\\Windows\\SpacePort\\.*$",
    r"^\\Microsoft\\Windows\\TaskScheduler\\.*$",
    r"^\\Microsoft\\Windows\\Time Synchronization\\.*$",
    r"^\\Microsoft\\Windows\\TPM\\.*$",
    r"^\\Microsoft\\Windows\\UNP\\.*$",
    r"^\\Microsoft\\Windows\\WDI\\.*$",
    r"^\\Microsoft\\Windows\\Windows Defender\\.*$",
    r"^\\Microsoft\\Windows\\Windows Error Reporting\\.*$",
    r"^\\Microsoft\\Windows\\Workplace Join\\.*$",
    r"^\\Microsoft\\Windows\\.NET Framework\\.*$",
]

KNOWN_GOOD_COMMAND_PATTERNS = [
    r"(?i)\b%windir%\\system32\\defrag\.exe\b",
    r"(?i)\b%windir%\\system32\\rundll32\.exe\b.*\b(shell32|dfdwiz|appxdeploymentclient|adproxy|pla|regidle|bfe)\b",
    r"(?i)\b%windir%\\system32\\mrt\.exe\b",
    r"(?i)\b%windir%\\system32\\schtasks\.exe\b",
    r"(?i)\b%windir%\\system32\\svchost\.exe\b",
    r"(?i)\b%windir%\\system32\\w32tm\.exe\b",
    r"(?i)\b%windir%\\system32\\wermgr\.exe\b",
    r"(?i)\b%windir%\\system32\\wsqmcons\.exe\b",
    r"(?i)\b%windir%\\system32\\rundll32\.exe\b.*\bwindows\.sharedpc\.accountmanager\.dll\b",
    r"(?i)\b%windir%\\system32\\rundll32\.exe\b.*\bstorageapplicationdata\.dll\b",
    r"(?i)\b%systemroot%\\system32\\cleanmgr\.exe\b",
    r"(?i)\b%systemroot%\\system32\\cscript\.exe\b.*\bcaluxxprovider\.vbs\b",
    r"(?i)\b%systemroot%\\system32\\sihclient\.exe\b",
    r"(?i)\b%systemroot%\\system32\\winsat\.exe\b",
    r"(?i)\bc:\\programdata\\microsoft\\windows defender\\platform\\.*\\mpcmdrun\.exe\b",
]

STRONG_SUSPICIOUS_PATTERNS = [
    r"(?i)\b-enc(?:odedcommand)?\b",
    r"(?i)frombase64string",
    r"(?i)\binvoke-expression\b",
    r"(?i)\biex\b",
    r"(?i)\bdownloadstring\b",
    r"(?i)\bdownloadfile\b",
    r"(?i)\binvoke-webrequest\b",
    r"(?i)\binvoke-restmethod\b",
    r"(?i)\biwr\b",
    r"(?i)\birm\b",
    r"(?i)\bhttps?://",
    r"(?i)\\\\[^\\]+\\",
]

BENIGN_SYSTEM_PATH_RE = re.compile(
    r"(?i)(^|[ \"'])((%windir%|%systemroot%)\\(system32|syswow64)\\|c:\\windows\\(system32|syswow64)\\)"
)

USER_WRITABLE_PATH_RE = re.compile(
    r"(?i)(\\users\\public\\|\\programdata\\|\\temp\\|\\appdata\\|\\perflogs\\|\\windows\\tasks\\|\\recycle\.bin\\)"
)

DEFAULT_NAME_PATTERNS = [
    r"^(Microsoft Visual C\+\+|Microsoft Update Health Tools|Microsoft Edge|Microsoft OneDrive|Microsoft Teams|Windows Driver Package|Intel\(|NVIDIA|AMD Software|Realtek|Dell Support|HP Support|Lenovo Vantage)"
]

SUSPICIOUS_SHELL = re.compile(r"(powershell|pwsh|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe)", re.I)
SUSPICIOUS_PATH = re.compile(r"(\\Users\\Public\\|\\ProgramData\\|\\Temp\\|\\AppData\\|\\Perflogs\\|\\Windows\\Tasks\\|\\Recycle\.Bin\\)", re.I)
ENCODED = re.compile(r"(-enc\b|-encodedcommand\b|frombase64string|iex\b|invoke-expression|invoke-command)", re.I)
NETWORK = re.compile(r"(https?://|ftp://|\\\\|downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|iwr\b|irm\b)", re.I)
HIDDEN_EXEC = re.compile(r"(-w hidden|-windowstyle hidden|-nop\b|-noni\b|-executionpolicy bypass)", re.I)
SYSTEMLIKE = re.compile(r"(svchost32|chromeupdate|telemetryupdater|updater|securityhealth|runtimebroker)", re.I)


def run_powershell_json(script: str):
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        script,
    ]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell command failed")

    raw = completed.stdout.strip()
    if not raw:
        return []

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"Failed to parse PowerShell JSON output:\n{raw[:1000]}")


def get_severity(score: int) -> str:
    if score >= 6:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Info"


def score_task(task: dict):
    reasons = []
    score = 0

    cmd = (task.get("CommandLine") or "").strip()
    task_path = task.get("TaskPath", "") or ""
    task_name = task.get("TaskName", "") or ""
    full_name = f"{task_path}{task_name}"
    author = str(task.get("Author", "") or "")
    user_id = str(task.get("UserId", "") or "")
    run_level = str(task.get("RunLevel", "") or "")
    trigger_text = " | ".join(task.get("Triggers", []) or [])

    in_microsoft_tree = bool(re.match(r"^\\Microsoft\\Windows\\", full_name, re.I))
    microsoft_authored = bool(re.search(r"microsoft", author, re.I))
    command_is_system = bool(BENIGN_SYSTEM_PATH_RE.search(cmd))
    command_user_writable = bool(USER_WRITABLE_PATH_RE.search(cmd))

    # Hard allowlist for common in-box tasks
    for pat in KNOWN_GOOD_TASK_PATTERNS:
        if re.match(pat, full_name, re.I):
            if not command_user_writable and not any(re.search(p, cmd, re.I) for p in STRONG_SUSPICIOUS_PATTERNS):
                task["Score"] = 0
                task["Severity"] = "Info"
                task["Reasons"] = ["Known Microsoft maintenance task"]
                task["Suspicious"] = False
                return task

    # Soft allowlist for common Microsoft/system command lines
    for pat in KNOWN_GOOD_COMMAND_PATTERNS:
        if re.search(pat, cmd, re.I):
            if in_microsoft_tree or microsoft_authored:
                task["Score"] = 0
                task["Severity"] = "Info"
                task["Reasons"] = ["Known Microsoft/system command line"]
                task["Suspicious"] = False
                return task

    # Strong indicators
    if task.get("Hidden") is True:
        score += 2
        reasons.append("Task is hidden")

    if "highest" in run_level.lower():
        score += 1
        reasons.append("Runs with highest privileges")

    if re.search(r"SYSTEM|LOCAL SERVICE|NETWORK SERVICE", user_id, re.I):
        # SYSTEM alone is very common, so only add a light reason
        score += 0.5
        reasons.append(f"Runs as privileged account: {user_id}")

    if SUSPICIOUS_SHELL.search(cmd):
        score += 1
        reasons.append("Uses a shell or script host")

    if command_user_writable:
        score += 2
        reasons.append("Executes from a user-writable or unusual path")

    if ENCODED.search(cmd):
        score += 3
        reasons.append("Contains encoded or obfuscated PowerShell indicators")

    if NETWORK.search(cmd):
        score += 2
        reasons.append("Contains network path or URL in action")

    if HIDDEN_EXEC.search(cmd):
        score += 2
        reasons.append("Uses hidden or bypass-style execution flags")

    if SYSTEMLIKE.search(task_name):
        # Very light weight by itself
        score += 0.5
        reasons.append("Task name mimics system or updater naming")

    if re.match(r"^[A-Za-z0-9]{6,}$", task_name) and re.search(r"[A-Z]", task_name) and re.search(r"[a-z]", task_name) and re.search(r"\d", task_name):
        if not in_microsoft_tree:
            score += 1
            reasons.append("Task name appears randomized")

    if re.search(r"LogonTrigger|BootTrigger", trigger_text, re.I):
        score += 1
        reasons.append("Uses persistence-style trigger")

    if re.search(r"PT([1-9]M|1[0-5]M)", trigger_text, re.I):
        score += 1
        reasons.append("Repeats frequently")

    # Only lightly penalize non-Microsoft task path if other weirdness exists
    if not in_microsoft_tree and score >= 2:
        score += 1
        reasons.append("Task is outside standard Microsoft task path")

    # If it is Microsoft/in-box and only has weak reasons, de-escalate
    if (in_microsoft_tree or microsoft_authored or command_is_system) and score <= 2:
        task["Score"] = 0
        task["Severity"] = "Info"
        task["Reasons"] = ["Looks like standard Microsoft/system scheduled task"]
        task["Suspicious"] = False
        return task

    final_score = int(score) if score == int(score) else int(score + 0.5)

    task["Score"] = final_score
    task["Severity"] = get_severity(final_score)
    task["Reasons"] = reasons
    task["Suspicious"] = final_score > 0
    return task


def score_registry(entry: dict):
    reasons = []
    reg_path = entry.get("RegistryPath", "")
    value_name = entry.get("ValueName", "")
    value_data = entry.get("ValueData", "")

    if re.search(r"\\CurrentVersion\\Run(Once|OnceEx)?$|\\Policies\\Explorer$|\\Winlogon$|\\Windows$|\\Session Manager$", reg_path, re.I):
        reasons.append("Autorun or logon-related registry location")
    if SUSPICIOUS_SHELL.search(value_data):
        reasons.append("Uses a shell or script host")
    if SUSPICIOUS_PATH.search(value_data):
        reasons.append("References a user-writable or unusual path")
    if ENCODED.search(value_data):
        reasons.append("Contains encoded or obfuscated PowerShell indicators")
    if NETWORK.search(value_data):
        reasons.append("Contains network or download behavior")
    if HIDDEN_EXEC.search(value_data):
        reasons.append("Uses hidden or bypass-style execution flags")
    if re.search(r"(\.dll|inprocserver32|appinit_dlls)", value_data, re.I):
        reasons.append("References DLL-based persistence behavior")
    if re.match(r"^[A-Za-z0-9_-]{7,}$", value_name, re.I) and not re.search(r"OneDrive|SecurityHealth|Teams|Sidebar|Windows", value_name, re.I):
        reasons.append("Value name may be generic or randomly named")

    score = len(reasons)
    entry["Score"] = score
    entry["Severity"] = get_severity(score)
    entry["Reasons"] = reasons
    entry["Suspicious"] = score > 0
    return entry


def get_tasks():
    script = r"""
$tasks = Get-ScheduledTask | ForEach-Object {
    $cmds = @()
    foreach ($a in $_.Actions) {
        if ($a.Execute) {
            $cmd = $a.Execute
            if ($a.Arguments) { $cmd = "$cmd $($a.Arguments)" }
            $cmds += $cmd.Trim()
        }
    }
    $triggers = @()
    foreach ($t in $_.Triggers) {
        $parts = @()
        $parts += $t.CimClass.CimClassName
        if ($t.Repetition.Interval) { $parts += $t.Repetition.Interval }
        $triggers += ($parts -join ':')
    }

    [pscustomobject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        State = [string]$_.State
        Author = $_.Author
        UserId = $_.Principal.UserId
        RunLevel = [string]$_.Principal.RunLevel
        Hidden = [bool]$_.Settings.Hidden
        CommandLine = ($cmds -join ' | ')
        Triggers = $triggers
    }
}
$tasks | ConvertTo-Json -Depth 5 -Compress
"""
    data = run_powershell_json(script)
    if isinstance(data, dict):
        data = [data]
    return [score_task(t) for t in data]


def get_registry_entries():
    script = r"""
$targets = @(
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';                  Type = 'Values' },
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce';              Type = 'Values' },
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';                  Type = 'Values' },
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce';              Type = 'Values' },
    @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';      Type = 'Values' },
    @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';  Type = 'Values' },
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';    Type = 'Named';  Names = @('Run') },
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';    Type = 'Named';  Names = @('Run') },
    @{ Path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon';          Type = 'Named';  Names = @('Shell','Userinit') },
    @{ Path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows';           Type = 'Named';  Names = @('Load','AppInit_DLLs') },
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager';               Type = 'Named';  Names = @('BootExecute') }
)

$results = New-Object System.Collections.Generic.List[object]

foreach ($target in $targets) {
    if (-not (Test-Path $target.Path)) { continue }

    if ($target.Type -eq 'Values') {
        $item = Get-ItemProperty -Path $target.Path
        if (-not $item) { continue }
        $skip = 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider'
        $props = $item.PSObject.Properties | Where-Object { $_.Name -notin $skip }

        foreach ($prop in $props) {
            $valueName = $prop.Name
            $valueData = [string]$prop.Value
            if ([string]::IsNullOrWhiteSpace($valueData)) { continue }

            $results.Add([pscustomobject]@{
                RegistryPath = $target.Path
                ValueName = $valueName
                ValueData = $valueData
            })
        }
    }

    if ($target.Type -eq 'Named') {
        foreach ($valueName in $target.Names) {
            $item = Get-ItemProperty -Path $target.Path -Name $valueName -ErrorAction SilentlyContinue
            if (-not $item) { continue }

            $valueData = [string]$item.$valueName
            if ([string]::IsNullOrWhiteSpace($valueData)) { continue }

            $results.Add([pscustomobject]@{
                RegistryPath = $target.Path
                ValueName = $valueName
                ValueData = $valueData
            })
        }
    }
}

$results | ConvertTo-Json -Depth 5 -Compress
"""
    data = run_powershell_json(script)
    if isinstance(data, dict):
        data = [data]
    return [score_registry(r) for r in data]


def get_installed_programs():
    script = r"""
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$results = foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -and -not $_.SystemComponent -and -not $_.ReleaseType
    } | ForEach-Object {
        [pscustomobject]@{
            DisplayName = $_.DisplayName
            DisplayVersion = $_.DisplayVersion
            Publisher = $_.Publisher
            InstallDate = $_.InstallDate
            InstallLocation = $_.InstallLocation
        }
    }
}
$results | Sort-Object DisplayName -Unique | ConvertTo-Json -Depth 5 -Compress
"""
    data = run_powershell_json(script)
    if isinstance(data, dict):
        data = [data]

    filtered = []
    for app in data:
        publisher = app.get("Publisher", "") or ""
        name = app.get("DisplayName", "") or ""

        pub_match = any(re.search(p, publisher, re.I) for p in DEFAULT_PUBLISHER_PATTERNS)
        name_match = any(re.search(p, name, re.I) for p in DEFAULT_NAME_PATTERNS)

        app["LikelyNonDefault"] = not (pub_match or name_match)
        filtered.append(app)

    return filtered


# Default Windows Local Security Policy values
DEFAULT_LOCAL_POLICY = {
    "System Access": {
        "MinimumPasswordAge": "1",
        "MaximumPasswordAge": "42",
        "MinimumPasswordLength": "0",
        "PasswordComplexity": "0",
        "PasswordHistorySize": "0",
        "LockoutBadCount": "0",
        "RequireLogonToChangePassword": "0",
        "ForceLogoffWhenHourExpire": "0",
        "ClearTextPassword": "0",
        "LSAAnonymousNameLookup": "0",
    },
    "Event Audit": {
        "AuditSystemEvents": "0",
        "AuditLogonEvents": "0",
        "AuditObjectAccess": "0",
        "AuditPrivilegeUse": "0",
        "AuditPolicyChange": "0",
        "AuditAccountManage": "0",
        "AuditProcessTracking": "0",
        "AuditDSAccess": "0",
        "AuditAccountLogon": "0",
    },
    "Registry Values": {
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM": "1",
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous": "0",
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLmHash": "1",
    }
}


def get_local_policy():
    """
    Get current local security policy and compare with Windows defaults.
    Returns list of settings that differ from defaults.
    """
    script = r"""
# Try to get security policy info from Group Policy registry locations and other key locations
$policies = @()

# Account policies from registry
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$samPath = 'HKLM:\SAM\SAM\Domains\Account'
$accountPath = 'HKLM:\SAM\SAM\Domains\Builtin'

# Get LSA settings
if (Test-Path $lsaPath) {
    $lsaKeys = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
    if ($lsaKeys) {
        foreach ($prop in $lsaKeys.PSObject.Properties) {
            if ($prop.Name -notmatch '(PS|__)') {
                $policies += @{
                    Section = "LSA Policy"
                    Setting = $prop.Name
                    CurrentValue = [string]$prop.Value
                }
            }
        }
    }
}

# Get Account policies - these are stored in registry hives sometimes
$accountPathItems = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Subsystems\Windows',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers'
)

foreach ($path in $accountPathItems) {
    if (Test-Path $path) {
        $item = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($item) {
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -notmatch '(PS|__)', $prop.Value) {
                    $policies += @{
                        Section = $path.Split('\')[-1]
                        Setting = $prop.Name
                        CurrentValue = [string]$prop.Value
                    }
                }
            }
        }
    }
}

# Try to use secedit if available (requires elevation)
$seceditOutput = @()
try {
    $tempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.cfg'
    $null = secedit /export /cfg $tempFile /quiet 2>$null
    
    if (Test-Path $tempFile) {
        $content = Get-Content -Path $tempFile -Raw
        
        # Parse secedit output
        $currentSection = ""
        foreach ($line in $content -split "`n") {
            $line = $line.Trim()
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $matches[1]
            } elseif ($line -match '^(.+?)\s*=\s*(.*)$' -and $currentSection) {
                $seceditOutput += @{
                    Section = $currentSection
                    Setting = $matches[1].Trim()
                    CurrentValue = $matches[2].Trim()
                }
            }
        }
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
} catch {
    # Secedit not available or no elevation
}

# Combine both sources
if ($seceditOutput.Count -gt 0) {
    $allPolicies = $seceditOutput
} else {
    $allPolicies = $policies
}

@{
    Error = ""
    Policies = @($allPolicies)
    Count = $allPolicies.Count
} | ConvertTo-Json -Depth 5 -Compress
"""
    
    try:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            script,
        ]
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        
        if completed.returncode != 0:
            return {
                "Error": f"Failed to export local policy",
                "Policies": [],
                "NonDefaultCount": 0,
            }
        
        raw = completed.stdout.strip()
        if not raw:
            return {
                "Error": "No policy data returned",
                "Policies": [],
                "NonDefaultCount": 0,
            }
        
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            return {
                "Error": "Failed to parse policy data",
                "Policies": [],
                "NonDefaultCount": 0,
            }
        
        # Process policies and compare with defaults
        raw_policies = result.get("Policies", [])
        if isinstance(raw_policies, dict):
            raw_policies = [raw_policies]
        
        non_default_settings = []
        
        for policy in raw_policies:
            section = policy.get("Section", "")
            setting = policy.get("Setting", "")
            current_value = policy.get("CurrentValue", "")
            
            default_value = DEFAULT_LOCAL_POLICY.get(section, {}).get(setting)
            
            # If we have a default and it differs, flag it
            if default_value is not None and str(current_value) != str(default_value):
                severity = "High" if section in ["System Access", "Security Policy"] else "Medium"
                non_default_settings.append({
                    "Section": section,
                    "Setting": setting,
                    "CurrentValue": current_value,
                    "DefaultValue": default_value,
                    "IsNonDefault": True,
                    "Severity": severity
                })
            # If we don't have a default but there's a value set, it might be custom
            elif default_value is None and current_value:
                # Only include if it looks like a security-relevant setting
                if any(keyword in setting.lower() for keyword in ["password", "lockout", "audit", "user", "admin", "policy", "anonymous", "signing", "encryption"]):
                    non_default_settings.append({
                        "Section": section,
                        "Setting": setting,
                        "CurrentValue": current_value,
                        "DefaultValue": "(unknown)",
                        "IsNonDefault": True,
                        "Severity": "Low"
                    })
        
        return {
            "Error": "",
            "Policies": sorted(non_default_settings, key=lambda x: (x["Section"], x["Setting"])),
            "NonDefaultCount": len(non_default_settings),
            "AllPolicies": raw_policies,
        }
        
    except Exception as e:
        return {
            "Error": f"Exception during policy query: {str(e)}",
            "Policies": [],
            "NonDefaultCount": 0,
        }