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
    if score >= 3:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Info"


def score_task(task: dict):
    reasons = []
    cmd = (task.get("CommandLine") or "").strip()
    path = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"

    if task.get("Hidden") is True:
        reasons.append("Task is hidden")
    if "highest" in str(task.get("RunLevel", "")).lower():
        reasons.append("Runs with highest privileges")

    user_id = str(task.get("UserId", ""))
    if re.search(r"SYSTEM|LOCAL SERVICE|NETWORK SERVICE", user_id, re.I):
        reasons.append(f"Runs as privileged account: {user_id}")

    if not re.match(r"^\\Microsoft\\", path, re.I):
        reasons.append("Task is outside standard Microsoft task path")

    name = str(task.get("TaskName", ""))
    if re.match(r"^[A-Za-z0-9]{6,}$", name) and re.search(r"[A-Z]", name) and re.search(r"[a-z]", name) and re.search(r"\d", name):
        reasons.append("Task name appears randomized")

    if SYSTEMLIKE.search(name):
        reasons.append("Task name mimics system or updater naming")

    if SUSPICIOUS_SHELL.search(cmd):
        reasons.append("Uses a shell or script host")
    if SUSPICIOUS_PATH.search(cmd):
        reasons.append("Executes from a user-writable or unusual path")
    if ENCODED.search(cmd):
        reasons.append("Contains encoded or obfuscated PowerShell indicators")
    if NETWORK.search(cmd):
        reasons.append("Contains network path or URL in action")

    trigger_text = " | ".join(task.get("Triggers", []))
    if re.search(r"LogonTrigger|BootTrigger", trigger_text, re.I):
        reasons.append("Uses persistence-style trigger")
    if re.search(r"PT([1-9]M|1[0-5]M)", trigger_text, re.I):
        reasons.append("Repeats frequently")

    score = len(reasons)
    task["Score"] = score
    task["Severity"] = get_severity(score)
    task["Reasons"] = reasons
    task["Suspicious"] = score > 0
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