import configparser
import json
import re
import subprocess
import tkinter as tk
import urllib.request
from html import unescape
from pathlib import Path
from urllib.parse import unquote

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

APP_TITLE = "Forensics Tool v5.3"
APP_THEME = "superhero"

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
HTML_TAG_RE = re.compile(r"<[^>]+>")


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


def html_to_text(content: str) -> str:
    text = content.replace("\r", "")
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>", "\n\n", text)
    text = re.sub(r"(?i)</div>", "\n", text)
    text = re.sub(r"(?i)</h[1-6]>", "\n\n", text)
    text = HTML_TAG_RE.sub(" ", text)
    text = unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def fetch_url_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        text = raw.decode(charset, errors="ignore")
        if "<html" in text.lower():
            return html_to_text(text)
        return text


def resolve_url_shortcut(file_path: Path):
    try:
        parser = configparser.ConfigParser()
        parser.optionxform = str
        parser.read(file_path, encoding="utf-8")

        if parser.has_section("InternetShortcut") and parser.has_option("InternetShortcut", "URL"):
            target = parser.get("InternetShortcut", "URL").strip()
        else:
            raw = file_path.read_text(encoding="utf-8", errors="ignore")
            target = None
            for line in raw.splitlines():
                if line.strip().lower().startswith("url="):
                    target = line.split("=", 1)[1].strip()
                    break

        if not target:
            return None, None

        target = unquote(target).strip().strip('"')

        if target.lower().startswith(("http://", "https://")):
            return "remote", target

        if target.lower().startswith("file:///"):
            target = target[8:]
        elif target.lower().startswith("file://"):
            target = target[7:]

        target = target.replace("/", "\\")
        if re.match(r"^[A-Za-z]:[^\\]", target):
            target = target[:2] + "\\" + target[2:]

        local_path = Path(target)
        if local_path.exists():
            return "local", local_path
    except Exception:
        pass
    return None, None


def resolve_lnk_shortcut(file_path: Path):
    script = rf"""
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut('{str(file_path).replace("'", "''")}')
[pscustomobject]@{{
    TargetPath = $sc.TargetPath
    Arguments = $sc.Arguments
    WorkingDirectory = $sc.WorkingDirectory
    Description = $sc.Description
}} | ConvertTo-Json -Compress
"""
    try:
        data = run_powershell_json(script)
        target = (data.get("TargetPath") or "").strip()
        args = (data.get("Arguments") or "").strip()
        return {"target": target, "args": args, "working_dir": (data.get("WorkingDirectory") or "").strip()}
    except Exception:
        return None


def find_report_candidates_in_directory(directory: Path):
    candidates = []
    if not directory.exists() or not directory.is_dir():
        return candidates

    preferred_names = [
        "index.html", "report.html", "results.html", "score.html", "scoring.html", "readme.html", "README.html"
    ]

    for name in preferred_names:
        p = directory / name
        if p.exists() and p.is_file():
            candidates.append(p)

    for p in directory.glob("*.html"):
        if p not in candidates:
            candidates.append(p)
    for p in directory.glob("*.htm"):
        if p not in candidates:
            candidates.append(p)

    return candidates[:10]


class StatCard(ttk.Frame):
    def __init__(self, parent, title, value="0", bootstyle="secondary"):
        super().__init__(parent, padding=16, bootstyle=bootstyle)
        self.value_var = ttk.StringVar(value=value)
        self.title_var = ttk.StringVar(value=title)

        ttk.Label(self, textvariable=self.title_var, font=("Segoe UI", 11, "bold"), bootstyle="light").pack(anchor="w")
        ttk.Label(self, textvariable=self.value_var, font=("Segoe UI", 28, "bold"), bootstyle="light").pack(anchor="w", pady=(10, 0))

    def set_value(self, value):
        self.value_var.set(str(value))



REPORT_KEYWORDS = (
    "readme",
    "score",
    "scoring",
    "report",
    "results",
    "cypat",
)

def looks_like_report_text(value: str) -> bool:
    if not value:
        return False
    v = value.lower()
    return any(k in v for k in REPORT_KEYWORDS)

def looks_like_report_candidate(*values) -> bool:
    for value in values:
        if value and looks_like_report_text(str(value)):
            return True
    return False

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

        self.style = ttk.Style(theme=APP_THEME)
        self.configure_styles()
        self.build_ui()

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
        ttk.Label(hero, text="Windows persistence review + questions + advanced report resolver", style="SubTitle.TLabel", bootstyle="secondary").pack(side=LEFT, padx=14, pady=(7, 0))

        actions = ttk.Frame(shell)
        actions.pack(fill=X, pady=(0, 12))
        ttk.Button(actions, text="Scan All", command=self.scan_all, bootstyle=SUCCESS).pack(side=LEFT)
        ttk.Button(actions, text="Reload Questions", command=self.load_question_files, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=8)
        ttk.Button(actions, text="Reload Reports", command=self.load_report_files, bootstyle=(PRIMARY, OUTLINE)).pack(side=LEFT, padx=8)
        ttk.Button(actions, text="Switch Theme", command=self.toggle_theme, bootstyle=(SECONDARY, OUTLINE)).pack(side=LEFT)

        self.status_var = ttk.StringVar(value="Ready")
        ttk.Label(actions, textvariable=self.status_var, bootstyle="warning").pack(side=RIGHT)

        self.notebook = ttk.Notebook(shell, bootstyle="primary")
        self.notebook.pack(fill=BOTH, expand=YES)

        self.overview_tab = ttk.Frame(self.notebook, padding=18)
        self.tasks_tab = ttk.Frame(self.notebook, padding=14)
        self.registry_tab = ttk.Frame(self.notebook, padding=14)
        self.apps_tab = ttk.Frame(self.notebook, padding=14)
        self.questions_tab = ttk.Frame(self.notebook, padding=14)
        self.reports_tab = ttk.Frame(self.notebook, padding=14)

        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.tasks_tab, text="Tasks")
        self.notebook.add(self.registry_tab, text="Registry")
        self.notebook.add(self.apps_tab, text="Apps")
        self.notebook.add(self.questions_tab, text="Questions")
        self.notebook.add(self.reports_tab, text="Reports")

        self.build_overview_tab()
        self.build_tasks_tab()
        self.build_registry_tab()
        self.build_apps_tab()
        self.build_questions_tab()
        self.build_reports_tab()

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
        self.card_apps.grid(row=0, column=4, sticky="nsew")

        for i in range(5):
            cards.columnconfigure(i, weight=1)

        summary_frame = ttk.Labelframe(self.overview_tab, text="Summary", padding=12, bootstyle="primary")
        summary_frame.pack(fill=BOTH, expand=YES)

        self.summary_text = tk.Text(summary_frame, wrap="word", height=20, bg="#122033", fg="#e9f2ff", insertbackground="#ffffff", relief="flat", borderwidth=0, padx=10, pady=10)
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
        self.tasks_tree = self.build_tree_with_scrollbars(self.tasks_tab, ("severity", "score", "name", "path", "user", "command"), [
            ("severity", "Severity", 90), ("score", "Score", 70), ("name", "Task Name", 220), ("path", "Task Path", 220), ("user", "User", 180), ("command", "Command", 520)
        ], bootstyle="danger")
        self.apply_tree_tags(self.tasks_tree)

    def build_registry_tab(self):
        ttk.Label(self.registry_tab, text="Registry Persistence", style="Section.TLabel", bootstyle="warning").pack(anchor="w", pady=(0, 8))
        self.registry_tree = self.build_tree_with_scrollbars(self.registry_tab, ("severity", "score", "path", "name", "data"), [
            ("severity", "Severity", 90), ("score", "Score", 70), ("path", "Registry Path", 320), ("name", "Value Name", 180), ("data", "Value Data", 560)
        ], bootstyle="warning")
        self.apply_tree_tags(self.registry_tree)

    def build_apps_tab(self):
        ttk.Label(self.apps_tab, text="Installed Programs", style="Section.TLabel", bootstyle="success").pack(anchor="w", pady=(0, 8))
        self.apps_tree = self.build_tree_with_scrollbars(self.apps_tab, ("flag", "name", "version", "publisher", "location"), [
            ("flag", "Likely Non-Default", 140), ("name", "Display Name", 320), ("version", "Version", 110), ("publisher", "Publisher", 260), ("location", "Install Location", 340)
        ], bootstyle="success")
        self.apply_tree_tags(self.apps_tree)

    def build_questions_tab(self):
        outer = ttk.Frame(self.questions_tab)
        outer.pack(fill=BOTH, expand=YES)
        left_card = ttk.Labelframe(outer, text="Question Files", padding=10, bootstyle="info")
        left_card.pack(side=LEFT, fill=Y)
        right_card = ttk.Labelframe(outer, text="Question Editor", padding=12, bootstyle="primary")
        right_card.pack(side=LEFT, fill=BOTH, expand=YES, padx=(12, 0))

        self.question_list = tk.Listbox(left_card, width=42, height=28, bg="#132238", fg="#e8f1ff", selectbackground="#2a9fd6", selectforeground="white", relief="flat", highlightthickness=0)
        self.question_list.pack(fill=Y, expand=NO)
        self.question_list.bind("<<ListboxSelect>>", self.on_question_selected)

        ttk.Label(right_card, text="Question", style="Section.TLabel", bootstyle="info").pack(anchor="w")
        self.question_text = tk.Text(right_card, wrap="word", height=20, bg="#122033", fg="#e9f2ff", insertbackground="#ffffff", relief="flat", borderwidth=0, padx=10, pady=10)
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

        self.report_list = tk.Listbox(left_card, width=42, height=28, bg="#132238", fg="#e8f1ff", selectbackground="#2a9fd6", selectforeground="white", relief="flat", highlightthickness=0)
        self.report_list.pack(fill=Y, expand=NO)
        self.report_list.bind("<<ListboxSelect>>", self.on_report_selected)

        meta = ttk.Frame(right_card)
        meta.pack(fill=X, pady=(0, 8))
        self.report_kind_var = ttk.StringVar(value="Type: ")
        self.report_source_var = ttk.StringVar(value="Source: ")
        ttk.Label(meta, textvariable=self.report_kind_var, bootstyle="info").pack(anchor="w")
        ttk.Label(meta, textvariable=self.report_source_var, bootstyle="secondary").pack(anchor="w")

        self.report_text = tk.Text(right_card, wrap="word", height=20, bg="#122033", fg="#e9f2ff", insertbackground="#ffffff", relief="flat", borderwidth=0, padx=10, pady=10)
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
        self.reports.append({
            "name": name,
            "kind": kind,
            "source": str(source),
            "content": content,
            "origin": str(origin),
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
                        stem = file_path.stem
                        lower_name = stem.lower()

                        if suffix in (".html", ".htm"):
                            if not looks_like_report_candidate(file_path.name, str(file_path)):
                                continue

                            raw = file_path.read_text(encoding="utf-8", errors="ignore")
                            name = file_path.stem
                            if name not in seen_names:
                                self.add_report_record(
                                    name,
                                    "Local HTML",
                                    file_path,
                                    html_to_text(raw),
                                    file_path,
                                )
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
                                    self.add_report_record(
                                        name,
                                        "Remote URL",
                                        resolved,
                                        content,
                                        file_path,
                                    )
                                    seen_names.add(name)

                            elif kind == "local":
                                if not looks_like_report_candidate(file_path.name, resolved):
                                    continue

                                if resolved.is_file() and resolved.suffix.lower() in (".html", ".htm", ".txt", ".md", ".text"):
                                    raw = resolved.read_text(encoding="utf-8", errors="ignore")
                                    content = html_to_text(raw) if resolved.suffix.lower() in (".html", ".htm") else raw
                                    name = file_path.stem
                                    if name not in seen_names:
                                        self.add_report_record(
                                            name,
                                            "Resolved URL Shortcut",
                                            resolved,
                                            content,
                                            file_path,
                                        )
                                        seen_names.add(name)

                                elif resolved.is_dir():
                                    for candidate in find_report_candidates_in_directory(resolved):
                                        if not looks_like_report_candidate(candidate.name, str(candidate)):
                                            continue

                                        raw = candidate.read_text(encoding="utf-8", errors="ignore")
                                        name = f"{file_path.stem} -> {candidate.name}"
                                        if name not in seen_names:
                                            self.add_report_record(
                                                name,
                                                "Shortcut Directory Candidate",
                                                candidate,
                                                html_to_text(raw),
                                                file_path,
                                            )
                                            seen_names.add(name)

                            else:
                                if not looks_like_report_candidate(file_path.name):
                                    continue

                                raw = file_path.read_text(encoding="utf-8", errors="ignore")
                                name = f"{file_path.stem} [unresolved .url]"
                                if name not in seen_names:
                                    self.add_report_record(
                                        name,
                                        "Unresolved URL Shortcut",
                                        file_path,
                                        raw,
                                        file_path,
                                    )
                                    seen_names.add(name)

                            continue

                        if suffix == ".lnk":
                            resolved = resolve_lnk_shortcut(file_path)
                            if not resolved:
                                if not looks_like_report_candidate(file_path.name):
                                    continue

                                name = f"{file_path.stem} [unresolved .lnk]"
                                if name not in seen_names:
                                    self.add_report_record(
                                        name,
                                        "Unresolved LNK",
                                        file_path,
                                        "Unable to resolve shortcut target.",
                                        file_path,
                                    )
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
                                    self.add_report_record(
                                        name,
                                        "Resolved LNK File",
                                        target_path,
                                        content,
                                        file_path,
                                    )
                                    seen_names.add(name)

                            elif target and Path(target).is_dir():
                                for candidate in find_report_candidates_in_directory(Path(target)):
                                    if not looks_like_report_candidate(candidate.name, str(candidate)):
                                        continue

                                    raw = candidate.read_text(encoding="utf-8", errors="ignore")
                                    candidate_name = f"{name} -> {candidate.name}"
                                    if candidate_name not in seen_names:
                                        self.add_report_record(
                                            candidate_name,
                                            "LNK Directory Candidate",
                                            candidate,
                                            html_to_text(raw),
                                            file_path,
                                        )
                                        seen_names.add(candidate_name)

                            elif target.lower().endswith(("msedge.exe", "chrome.exe", "firefox.exe", "opera.exe")):
                                possible = None
                                combined = f"{target} {args} {working_dir}".strip()
                                m = re.search(r"([A-Za-z]:\\[^\s\"]+\\(?:index|report|results|score|scoring)[^\s\"]*\.html?)", combined, re.I)
                                if m:
                                    possible = Path(m.group(1))

                                if possible and possible.exists():
                                    raw = possible.read_text(encoding="utf-8", errors="ignore")
                                    if name not in seen_names:
                                        self.add_report_record(
                                            name,
                                            "Browser Shortcut to Local Report",
                                            possible,
                                            html_to_text(raw),
                                            file_path,
                                        )
                                        seen_names.add(name)
                                else:
                                    diagnostic = f"Shortcut target: {target}\nArguments: {args}\nWorking Dir: {working_dir}"
                                    if name not in seen_names:
                                        self.add_report_record(
                                            name,
                                            "Browser Shortcut",
                                            file_path,
                                            diagnostic,
                                            file_path,
                                        )
                                        seen_names.add(name)

                            else:
                                diagnostic = f"Shortcut target: {target}\nArguments: {args}\nWorking Dir: {working_dir}"
                                if name not in seen_names:
                                    self.add_report_record(
                                        name,
                                        "Resolved LNK",
                                        file_path,
                                        diagnostic,
                                        file_path,
                                    )
                                    seen_names.add(name)

                    except Exception as ex:
                        if looks_like_report_candidate(file_path.name):
                            name = f"{file_path.stem} [error]"
                            if name not in seen_names:
                                self.add_report_record(
                                    name,
                                    "Error",
                                    file_path,
                                    str(ex),
                                    file_path,
                                )
                                seen_names.add(name)

        self.card_reports.set_value(len(self.reports))

    def on_question_selected(self, event=None):
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

    def on_report_selected(self, event=None):
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

    def save_current_answer(self, event=None):
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
            self.tasks_tree.insert("", "end", values=(task.get("Severity", ""), task.get("Score", ""), task.get("TaskName", ""), task.get("TaskPath", ""), task.get("UserId", ""), task.get("CommandLine", "")), tags=(sev,))
        self.card_tasks.set_value(sum(1 for t in self.tasks if t.get("Suspicious")))

    def populate_registry(self):
        for item in self.registry_tree.get_children():
            self.registry_tree.delete(item)
        for entry in sorted(self.registry_entries, key=lambda x: x.get("Score", 0), reverse=True):
            sev = entry.get("Severity", "Info")
            self.registry_tree.insert("", "end", values=(entry.get("Severity", ""), entry.get("Score", ""), entry.get("RegistryPath", ""), entry.get("ValueName", ""), entry.get("ValueData", "")), tags=(sev,))
        self.card_registry.set_value(sum(1 for r in self.registry_entries if r.get("Suspicious")))

    def populate_apps(self):
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)
        for app in sorted(self.apps, key=lambda x: (not x.get("LikelyNonDefault", False), x.get("DisplayName", ""))):
            tag = "Likely" if app.get("LikelyNonDefault") else "Default"
            self.apps_tree.insert("", "end", values=("Yes" if app.get("LikelyNonDefault") else "No", app.get("DisplayName", ""), app.get("DisplayVersion", ""), app.get("Publisher", ""), app.get("InstallLocation", "")), tags=(tag,))
        self.card_apps.set_value(sum(1 for a in self.apps if a.get("LikelyNonDefault")))

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

            suspicious_tasks = sum(1 for t in self.tasks if t.get("Suspicious"))
            suspicious_registry = sum(1 for r in self.registry_entries if r.get("Suspicious"))
            likely_non_default = sum(1 for a in self.apps if a.get("LikelyNonDefault"))

            summary = (
                f"Questions found: {len(self.questions)}\n"
                f"Reports found: {len(self.reports)}\n"
                f"Scheduled tasks: {len(self.tasks)} total, {suspicious_tasks} suspicious\n"
                f"Registry persistence entries: {len(self.registry_entries)} total, {suspicious_registry} suspicious\n"
                f"Installed programs: {len(self.apps)} total, {likely_non_default} likely non-default\n\n"
                f"Notes:\n"
                f"- Reports now support remote .url targets, local HTML, and .lnk shortcut resolution.\n"
                f"- Browser shortcuts may display diagnostic metadata if a local HTML path cannot be extracted.\n"
                f"- Task and registry scores are heuristic.\n"
                f"- Installed-program filtering is an approximation, not a guarantee."
            )
            self.set_summary(summary)
            self.status_var.set("Scan complete")
        except Exception as ex:
            self.status_var.set("Scan failed")
            messagebox.showerror("Scan failed", str(ex))


def main():
    root = ttk.Window(themename=APP_THEME)
    ForensicsToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()