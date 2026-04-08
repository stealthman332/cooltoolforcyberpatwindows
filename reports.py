import configparser
import re
import urllib.request
from html import unescape
from pathlib import Path
from urllib.parse import unquote

from collectors import run_powershell_json


HTML_TAG_RE = re.compile(r"<[^>]+>")

REPORT_KEYWORDS = (
    "readme",
    "score",
    "scoring",
    "report",
    "results",
    "cypat",
)


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
        "index.html", "report.html", "results.html", "score.html",
        "scoring.html", "readme.html", "README.html"
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