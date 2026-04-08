import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class ReadmePolicy:
    AuthorizedAdministrators: List[str] = field(default_factory=list)
    AuthorizedUsers: List[str] = field(default_factory=list)
    CriticalServices: List[str] = field(default_factory=list)
    RequiredSoftware: List[str] = field(default_factory=list)
    MinimumPasswordLength: Optional[int] = None
    RawSections: Dict[str, str] = field(default_factory=dict)


SECTION_HEADERS = [
    "authorized administrators",
    "authorized users",
    "critical services",
    "required software",
    "competition info",
    "image download",
    "errata",
    "competition scenario",
]


def _normalize_line(line: str) -> str:
    return line.strip("\r\n")


def _extract_sections(text: str) -> Dict[str, str]:
    """
    Turn the README into named sections based on common headings like:

        Authorized Administrators (user:password):
        Authorized Users:
        Critical Services:
        Required Software:
    """
    lines = [_normalize_line(l) for l in text.splitlines()]
    sections: Dict[str, List[str]] = {}
    current_name = "root"
    sections[current_name] = []

    header_re = re.compile(
        r"^\s*(authorized administrators|authorized users|critical services|required software|competition info|image download|errata|competition scenario)\b.*:",
        re.I,
    )

    for line in lines:
        m = header_re.match(line)
        if m:
            current_name = m.group(1).strip().lower()
            sections.setdefault(current_name, [])
            continue
        sections.setdefault(current_name, []).append(line)

    return {name: "\n".join(body).strip() for name, body in sections.items()}


def _extract_authorized_admins(section_text: str) -> List[str]:
    """
    Handle lines like:

        frodo:Pa$$w0rd10 (YOU)
        gandalf:Pa$$w0rd10
        samwise:Pa$$w0rd10
    """
    admins: List[str] = []
    for raw in section_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("authorized administrators"):
            continue
        if line.startswith("#") or line.lower().startswith("note"):
            continue

        m = re.match(r"^([A-Za-z0-9._-]+)\s*:\s*([^ \t]+)", line)
        if m:
            user = m.group(1).strip()
            if user and user.lower() not in (u.lower() for u in admins):
                admins.append(user)
            continue

        m2 = re.match(r"^([A-Za-z0-9._-]+)\b.*", line)
        if m2:
            user = m2.group(1).strip()
            if user and user.lower() not in (u.lower() for u in admins):
                admins.append(user)

    return admins


def _extract_authorized_users(section_text: str) -> List[str]:
    """
    Handle a simple vertical list:

        gandalf
        samwise
        elrond
        aragorn
        ...
    """
    users: List[str] = []
    for raw in section_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("authorized users"):
            continue
        if line.startswith("#") or line.lower().startswith("note"):
            continue
        if ":" in line:
            # Avoid accidentally pulling “something: explanation” here
            # Admins are handled in their own section.
            continue

        m = re.match(r"^([A-Za-z0-9._-]+)\b.*$", line)
        if not m:
            continue

        user = m.group(1).strip()
        if user and user.lower() not in (u.lower() for u in users):
            users.append(user)

    return users


def _extract_critical_services(section_text: str) -> List[str]:
    """
    Handle lines like:

        SMTP ( MailEnable )
        HTTP ( IIS )
    """
    services: List[str] = []
    for raw in section_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("critical services"):
            continue
        if line.startswith("#") or line.lower().startswith("note"):
            continue

        cleaned = re.sub(r"\s+", " ", line)
        if cleaned and cleaned.lower() not in (s.lower() for s in services):
            services.append(cleaned)

    return services


def _extract_required_software_from_text(text: str) -> List[str]:
    """
    Some READMEs describe required software in prose instead of a neat section, e.g.:

        This includes the latest versions of Opera GX, Thunderbird, and Brackets.
    """
    software = set()
    patterns = [
        r"\bOpera GX\b",
        r"\bThunderbird\b",
        r"\bBrackets\b",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.I):
            name = m.group(0)
            software.add(name)
    return sorted(software)


def _extract_required_software(section_text: str, full_text: str) -> List[str]:
    """
    Try section first; if empty, fall back to prose scan.
    """
    items: List[str] = []
    for raw in section_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("required software"):
            continue
        if line.startswith("#") or line.lower().startswith("note"):
            continue

        cleaned = re.sub(r"\s+", " ", line)
        if cleaned and cleaned.lower() not in (i.lower() for i in items):
            items.append(cleaned)

    if not items:
        items = _extract_required_software_from_text(full_text)

    return items


def _extract_min_password_length(text: str) -> Optional[int]:
    """
    Match phrases like:

        minimum password length to exactly 10
        minimum password length to 10
        minimum password length of 10
    """
    patterns = [
        r"minimum password length\s*(?:to|of|=)?\s*(exactly\s*)?(\d+)",
        r"set the minimum password length\s*(?:to|of|=)?\s*(exactly\s*)?(\d+)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            try:
                value = int(m.group(2))
                return value
            except Exception:
                continue
    return None


def parse_readme(text: str) -> ReadmePolicy:
    """
    Top-level entry: parse a README-style scoring file into a structured policy object.
    """
    if not text:
        return ReadmePolicy()

    sections = _extract_sections(text)

    admins_section = sections.get("authorized administrators", "")
    users_section = sections.get("authorized users", "")
    critical_services_section = sections.get("critical services", "")
    required_software_section = sections.get("required software", "")

    admins = _extract_authorized_admins(admins_section)
    users = _extract_authorized_users(users_section)
    critical_services = _extract_critical_services(critical_services_section)
    required_software = _extract_required_software(required_software_section, text)
    min_pw_len = _extract_min_password_length(text)

    policy = ReadmePolicy(
        AuthorizedAdministrators=admins,
        AuthorizedUsers=users,
        CriticalServices=critical_services,
        RequiredSoftware=required_software,
        MinimumPasswordLength=min_pw_len,
        RawSections={k: v for k, v in sections.items() if k != "root"},
    )
    return policy