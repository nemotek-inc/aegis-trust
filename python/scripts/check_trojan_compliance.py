#!/usr/bin/env python3
"""S020 checklist Trojan Horse lint gate (T-809).

Scans public-facing files for Trojan Horse violations:

- Banned internal component names (aegis-core, sync_policies, Mode.FULL/LITE/AUTO, etc.)
- Legacy package name (``aegis-shield``) outside of allowed migration context
- GitHub repo references outside the approved set (this repo only)
- Non-approved contact emails / hosts (only the project's own channel)
- Relative links to private-repo files (``examples/``, ``docs/decisions/``)

Aegis 米軍規格: skip = fail.

Exit 0 on PASS, 1 on FAIL with the list of violations on stderr.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files to scan (relative to repo root)
PUBLIC_FILES = [
    "README.md",
    "llms.txt",
    "AGENTS.md",
    "SECURITY.md",
    "pyproject.toml",
    "CHANGELOG.md",
]
# Source files (src/aegis/) are scanned only inside docstrings and string-literal
# arguments to ``logger.{info,warning,error,debug,critical}`` calls. These are the
# user-visible surfaces (``help()``, runtime stderr, Sphinx autodoc). Bare Python
# identifiers like ``Mode.FULL`` and ``sync_policies`` are required at the language
# level and are NOT flagged here.
SOURCE_GLOB = ("src/aegis/**/*.py",)
SOURCE_EXCLUDE = {"_generated"}

# CHANGELOG.md is allowed to mention legacy names in history entries.
# Migration section in README.md / SECURITY.md is allowed to mention aegis-shield.

BANNED_TERMS = {
    # name: (regex pattern, allowlist of contexts)
    "aegis-core": re.compile(r"\baegis-core\b"),
    "sync_policies": re.compile(r"\bsync_policies\b"),
    "Mode.FULL": re.compile(r"\bMode\.FULL\b"),
    "Mode.LITE": re.compile(r"\bMode\.LITE\b"),
    "Mode.AUTO": re.compile(r"\bMode\.AUTO\b"),
    "reflex engine": re.compile(r"\breflex engine\b", re.IGNORECASE),
    # "contact contact@" / "contact `contact@" reads as verb/name duplicated.
    # Use "email contact@..." or "reach contact@..." instead. Catches the
    # duplication even when the email itself is in the approved list.
    "contact contact@ duplication": re.compile(r"\bcontact\s+`?contact@"),
}

# 'aegis-shield' is allowed in:
# - README.md Migration section (## Migration ...)
# - SECURITY.md if scoped to migration note
# - pyproject.toml inside [tool.hatch.build.targets.wheel] reference paths (none currently)
# - CHANGELOG.md: allowed for historical entries that describe the rename from
#   aegis-shield to aegis-trust (the CHANGELOG is an append-only record, and
#   rewriting prior entries would misrepresent what actually shipped).
LEGACY_NAME_RE = re.compile(r"\baegis-shield\b")

# Historical backend-name references (`aegis-core`) in CHANGELOG entries for
# 0.1.x / 0.2.x — these describe what actually shipped at the time and are
# part of the append-only release record. BANNED_TERMS still flags `aegis-core`
# everywhere else; the CHANGELOG-scoped allowlist is narrow.
CHANGELOG_HISTORICAL_OK = {"aegis-core"}

# Only this repository may be named by a github.com repo reference in a public
# file. This is an allowlist rather than a denylist of specific private repos:
# it catches a reference to *any* unapproved repo (including ones that do not
# exist yet), and — unlike a denylist — it does not require a private repo name
# to be written into this public file in order to recognise one.
APPROVED_REPOS = {"nemotek-inc/aegis-trust"}
GITHUB_REPO_RE = re.compile(
    r"github\.com[:/]([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]+)", re.IGNORECASE)

# Hosts that may appear in a public file. Same rationale as APPROVED_REPOS: the
# rule is "only these", so a host that was never registered is caught without
# being named here.
APPROVED_HOSTS = {
    "aegisagentcontrol.com",  # the project's only owned contact domain
    "github.com",
    "img.shields.io",
    "pypi.org",
    "npmjs.com",
    "www.npmjs.com",
    "opensource.org",
    "spdx.org",
    "packaging.python.org",
    "peps.python.org",
    "docs.pypi.org",
    "blockstream.info",  # OpenTimestamps calendar/explorer referenced by the attestation docs
    "localhost",
    "example.com",
    "ex.com",
}

# Two checks, because they have genuinely different reach — do not read the
# second as covering the first.
#
# URL_HOST_RE is the EXACT one: anything written as a real URL has its host
# checked whatever its TLD, so an unregistered or newly-invented domain is
# caught. This is the check that matters, and it has no false positives.
URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)", re.IGNORECASE)
#
# HOSTNAME_RE is a HEURISTIC for bare mentions in prose ("write to example.com"),
# where nothing marks the token as a host. It is deliberately limited to the TLDs
# below: widening it makes dotted identifiers and filenames (``ci-matrix.sh``,
# ``profile.name``, ``tool.mypy``) read as hosts. So a bare mention of a host on
# an unlisted TLD is NOT caught — write it as a URL and it is.
HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|io|net|dev|jp|ai)\b",
    re.IGNORECASE)


# Emails: must be in approved set OR be example.com demo data.
# contact@aegisagentcontrol.com is the only real, owned contact channel.
# The earlier placeholder addresses were never set up and MUST NOT appear
# in any user-facing artifact.
APPROVED_EMAILS = {
    "contact@aegisagentcontrol.com",
}
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DEMO_EMAIL_DOMAINS = {"example.com", "ex.com"}


def unapproved_repos(text: str):
    """Yield (line_no, "owner/repo") for every github repo outside the allowlist."""
    for m in GITHUB_REPO_RE.finditer(text):
        owner, repo = m.group(1), m.group(2).rstrip(".")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        if f"{owner}/{repo}".lower() in {r.lower() for r in APPROVED_REPOS}:
            continue
        yield text.count("\n", 0, m.start()) + 1, f"{owner}/{repo}"


def unapproved_hosts(text: str):
    """Yield (line_no, host) for every host outside the allowlist.

    Hosts written as a URL are checked exactly; bare prose mentions are matched
    by the TLD heuristic. A host found both ways is reported once.
    """
    seen = set()
    for pattern, group in ((URL_HOST_RE, 1), (HOSTNAME_RE, 0)):
        for m in pattern.finditer(text):
            host = m.group(group).lower().rstrip(".")
            if not host or host in APPROVED_HOSTS:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            if (line_no, host) in seen:
                continue
            seen.add((line_no, host))
            yield line_no, host


def unapproved_emails(text: str):
    """Yield (line_no, email) for every address outside the approved set."""
    approved = {e.lower() for e in APPROVED_EMAILS}
    for m in EMAIL_RE.finditer(text):
        email = m.group(0)
        if email.lower() in approved:
            continue
        if email.rsplit("@", 1)[1].lower() in DEMO_EMAIL_DOMAINS:
            continue
        yield text.count("\n", 0, m.start()) + 1, email

# Relative private paths in markdown links: [text](examples/foo.py) or [text](docs/decisions/...)
PRIVATE_RELATIVE_RE = re.compile(r"\]\((?:\./)?(?:examples/|docs/decisions/)[^\)]+\)")


def in_migration_section(path: Path, line_no: int) -> bool:
    """True if line_no is within a Migration section.

    For README/SECURITY this matches ``## Migration`` sub-sections. For
    CHANGELOG, the entire file is treated as append-only historical record:
    legacy-name references are allowed because rewriting prior entries
    would misrepresent what actually shipped at each version.
    """
    if path.name == "CHANGELOG.md":
        return True
    if path.name not in {"README.md", "SECURITY.md"}:
        return False
    text = path.read_text().splitlines()
    in_section = False
    for i, line in enumerate(text, start=1):
        if re.match(r"^##\s+Migration", line):
            in_section = True
        elif in_section and re.match(r"^##\s+", line):
            in_section = False
        if i == line_no:
            return in_section
    return False


def scan_file(path: Path, violations: list[str]) -> None:
    if not path.exists():
        return
    text = path.read_text()
    lines = text.splitlines()

    # Banned terms. CHANGELOG gets a narrow historical allowlist for
    # backend-name references that appear only in entries for versions
    # where those names were the public surface.
    for name, pat in BANNED_TERMS.items():
        if path.name == "CHANGELOG.md" and name in CHANGELOG_HISTORICAL_OK:
            continue
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            violations.append(
                f"{path.relative_to(ROOT)}:{line_no}: banned term '{name}'"
            )

    # Legacy aegis-shield (with allowed exceptions)
    for i, line in enumerate(lines, start=1):
        for m in LEGACY_NAME_RE.finditer(line):
            if in_migration_section(path, i):
                continue
            violations.append(
                f"{path.relative_to(ROOT)}:{i}: legacy name 'aegis-shield' outside Migration section"
            )

    # GitHub repo references outside the approved set
    for line_no, repo in unapproved_repos(text):
        violations.append(
            f"{path.relative_to(ROOT)}:{line_no}: github repo reference outside the approved set: '{repo}'"
        )

    # Hosts outside the approved set
    for line_no, host in unapproved_hosts(text):
        violations.append(
            f"{path.relative_to(ROOT)}:{line_no}: host outside the approved set: '{host}'"
        )

    # Emails
    for line_no, email in unapproved_emails(text):
        violations.append(
            f"{path.relative_to(ROOT)}:{line_no}: non-approved contact email '{email}'"
        )

    # Private relative links (markdown)
    for m in PRIVATE_RELATIVE_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        violations.append(
            f"{path.relative_to(ROOT)}:{line_no}: relative link to private repo path: {m.group(0)}"
        )


SOURCE_BANNED = {
    "aegis-core": re.compile(r"\baegis-core\b"),
    "reflex engine": re.compile(r"\breflex engine\b", re.IGNORECASE),
    "aegis-shield": re.compile(r"\baegis-shield\b"),
    # Internal AO compliance codes (AO-001 .. AO-006) leak in user-visible
    # strings — public docstrings, log lines, error messages — surface
    # internal Aegis nomenclature that means nothing to consumers.
    "AO-XXX code": re.compile(r"\bAO-00[1-6]\b"),
    # "contact contact@" duplication at the source level (docstrings, log
    # strings). Same pattern as the public-file guard above.
    "contact contact@ duplication": re.compile(r"\bcontact\s+`?contact@"),
}
LOGGER_METHODS = {"info", "warning", "error", "debug", "critical", "exception"}


def collect_source_strings(path: Path) -> list[tuple[int, str]]:
    """Return (line, text) for every user-visible string in the module.

    User-visible means:
    - Module docstring (always public).
    - Public class docstring (name does not start with ``_``) plus all method
      docstrings on a public class — methods are reachable via ``help(Cls)``.
    - Public top-level function docstring.
    - Every ``logger.<level>(...)`` string literal (runtime stderr, always
      visible to users with logging enabled).

    Private function docstrings (``_filter_dict``, etc.) are intentionally
    skipped: they document internal invariants for engineers reading the source
    and never reach users via ``help(public_thing)``.
    """
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    out: list[tuple[int, str]] = []

    # Module-level docstring.
    mod_doc = ast.get_docstring(tree, clean=False)
    if mod_doc:
        out.append((1, mod_doc))

    # Walk top-level defs to decide public/private; recurse into public class bodies.
    for node in tree.body:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and not node.name.startswith("_"):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                out.append((node.lineno, doc))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            cls_doc = ast.get_docstring(node, clean=False)
            if cls_doc:
                out.append((node.lineno, cls_doc))
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m_doc = ast.get_docstring(child, clean=False)
                    if m_doc:
                        out.append((child.lineno, m_doc))

    # logger.<level>(...) string args anywhere in the module.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in LOGGER_METHODS:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        out.append((node.lineno, arg.value))
                    elif isinstance(arg, ast.JoinedStr):
                        for v in arg.values:
                            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                                out.append((node.lineno, v.value))
    return out


def scan_source_file(path: Path, violations: list[str]) -> None:
    if not path.exists():
        violations.append(
            f"{path.relative_to(ROOT)}: source file missing (lint cannot verify)"
        )
        return
    for line, text in collect_source_strings(path):
        for name, pat in SOURCE_BANNED.items():
            if pat.search(text):
                violations.append(
                    f"{path.relative_to(ROOT)}:{line}: source-side Trojan leak '{name}' in docstring or log message"
                )
        for _, repo in unapproved_repos(text):
            violations.append(
                f"{path.relative_to(ROOT)}:{line}: github repo reference outside the approved set: '{repo}'"
            )
        for _, host in unapproved_hosts(text):
            violations.append(
                f"{path.relative_to(ROOT)}:{line}: host outside the approved set: '{host}'"
            )
        for _, email in unapproved_emails(text):
            violations.append(
                f"{path.relative_to(ROOT)}:{line}: non-approved contact email '{email}'"
            )


def main() -> int:
    violations: list[str] = []
    for relpath in PUBLIC_FILES:
        path = ROOT / relpath
        if not path.exists():
            violations.append(f"{relpath}: required public file missing")
            continue
        scan_file(path, violations)
    for pattern in SOURCE_GLOB:
        for path in sorted(ROOT.glob(pattern)):
            if any(part in SOURCE_EXCLUDE for part in path.parts):
                continue
            scan_source_file(path, violations)

    if violations:
        print("TROJAN HORSE FAIL: violations found", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("TROJAN HORSE PASS: no violations in public-facing files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
