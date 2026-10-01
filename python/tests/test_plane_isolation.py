"""test_plane_isolation.py — SDK isolation guard for execution planes (Issue #284).

Positive control for Issue #284:
  "SDK 本体にクラウド名を 1 つ足すと、不変条件検査が落ちること
   (許可されるのは closed enum と adapter module 内のみ)"

Rules:
  - SDK core logic modules in `python/src/aegis_trust/` and `node/src/` MUST NOT
    contain cloud provider names in executable code.
  - Cloud provider names are strictly quarantined to:
      1. `python/src/aegis_trust/planes/` (closed enum and plane adapters)
      2. `node/src/planes/` (closed enum and plane adapters)
  - Any cloud name leaking into `shield`, `client`, `doctor`, `wrap`, `types`, etc.,
    triggers an immediate failure.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_SRC = REPO_ROOT / "python" / "src" / "aegis_trust"
NODE_SRC = REPO_ROOT / "node" / "src"

# Forbidden cloud execution plane names in SDK core (case-insensitive token match)
FORBIDDEN_CLOUD_RE = re.compile(r"\b(aws|azure|gcp|oracle_cloud)\b", re.IGNORECASE)

# Allowed directories relative to src
ALLOWED_SUBDIRS = ("planes",)


def strip_comments(line: str, lang: str = "py") -> str:
    """Strip line comments from source code."""
    trimmed = line.lstrip()
    if lang == "py":
        if trimmed.startswith("#"):
            return ""
        if "#" in line:
            return line.split("#", 1)[0]
    elif lang in ("ts", "js"):
        if trimmed.startswith("//"):
            return ""
        if "//" in line:
            return line.split("//", 1)[0]
    return line


def check_file_isolation(path: Path, lang: str) -> list[tuple[int, str, str]]:
    """Check a single file for forbidden cloud provider names in code lines."""
    violations = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                code = strip_comments(line, lang).strip()
                if not code:
                    continue
                match = FORBIDDEN_CLOUD_RE.search(code)
                if match:
                    violations.append((idx, match.group(0), code))
    except OSError as e:
        print(f"  [ERROR] Failed to read {path}: {e}", file=sys.stderr)
    return violations


def run_isolation_check(src_dir: Path, lang: str) -> list[tuple[Path, int, str, str]]:
    """Scan all source files outside allowed subdirectories for forbidden cloud names."""
    all_violations = []
    for dp, _, fns in os.walk(src_dir):
        rel_dir = Path(dp).relative_to(src_dir)
        if any(part in ALLOWED_SUBDIRS for part in rel_dir.parts):
            continue

        ext = ".py" if lang == "py" else ".ts"
        for fn in fns:
            if not fn.endswith(ext) or fn.endswith(".d.ts"):
                continue
            full_path = Path(dp) / fn
            rel_path = full_path.relative_to(src_dir)

            violations = check_file_isolation(full_path, lang)
            for line_no, token, line_code in violations:
                all_violations.append((rel_path, line_no, token, line_code))
    return all_violations


def self_test() -> bool:
    """Self-test: verify that a synthetic cloud name injected into a core module is caught."""
    import shutil
    import tempfile

    temp_dir = Path(tempfile.mkdtemp(prefix="aegis_sdk_isolation_selftest_"))
    try:
        # Create allowed planes module
        planes_dir = temp_dir / "planes"
        planes_dir.mkdir()
        (planes_dir / "types.py").write_text(
            "class PlaneKind: AWS = 'aws'\n", encoding="utf-8"
        )

        # Create clean core file
        (temp_dir / "shield.py").write_text("def shield(): pass\n", encoding="utf-8")

        clean_violations = run_isolation_check(temp_dir, "py")
        if clean_violations:
            print(
                f"  [SELF-TEST FAIL] Clean directory had false positives: {clean_violations}"
            )
            return False

        # Inject forbidden cloud name into shield.py
        (temp_dir / "shield.py").write_text(
            "def shield():\n    target = 'aws'\n", encoding="utf-8"
        )

        dirty_violations = run_isolation_check(temp_dir, "py")
        if not dirty_violations:
            print("  [SELF-TEST FAIL] Injected cloud name in core was NOT caught")
            return False

        if dirty_violations[0][2].lower() != "aws":
            print(
                f"  [SELF-TEST FAIL] Expected token 'aws', got: {dirty_violations[0][2]}"
            )
            return False

        return True
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_plane_isolation():
    """Pytest entrypoint for SDK plane isolation guard."""
    py_violations = run_isolation_check(PYTHON_SRC, "py")
    assert not py_violations, (
        f"Python SDK core leaked cloud provider names: {py_violations}"
    )

    node_violations = run_isolation_check(NODE_SRC, "ts")
    assert not node_violations, (
        f"Node SDK core leaked cloud provider names: {node_violations}"
    )


def test_plane_isolation_self_test():
    """Pytest entrypoint for isolation guard self-test."""
    assert self_test() is True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis SDK Execution Plane Isolation Guard"
    )
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        if ok:
            print("test_plane_isolation: SELF-TEST PASSED")
            sys.exit(0)
        else:
            print("test_plane_isolation: SELF-TEST FAILED", file=sys.stderr)
            sys.exit(1)

    py_v = run_isolation_check(PYTHON_SRC, "py")
    node_v = run_isolation_check(NODE_SRC, "ts")
    all_v = py_v + node_v
    if all_v:
        print("test_plane_isolation: [FAIL] Cloud provider names leaked into SDK core:")
        for rel_path, line_no, token, code in all_v:
            print(f"  {rel_path}:{line_no} [leaked '{token}']: {code}")
        print(
            "  → Cloud provider names are only allowed in planes/ (closed enum & adapters)."
        )
        sys.exit(1)

    print("test_plane_isolation: OK (SDK core strictly isolated from cloud names)")
    sys.exit(0)
