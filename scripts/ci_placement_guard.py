#!/usr/bin/env python3
"""ci_placement_guard.py — CI が「どこで走るか」を宣言と突き合わせる。

この門は lane の各 repo に同じものが置かれる (2026-09-15)。片方だけ直す事故を
防ぐため、変更したら他 repo の同名 file も揃えること。差異は repo root の
深さだけ (この repo では scripts/ に在るので parents[1])。

なぜ在るか (2026-09-15):
    CI は作業機の self-hosted runner で走っていた。開発・常駐 job・索引・署名検査と
    同じ 10 コアに並び、受入検査は 3 日で 11 分 → 85 分に落ちた。**どの門もそれを
    見られなかった** — 所要を判定する門が無く、実行先を判定する門も無かった。
    専用 host へ移して 7 分 26 秒になった。

    ただし「移した」だけでは保証にならない。`runs-on:` を 1 行戻せば元に戻り、
    次に誰かが気づくのは、また誰かが「遅くないか」と言った時になる。それは
    人を検知役に戻すということで、この製品が無くそうとしているものそのもの。

    この guard は 4 つを見る:

      R1 網羅   workflow の全 job が宣言に載っているか (新しい job の取りこぼし)
      R2 一致   宣言が既定と言う job の `runs-on` が、そのラベルを含むか
      R3 例外   `!` 行 (例外) に理由が書かれ、宣言どおりのラベルで走っているか
      R4 陳腐   宣言が、もう存在しない workflow / job を指していないか

    R4 が要る理由: job を消して宣言を残すと、宣言は「守られている」ように見える。
    R1 だけでは片方向しか閉じない。

    例外を増やす道は 1 本だけ — `ops/ci_placement.manifest` に理由を書いて commit
    する。黙って増やせる例外は統制ではない。

終了コード: 0 = 全規則を満たす / 1 = 満たさない規則がある
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(os.environ.get("AEGIS_CI_PLACEMENT_ROOT")
            or Path(__file__).resolve().parents[1])
MANIFEST = REPO / "ops" / "ci_placement.manifest"
WORKFLOWS = REPO / ".github" / "workflows"


def parse_manifest(path: Path):
    """宣言を読む。required = 既定の実行先、exceptions = 宣言された例外。"""
    required: dict[tuple[str, str], str] = {}
    exceptions: dict[tuple[str, str], tuple[str, str]] = {}
    if not path.is_file():
        return None, None, f"宣言が無い: {path.name} — 実行先が宣言されていない"
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        excluded = line.startswith("!")
        cells = [c.strip() for c in (line[1:] if excluded else line).split("|")]
        if len(cells) < 4 or not all(cells[:3]):
            return None, None, f"{path.name}:{lineno} 列が足りない (workflow|job|ラベル|根拠)"
        if not cells[3]:
            return None, None, f"{path.name}:{lineno} 根拠が空"
        key = (cells[0], cells[1])
        if excluded:
            exceptions[key] = (cells[2], cells[3])
        else:
            required[key] = cells[2]
    return required, exceptions, None


def workflow_jobs() -> tuple[dict[tuple[str, str], list[str]], list[str]]:
    """workflow を YAML として読み、job ごとの `runs-on` を集める。

    文字列 grep にしないのは judge_wiring_guard と同じ理由で、**壊れた YAML の
    step は一度も走らない**のに、grep では配線されているように見えるため。
    """
    import yaml

    jobs: dict[tuple[str, str], list[str]] = {}
    broken: list[str] = []
    if not WORKFLOWS.is_dir():
        return jobs, ["workflow ディレクトリが無い"]
    for wf in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        try:
            doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            first = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            broken.append(f"{wf.name}: YAML として読めない ({first})")
            continue
        if not isinstance(doc, dict):
            broken.append(f"{wf.name}: 空")
            continue
        for job, body in (doc.get("jobs") or {}).items():
            if not isinstance(body, dict):
                continue
            runs_on = body.get("runs-on")
            if isinstance(runs_on, str):
                labels = [runs_on]
            elif isinstance(runs_on, list):
                labels = [str(x) for x in runs_on]
            else:
                # 式や group 指定など、ここでは読み切れない形。**読めないことを
                # 読めたことにしない** — 宣言側で例外にするしかない形として扱う。
                labels = [f"<読めない: {runs_on!r}>"]
            jobs[(wf.name, str(job))] = labels
    return jobs, broken


def main() -> int:
    fails: list[str] = []
    required, exceptions, err = parse_manifest(MANIFEST)
    if err:
        print(f"FAIL  {err}")
        return 1

    jobs, broken = workflow_jobs()
    for b in broken:
        fails.append(f"R0 {b}")

    declared = set(required) | set(exceptions)

    # R1: 全 job が宣言に載っているか。
    for key in sorted(jobs):
        if key not in declared:
            fails.append(
                f"R1 {key[0]}:{key[1]} が宣言に無い — 実行先が誰にも宣言されていない job"
            )

    # R2 / R3: 宣言どおりのラベルで走っているか。
    for key, label in sorted(required.items()):
        if key not in jobs:
            continue
        if label not in jobs[key]:
            fails.append(
                f"R2 {key[0]}:{key[1]} は {label} で走るはずが {jobs[key]} で走る"
            )
    for key, (label, _reason) in sorted(exceptions.items()):
        if key not in jobs:
            continue
        if label not in jobs[key]:
            fails.append(
                f"R3 {key[0]}:{key[1]} は例外として {label} と宣言されているが {jobs[key]} で走る"
            )

    # R4: 宣言が、もう無い workflow / job を指していないか。
    for key in sorted(declared):
        if key not in jobs:
            fails.append(f"R4 宣言が実在しない job を指している: {key[0]}:{key[1]}")

    print(f"ci placement guard — 宣言 {MANIFEST.name}")
    print(f"  job {len(jobs)} 件 / 既定 {len(required)} 件 / 宣言された例外 {len(exceptions)} 件")
    for key, (label, reason) in sorted(exceptions.items()):
        print(f"  例外  {key[0]}:{key[1]} → {label} ({reason})")
    if fails:
        for f in fails:
            print(f"  FAIL  {f}")
        print(f"ci placement guard: 満たさない規則 {len(fails)} 件")
        return 1
    print("ci placement guard: R1/R2/R3/R4 をすべて満たす")
    return 0


def _selftest() -> int:
    """恒真でないことの実測。fixture の repo を作り、同じ main() を subprocess で通す。"""
    import subprocess
    import tempfile

    ng = 0

    def run(root: Path) -> int:
        env = dict(os.environ, AEGIS_CI_PLACEMENT_ROOT=str(root))
        return subprocess.run(
            [sys.executable, str(Path(__file__).resolve())],
            env=env, capture_output=True, text=True,
        ).returncode

    def ck(name: str, want: int, got: int) -> None:
        nonlocal ng
        if want == got:
            print(f"  OK  {name}")
        else:
            print(f"  NG  {name} (expect rc={want} got rc={got})")
            ng += 1

    def write(root: Path, rel: str, body: str) -> None:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")

    WF_OK = ("name: t\non:\n  pull_request:\njobs:\n"
             "  heavy:\n    runs-on: [self-hosted, linux, aegis-azure]\n"
             "    steps:\n      - run: true\n")
    WF_BACK_ON_WORKSTATION = ("name: t\non:\n  pull_request:\njobs:\n"
                              "  heavy:\n    runs-on: [self-hosted, macos-arm64, aegis-local]\n"
                              "    steps:\n      - run: true\n")
    MAN_OK = "w.yml | heavy | aegis-azure | 専用 host\n"

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)

        a = t / "a"
        write(a, ".github/workflows/w.yml", WF_OK)
        write(a, "ops/ci_placement.manifest", MAN_OK)
        ck("宣言どおりに走っていれば通る", 0, run(a))

        # **本命の対照**: 実行先を作業機に戻したら赤。これが赤にならないなら、
        # この guard は何も守っていない。
        b = t / "b"
        write(b, ".github/workflows/w.yml", WF_BACK_ON_WORKSTATION)
        write(b, "ops/ci_placement.manifest", MAN_OK)
        ck("実行先が作業機に戻れば落ちる", 1, run(b))

        # 新しい job を足して宣言に書かない = 取りこぼし。
        c = t / "c"
        write(c, ".github/workflows/w.yml",
              WF_OK + "  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
        write(c, "ops/ci_placement.manifest", MAN_OK)
        ck("宣言に無い job が在れば落ちる", 1, run(c))

        # 宣言が実在しない job を指している = 消した job の宣言だけが残る形。
        d = t / "d"
        write(d, ".github/workflows/w.yml", WF_OK)
        write(d, "ops/ci_placement.manifest", MAN_OK + "w.yml | gone | aegis-azure | 消えた job\n")
        ck("宣言が実在しない job を指していれば落ちる", 1, run(d))

        # 例外に理由が無い = 黙って例外を増やす道。
        e = t / "e"
        write(e, ".github/workflows/w.yml", WF_BACK_ON_WORKSTATION)
        write(e, "ops/ci_placement.manifest", "! w.yml | heavy | macos-arm64 | \n")
        ck("例外に理由が無ければ落ちる", 1, run(e))

        # 理由つきの例外は通る (出荷の macOS build がこれ)。
        f = t / "f"
        write(f, ".github/workflows/w.yml", WF_BACK_ON_WORKSTATION)
        write(f, "ops/ci_placement.manifest",
              "! w.yml | heavy | macos-arm64 | Apple 署名は macOS でしか作れない\n")
        ck("理由つきの例外は通る", 0, run(f))

        # 宣言そのものが無い = 不在を合格と読まない。
        g = t / "g"
        write(g, ".github/workflows/w.yml", WF_OK)
        ck("宣言が無ければ落ちる (不在を合格と読まない)", 1, run(g))

    if ng == 0:
        print("SELFTEST PASS — 実行先の戻り・宣言外の job・陳腐な宣言・理由なき例外を落とす")
        return 0
    print(f"SELFTEST: {ng} 件の期待が破れている", file=sys.stderr)
    return 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(_selftest())
    sys.exit(main())
