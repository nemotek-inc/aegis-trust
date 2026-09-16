#!/usr/bin/env python3
"""merge_on_green.py — 緑を見て merge する役を、人からもアカウントからも外す。

なぜこの形なのか (2026-09-16):
    最初の設計は GitHub App の installation token を使うものだった。**App の作成には
    browser の click が要る** ので、経路の最後の 1 手が人に残った。それは
    「人が検知役・実行役として介在しない」という目的に反する — 経路を自動化しながら
    起動に人を要求したら、止まる場所が移っただけ。

    この版は `GITHUB_TOKEN` だけで動く。workflow の `permissions:` で
    contents:write / pull-requests:write / checks:read / actions:write を明示すれば足りる
    (既定が read でも、明示した scope は取れる — 本 repo の ledger-verify が
    id-token:write で実証済み)。**新しい資格情報も、人の操作も要らない。**

「緑」の定義を 2 つ作らない:
    判定に使う必須 check の一覧は `ops/required_checks.json` の 1 本だけ。
    branch protection (GitHub 側の強制) も同じ file から apply する。
    ここが 2 か所に分かれると、甘い方が勝つ。

何を確かめてから merge するか:
    1. PR が武装条件を満たす (ops/auto_merge_decide.py — draft / fork / bot / 保留 label)
    2. 宣言された必須 check が **その commit で全部 success**
       — 「まだ来ていない」は success ではない。1 本でも欠けたら merge しない
    3. PR が mergeable (conflict していない)

merge の後:
    main への push は bot 由来なので workflow を再発火させない。**post-merge の検査が
    消えるのを放置しない** — merge した直後に acceptance を main へ dispatch する。

終了コード: 0 = merge した / 3 = まだ条件を満たさない (赤ではない) / 1 = 異常 / 2 = 測れない
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "ops" / "required_checks.json"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")

sys.path.insert(0, str(ROOT / "ops"))
from auto_merge_decide import decide  # noqa: E402
from auto_merge_decide import Unmeasurable as DecideUnmeasurable  # noqa: E402


class Unmeasurable(Exception):
    """測れなかった。緑でも赤でもなく 2。"""


def _api(path: str, token: str, method: str = "GET", body: dict | None = None) -> object:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"{API}/{path}",
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise Unmeasurable(f"{method} {path}: HTTP {exc.code} {detail}") from exc
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        raise Unmeasurable(f"{method} {path}: {exc}") from exc


def required_contexts(path: Path = DECLARATION) -> list[str]:
    if not path.exists():
        raise Unmeasurable(f"必須 check の宣言が無い: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Unmeasurable(f"{path}: {exc}") from exc
    contexts = doc.get("required_contexts")
    if not isinstance(contexts, list) or not contexts or not all(isinstance(c, str) and c for c in contexts):
        raise Unmeasurable(f"{path}: required_contexts が非空の文字列配列でない")
    return contexts


def judge_checks(contexts: list[str], check_runs: list[dict]) -> tuple[bool, list[str]]:
    """宣言された check が **その commit で全部 success** か。

    「来ていない」を緑と数えない。同名が複数あれば **最新の 1 本**で判定する
    (再実行した check の古い結果を拾わないため)。
    """
    lines: list[str] = []
    latest: dict[str, dict] = {}
    for run in check_runs:
        if not isinstance(run, dict):
            raise Unmeasurable(f"check run が dict でない: {run!r}")
        name = run.get("name")
        if not isinstance(name, str):
            raise Unmeasurable(f"check run に name が無い: {run!r}")
        started = str(run.get("started_at") or "")
        prev = latest.get(name)
        if prev is None or started >= str(prev.get("started_at") or ""):
            latest[name] = run

    ok = True
    for ctx in contexts:
        run = latest.get(ctx)
        if run is None:
            lines.append(f"  未着  {ctx}: この commit に check が無い — 「まだ」は緑ではない")
            ok = False
            continue
        status = str(run.get("status"))
        conclusion = str(run.get("conclusion"))
        if status != "completed":
            lines.append(f"  途中  {ctx}: {status}")
            ok = False
        elif conclusion != "success":
            lines.append(f"  赤    {ctx}: {conclusion}")
            ok = False
        else:
            lines.append(f"  緑    {ctx}")
    return ok, lines


# --------------------------------------------------------------------------
# 対照
# --------------------------------------------------------------------------
def _run(name: str, conclusion: str = "success", status: str = "completed", started: str = "2026-09-16T00:00:00Z") -> dict:
    return {"name": name, "status": status, "conclusion": conclusion, "started_at": started}


def self_test() -> int:
    ctx = ["a", "b"]
    cells: list[tuple[str, list[dict], object]] = [
        ("宣言された check が全部緑なら merge してよい (陽性対照)", [_run("a"), _run("b")], True),
        ("1 本が赤なら merge しない", [_run("a"), _run("b", "failure")], False),
        ("1 本が未着なら merge しない — 「まだ」は緑ではない", [_run("a")], False),
        ("1 本が途中なら merge しない", [_run("a"), _run("b", "", "in_progress")], False),
        ("宣言外の check が赤でも判定に影響しない", [_run("a"), _run("b"), _run("z", "failure")], True),
        (
            "同名が 2 本あるとき新しい方で判定する (再実行で緑)",
            [_run("a"), _run("b", "failure", started="2026-09-16T00:00:00Z"), _run("b", "success", started="2026-09-16T01:00:00Z")],
            True,
        ),
        (
            "同名が 2 本あるとき新しい方で判定する (再実行で赤)",
            [_run("a"), _run("b", "success", started="2026-09-16T00:00:00Z"), _run("b", "failure", started="2026-09-16T01:00:00Z")],
            False,
        ),
        ("check の形が違えば判定不能 (2)", [_run("a"), {"conclusion": "success"}], Unmeasurable),
    ]

    bad = 0
    for name, runs, want in cells:
        try:
            got: object = judge_checks(ctx, runs)[0]
        except Unmeasurable:
            got = Unmeasurable
        ok = got is want if want is Unmeasurable else got == want
        print(f"  {'[OK]  ' if ok else '[FAIL]'} {name}")
        if not ok:
            bad += 1
            print(f"         want={want} got={got}")

    # 宣言が読めて、形が壊れていないこと。repo ごとの中身は宣言側の責任なので
    # ここでは名前を固定しない — 固定すると、宣言を直すたびに無関係な赤が出る。
    try:
        contexts = required_contexts()
        ok = bool(contexts) and len(set(contexts)) == len(contexts)
    except Unmeasurable:
        ok = False
        contexts = []
    print(f"  {'[OK]  ' if ok else '[FAIL]'} 宣言から必須 check を読める・重複が無い ({contexts})")
    if not ok:
        bad += 1

    total = len(cells) + 1
    print(f"merge-on-green self-test: {total - bad}/{total}")
    return 1 if bad else 0


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "nemotek-inc/aegis-boundary-core"))
    ap.add_argument("--sha", help="判定する commit (既定: GITHUB_EVENT の workflow_run.head_sha)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="判定だけして merge しない")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("COULD NOT MEASURE: GH_TOKEN が無い", file=sys.stderr)
        return 2

    sha = args.sha
    if not sha:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if not event_path or not Path(event_path).exists():
            print("COULD NOT MEASURE: 判定する commit が決まらない", file=sys.stderr)
            return 2
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        sha = ((event.get("workflow_run") or {}).get("head_sha")) or ""
        if not sha:
            print("COULD NOT MEASURE: workflow_run.head_sha が無い", file=sys.stderr)
            return 2

    try:
        contexts = required_contexts()
        pulls = _api(f"repos/{args.repo}/commits/{sha}/pulls", token)
        if not isinstance(pulls, list):
            raise Unmeasurable("PR 一覧が list でない")
        open_pulls = [p for p in pulls if isinstance(p, dict) and p.get("state") == "open"]
        if not open_pulls:
            print(f"この commit ({sha[:8]}) に open な PR が無い — 何もしない")
            return 3
        if len(open_pulls) > 1:
            raise Unmeasurable(f"commit {sha[:8]} に open な PR が {len(open_pulls)} 件 — どれを merge すべきか決まらない")
        number = open_pulls[0].get("number")

        # 一覧の PR は情報が薄い (draft / mergeable が無い)。判定は必ず単体取得で行う。
        pr = _api(f"repos/{args.repo}/pulls/{number}", token)
        if not isinstance(pr, dict):
            raise Unmeasurable("PR が dict でない")
        try:
            arm, reason = decide({"pull_request": pr})
        except DecideUnmeasurable as exc:
            raise Unmeasurable(f"武装条件を判定できない: {exc}") from exc
        print(f"PR #{number}: {'ARM' if arm else 'HOLD'} — {reason}")
        if not arm:
            return 3

        doc = _api(f"repos/{args.repo}/commits/{sha}/check-runs?per_page=100", token)
        if not isinstance(doc, dict):
            raise Unmeasurable("check-runs の返しが期待した形ではない")
        green, lines = judge_checks(contexts, doc.get("check_runs") or [])
    except Unmeasurable as exc:
        print(f"COULD NOT MEASURE: {exc}", file=sys.stderr)
        return 2

    print(f"宣言された必須 check ({len(contexts)} 本) を commit {sha[:8]} で照合:")
    for line in lines:
        print(line)
    if not green:
        print("まだ全部緑ではない — merge しない (赤ではなく、待ち)")
        return 3
    if pr.get("mergeable") is False:
        print("conflict している — merge しない")
        return 3
    if args.dry_run:
        print("dry-run: ここで merge する")
        return 0

    try:
        _api(
            f"repos/{args.repo}/pulls/{number}/merge",
            token,
            method="PUT",
            body={"merge_method": "squash", "sha": sha},
        )
    except Unmeasurable as exc:
        print(f"merge できなかった: {exc}", file=sys.stderr)
        return 1
    print(f"merge した: PR #{number} ({sha[:8]}) → main")

    # bot の push は workflow を再発火させない。**post-merge の検査を消したままにしない。**
    doc = json.loads(DECLARATION.read_text(encoding="utf-8"))
    wf = doc.get("post_merge_verify_workflow")
    if wf:
        try:
            _api(f"repos/{args.repo}/actions/workflows/{wf}/dispatches", token, method="POST", body={"ref": "main"})
            print(f"main の事後検査を起動した: {wf}")
        except Unmeasurable as exc:
            # ここで落ちても merge は済んでいる。**黙って済ませない** — 赤にして残す。
            print(f"merge は済んだが main の事後検査を起動できなかった: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
