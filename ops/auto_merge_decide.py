#!/usr/bin/env python3
"""auto_merge_decide.py — この PR の merge を機械に任せてよいか、を 1 か所で決める。

なぜ在るか (2026-09-16):
    これまで merge を実行していたのは人のアカウントだった (直近 15 件すべて)。
    形は「CI が緑になったら merge する」だが、**緑を見て次の行動を起こすのは
    作業機に居る人**で、その人が居ない時間は経路ごと止まる。検知役に人を置く形は
    この製品が無くそうとしているものそのものなので、判定から実行までを機械に渡す。

    渡すときに危ないのは「条件を workflow の if: 式に書く」形。式は試験できず、
    赤にも緑にもならないまま静かに間違える。だからここに出し、**offline で試験
    できる 1 つの関数**にした。workflow はこの判定を呼ぶだけ。

何を見るか (すべて「任せない」側に倒れる条件):
    base      main 以外に向いた PR は対象外
    fork      別 repo からの PR は対象外
    draft     draft は「まだ」の宣言。人が ready にするまで武装しない
    bot       bot が開いた PR は既定で武装しない。これが「機械の push で機械が
              再発火する」輪を切る最後の 1 枚。
              **例外は宣言で名指しした bot だけ** (`ops/required_checks.json` の
              `allowed_bot_authors`)。この repo では dependabot がそれに当たる —
              依存更新は放置するほど危険になる種類の PR で、可否の判定は CI が行う。
              名指しなので、別の bot が現れても勝手には通らない。
    label     `no-auto-merge` が付いていれば人が握る。draft にしたくない時の口

終了コード:
    0  判定できた (武装するかどうかは GITHUB_OUTPUT / stdout に出す)
    2  判定できなかった。**これは「問題なし」ではない** — 入力が読めない時に
       緑を返すと、判定していないものを緑と呼ぶことになる
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BASE_BRANCH = "main"
HOLD_LABEL = "no-auto-merge"
DECLARATION = Path(__file__).resolve().parent / "required_checks.json"


def allowed_bot_authors() -> set[str]:
    """宣言で名指しされた bot だけが、bot 拒否の例外になる。

    読めない宣言は**例外なし**に倒す: 例外の一覧が読めない時に例外を広げるのは、
    統制の向きが逆。
    """
    try:
        doc = json.loads(DECLARATION.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    names = doc.get("allowed_bot_authors")
    if not isinstance(names, list):
        return set()
    return {str(n) for n in names if isinstance(n, str) and n}


class Unmeasurable(Exception):
    """入力が読めない。緑でも赤でもなく 2。"""


def _is_bot(user: dict) -> bool:
    if str(user.get("type", "")).lower() == "bot":
        return True
    return str(user.get("login", "")).endswith("[bot]")


def decide(event: dict) -> tuple[bool, str]:
    """(武装するか, 理由) を返す。理由は必ず 1 行で、log に出す前提。"""
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        raise Unmeasurable("event に pull_request が無い — これは PR の event ではない")

    base = pr.get("base") or {}
    head = pr.get("head") or {}
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise Unmeasurable("base / head が読めない")

    base_ref = base.get("ref")
    if base_ref is None:
        raise Unmeasurable("base.ref が無い")
    if base_ref != BASE_BRANCH:
        return False, f"base が {base_ref} — 機械に渡すのは {BASE_BRANCH} 向けだけ"

    base_repo = (base.get("repo") or {}).get("full_name")
    head_repo = (head.get("repo") or {}).get("full_name")
    if not base_repo:
        raise Unmeasurable("base.repo.full_name が無い")
    if head_repo != base_repo:
        return False, f"fork からの PR ({head_repo!r}) — self-hosted runner の上では武装しない"

    if pr.get("draft") is True:
        return False, "draft — 「まだ」の宣言なので武装しない"

    user = pr.get("user")
    if not isinstance(user, dict):
        raise Unmeasurable("pull_request.user が読めない")
    if _is_bot(user):
        login = str(user.get("login") or "")
        if login not in allowed_bot_authors():
            return False, f"bot が開いた PR ({login!r}) — 宣言で名指しされていない"

    labels = pr.get("labels") or []
    names = {str((lbl or {}).get("name", "")) for lbl in labels if isinstance(lbl, dict)}
    if HOLD_LABEL in names:
        return False, f"label {HOLD_LABEL!r} が付いている — 人が握ると宣言されている"

    return True, "武装する: main 向け / 同一 repo / ready / 人が開いた / 保留 label 無し"


def _emit(arm: bool, reason: str) -> None:
    print(f"auto-merge: {'ARM' if arm else 'HOLD'} — {reason}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"arm={'true' if arm else 'false'}\n")
            fh.write(f"reason={reason}\n")


# --------------------------------------------------------------------------
# 対照。武装する側 (陽性) と、条件ごとに武装しない側 (陰性) の両方を持つ。
# 片側しか無い対照は「常に HOLD を返す実装」を緑にしてしまう。
# --------------------------------------------------------------------------
def _base_event() -> dict:
    return {
        "pull_request": {
            "number": 1,
            "draft": False,
            "user": {"login": "a-human", "type": "User"},
            "labels": [{"name": "security"}],
            "base": {"ref": "main", "repo": {"full_name": "o/r"}},
            "head": {"ref": "topic", "repo": {"full_name": "o/r"}},
        }
    }


def self_test() -> int:
    cells: list[tuple[str, dict, object]] = []

    cells.append(("ready な PR は武装する (陽性対照)", _base_event(), True))

    e = _base_event()
    e["pull_request"]["draft"] = True
    cells.append(("draft は武装しない", e, False))

    e = _base_event()
    e["pull_request"]["base"]["ref"] = "release/x"
    cells.append(("main 以外は武装しない", e, False))

    e = _base_event()
    e["pull_request"]["head"]["repo"]["full_name"] = "fork/r"
    cells.append(("fork は武装しない", e, False))

    e = _base_event()
    e["pull_request"]["user"] = {"login": "some-other[bot]", "type": "Bot"}
    cells.append(("宣言に無い bot の PR は武装しない (輪を切る)", e, False))

    e = _base_event()
    e["pull_request"]["user"] = {"login": "renovate[bot]", "type": "User"}
    cells.append(("type が User でも login が [bot] で、宣言に無ければ武装しない", e, False))

    # 陽性対照: 宣言で名指しした bot は通る。これが無いと「全 bot を拒否する実装」が
    # 緑のままになり、この repo の目的 (溜まった dependabot を機械が捌く) が死ぬ。
    e = _base_event()
    e["pull_request"]["user"] = {"login": "dependabot[bot]", "type": "Bot"}
    cells.append(("宣言で名指しした bot (dependabot) は武装する", e, True))

    e = _base_event()
    e["pull_request"]["labels"] = [{"name": "security"}, {"name": HOLD_LABEL}]
    cells.append((f"{HOLD_LABEL} が付いていれば武装しない", e, False))

    cells.append(("PR event でなければ判定不能 (2)", {"push": {}}, Unmeasurable))
    e = _base_event()
    del e["pull_request"]["base"]["ref"]
    cells.append(("base.ref が無ければ判定不能 (2)", e, Unmeasurable))
    e = _base_event()
    e["pull_request"]["user"] = "a-human"
    cells.append(("user が文字列なら判定不能 (2)", e, Unmeasurable))

    bad = 0
    for name, event, want in cells:
        try:
            got: object = decide(event)[0]
        except Unmeasurable:
            got = Unmeasurable
        ok = got is want if want is Unmeasurable else got == want
        print(f"  {'[OK]  ' if ok else '[FAIL]'} {name}")
        if not ok:
            bad += 1
            print(f"         want={want} got={got}")
    print(f"auto-merge decide self-test: {len(cells) - bad}/{len(cells)}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--event", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if not args.event:
        print("COULD NOT MEASURE: event の path が無い (--event / GITHUB_EVENT_PATH)", file=sys.stderr)
        return 2
    try:
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
        arm, reason = decide(event)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"COULD NOT MEASURE: {exc}", file=sys.stderr)
        return 2
    except Unmeasurable as exc:
        print(f"COULD NOT MEASURE: {exc}", file=sys.stderr)
        return 2
    _emit(arm, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
