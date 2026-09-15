#!/usr/bin/env python3
"""release-attestation の invariant 6 を、機械で確かめる。

`.github/workflows/release-attestation.yml` の invariant 6 はこう書いている:

    Runner trust boundary = repository WRITE access. ... a write-capable actor
    can always bring their own workflow to the self-hosted runner. The dispatch
    ref guard on the self-hosted jobs prevents mistakes, not adversaries; the
    control is repository rulesets on `main` (pull-request only) and on `v*`
    tags (restricted creation) — **owner-side settings this file cannot enforce**.

「この file では強制できない」で止めると、統制は誰にも確かめられないまま残る。
2026-09-15 に実測したところ、書かれていた 2 つのうち

  - `v*` tag の作成制限   → **存在しなかった** (ruleset 0 件)
  - `ci-gate` が必須 check → **存在しなかった** (required_status_checks = null)

の両方が実在しなかった。**書いた本人が一番信じている統制ほど、検査が抜ける。**

**どこで走るか**: repo の CI では走らせない。CI の既定 token には repo 設定を読む
権限が無く (`administration` は job の permissions に指定できる名前ですらない —
2026-09-15 に指定して workflow ごと壊した)、CI に置くと必ず「読めない」になる。
必ず NOT-MEASURED になる検査を CI に置くのは、緑の意味を薄めるだけ。

資格情報のある端末から lane 全体を見る時に走らせる:

    python3 scripts/verify_release_controls.py          # この repo
    GITHUB_REPOSITORY=<owner>/<repo> python3 ...        # 他 repo

設定は file の外に在るので API を読む — 権限が無い時は「検査していない」と言って
exit 2 で終わる (未認証を全 OK と読まない)。**保護が無い (404) は判定そのもの**
なので exit 1 で落とす。

終了コード: 0 = 統制が実在する / 1 = 欠けている / 2 = 検査できなかった
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = os.environ.get("GITHUB_REPOSITORY", "nemotek-inc/aegis-trust")
API = "https://api.github.com"


def api(path: str):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        token = out.stdout.strip() if out.returncode == 0 else ""
    if not token:
        raise LookupError("token が無い")
    req = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main() -> int:
    fails: list[str] = []
    print(f"release controls — {REPO}")

    # 404 と 403 を混ぜない。**404 は「保護が無い」という判定そのもの**で、
    # 「読めなかった」ではない。混ぜると、保護がゼロの repo が NOT-MEASURED で
    # 素通りする — 不在を合格と読まない規律の逆になる (2026-09-15、対照を取って
    # 自分のこの誤りを見つけた)。
    try:
        prot = api(f"/repos/{REPO}/branches/main/protection")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            prot = {}
            fails.append("main に branch 保護が 1 つも無い (404) — 直接 push を止めるものが無い")
        elif exc.code in (401, 403):
            print(f"  NOT-MEASURED  保護設定を読む権限が無い ({exc.code}) — 未認証を全 OK と読まない")
            return 2
        else:
            print(f"  NOT-MEASURED  保護設定を読めない ({exc})")
            return 2
    except (urllib.error.URLError, LookupError) as exc:
        print(f"  NOT-MEASURED  保護設定を読めない ({exc}) — 未認証を全 OK と読まない")
        return 2

    if not prot.get("required_pull_request_reviews"):
        fails.append("main に pull request 必須が無い — 直接 push で自前の workflow を持ち込める")
    else:
        print("  OK  main は pull request 必須")

    contexts = ((prot.get("required_status_checks") or {}).get("contexts")) or []
    if "ci-gate" not in contexts:
        fails.append(f"ci-gate が必須 check に無い (現在: {contexts or 'なし'})")
    else:
        print("  OK  ci-gate が必須 check")

    if not (prot.get("enforce_admins") or {}).get("enabled"):
        fails.append("enforce_admins が無効 — 管理者が保護を素通りできる")
    else:
        print("  OK  保護は管理者にも適用される")

    try:
        rulesets = api(f"/repos/{REPO}/rulesets")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        print(f"  NOT-MEASURED  ruleset を読めない ({exc})")
        return 2

    tag_rule = [
        r for r in rulesets
        if r.get("target") == "tag" and r.get("enforcement") == "active"
    ]
    if not tag_rule:
        fails.append(
            "v* tag の作成を制限する ruleset が無い — tag を作れる相手は自前の "
            "workflow 版を self-hosted release runner で走らせられる"
        )
    else:
        print(f"  OK  tag ruleset が有効 ({len(tag_rule)} 件)")

    if fails:
        for f in fails:
            print(f"  FAIL  {f}")
        print(f"release controls: 欠けている統制 {len(fails)} 件")
        return 1
    print("release controls: invariant 6 の統制はすべて実在する")
    return 0


if __name__ == "__main__":
    sys.exit(main())
