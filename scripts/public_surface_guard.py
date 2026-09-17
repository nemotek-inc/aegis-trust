#!/usr/bin/env python3
"""public_surface_guard — この repo は公開されている。公開してよいものだけが在るかを見る。

なぜ在るか (2026-09-16 に実際に起きた):
    この SDK repo は PUBLIC、密結合している core repo は PRIVATE。両者を跨いだ
    調査をしていた時、**宛先の可視性を確認せずに公開側へ起票した**。1 件は private
    repo のソース抜粋 (trait 定義と struct) を含み、約 25 分間公開された。
    もう 1 件は未公開の商用構想を含んでいた。どちらも transfer で消したが、
    public events の外部アーカイブと watcher 宛の通知は回収できない。

    **人間の指摘で発覚した。機械では止まらなかった。**

    この製品は「宣言されていないものは境界の外に出ない」を売っている。その製品を
    作っている repo 群に、同じ性質の境界が人の注意力の上にしか乗っていなかった。
    注意力は 1 回で尽きる。この門はその 1 回を機械側へ移す。

設計の要点 — **検査そのものが漏洩経路になってはならない**:
    公開 repo に「private に何が在るか」の一覧を置いたら、門が漏洩装置になる。
    だから規則は 2 段構えで、主軸は**秘密を必要としない構造規則**にしてある。

      R1  この repo に存在しない source path への参照
          → 実在しない自分の file を指す参照は、**別の repo の file を指している**。
            2026-09-16 に漏れたのは、まさにこの形 (`…/src/backends/mod.rs`)。
            判定に private の語彙を 1 つも使わない。
      R2  この repo に存在しない言語の code fence
          → tracked file の拡張子から「この repo の言語」を作り、それ以外の言語で
            書かれた囲みを見つける。この repo の code でない code が貼られている。
            これも private の語彙を使わない。
      R3  語彙 (**hash 化**)
          → R1/R2 で表現できないもの (private repo 名、内部 crate 名、未公開の
            商用語) のための逃げ道。値ではなく sha256 を置く。
      R4  宣言の健全性
          → 語彙 file が無い / 読めない / 生成印が無い → **落とす**。
            測れなかったものを緑に丸めない。

    **R3 の限界を正直に書く**: hash 化は「一覧をそのまま読まれること」を防ぐだけで、
    語彙が短く推測可能なら総当たりで戻せる。秘匿の強度ではなく、**うっかり読める
    状態にしない**ための措置。だから R3 は補助で、主軸は R1/R2。

    同じ理由で、**この門は一致した中身を一切出力しない**。file と行番号と規則 ID
    だけを言う。公開 CI の log は公開なので、検出値を出したらそこで再公開になる。

例外:
    `scripts/public_surface_allow.txt` に 1 行 1 件、`<path> | <規則> | <理由>`。
    理由が空の行は宣言として扱わない (黙って増やせる例外は統制ではない)。

終了コード: 0 = 公開してよいものだけ / 1 = 公開してはならないものが在る
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO_DEFAULT = Path(__file__).resolve().parents[1]

MARKERS_NAME = "scripts/private_markers.sha256"
ALLOW_NAME = "scripts/public_surface_allow.txt"

# 走査対象にする拡張子 (テキストとして読めるもの)。tracked でもこれ以外は読まない。
TEXT_SUFFIXES = {
    ".md", ".txt", ".rst", ".py", ".ts", ".tsx", ".js", ".mjs", ".cjs",
    ".json", ".yml", ".yaml", ".toml", ".sh", ".cfg", ".ini", ".service",
    ".typed", ".log", "",
}

# R1 が source path と見なす拡張子。**この repo に無い言語も入れる** —
# 無い言語の path こそ他 repo のものだから。
SOURCE_SUFFIXES = {
    ".rs", ".py", ".ts", ".tsx", ".js", ".mjs", ".go", ".java", ".kt",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".swift", ".rb", ".php", ".cs",
    ".toml", ".sh", ".sql", ".proto",
}

# 手引きの中の穴埋め。これらで始まる path は「実在しない」ではなく「書き手が
# 埋める場所」なので R1 の対象外。
PLACEHOLDER_HEADS = {
    "path", "paths", "your", "my", "example", "examples", "sample", "samples",
    "foo", "bar", "baz", "some", "any", "dir", "directory", "folder", "repo",
    "project", "app", "usr", "etc", "var", "opt", "tmp", "home", "site-packages",
    "node_modules", "dist", "build", "target", "venv", ".venv", "__pycache__",
}

# path らしき token。2 segment 以上で、末尾に拡張子が在るもの。
PATH_RE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/){1,8}[\w.-]+\.[A-Za-z0-9]{1,6})(?![\w/])")

# 生成物 / 依存物の置き場。ここを通る path は「この repo に無い」ことに意味が無い
# (`dist/` は build の出力で、tracked file として存在しないのが正常)。
BUILD_SEGMENTS = {
    "dist", "build", "out", "target", "node_modules", "coverage", ".venv",
    "venv", "site-packages", "__pycache__", ".next", ".cache", "vendor",
    "htmlcov", ".tox", ".mypy_cache", ".pytest_cache", "egg-info",
}

# 生成 file。中身は道具が書くので、走査しても人の判断は 1 つも入っていない。
GENERATED_FILES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
    "Cargo.lock", "uv.lock", "requirements.lock",
}

# import / require / export の行。ここに出る path は module 指定子であって、
# 「別 repo の file を指す参照」ではない。
MODULE_STMT_RE = re.compile(
    r"\b(?:import|export|require|from|resolve|__dirname|importlib|include)\b"
)

# 言語つき code fence の開始行。
FENCE_RE = re.compile(r"^\s*(?:```|~~~)\s*([A-Za-z][\w+#-]*)\s*$")

# 拡張子 -> fence tag。この repo に tracked file が在る言語だけが「この repo の言語」。
SUFFIX_TO_LANGS = {
    ".py": {"python", "py", "python3", "pycon", "ipython"},
    ".ts": {"typescript", "ts"},
    ".tsx": {"tsx", "typescript"},
    ".js": {"javascript", "js"},
    ".mjs": {"javascript", "js"},
    ".cjs": {"javascript", "js"},
    ".json": {"json", "jsonc", "json5"},
    ".yml": {"yaml", "yml"},
    ".yaml": {"yaml", "yml"},
    ".toml": {"toml"},
    ".sh": {"bash", "sh", "shell", "console", "shell-session", "zsh"},
    ".service": {"ini", "systemd"},
    ".sql": {"sql"},
    ".rs": {"rust", "rs"},
    ".go": {"go", "golang"},
    ".java": {"java"},
    ".c": {"c"},
    ".cpp": {"cpp", "c++"},
    ".rb": {"ruby", "rb"},
    ".php": {"php"},
    ".cs": {"csharp", "cs"},
    ".swift": {"swift"},
    ".kt": {"kotlin"},
    ".proto": {"protobuf", "proto"},
}

# 言語に依らない fence tag (何の repo でも出てよい)。
NEUTRAL_LANGS = {
    "", "text", "txt", "plain", "plaintext", "none", "output", "log",
    "diff", "patch", "http", "html", "css", "xml", "csv", "tsv", "md",
    "markdown", "mermaid", "dockerfile", "docker", "make", "makefile",
    "env", "dotenv", "properties", "ini", "conf", "config", "regex",
    "console", "terminal", "tree", "ascii", "svg", "graphql", "hcl",
}

# R3 の語彙正規化: 小文字化し、区切りを削る。`Aegis-Core` と `aegis_core` を
# 同じ 1 語として扱う (綴りを変えるだけで抜けられる門にしない)。
NORM_RE = re.compile(r"[^a-z0-9]+")

# R3 が語として切り出す単位。**1 語 = 1 token ではない。**
#
# 最初に書いた版は `[A-Za-z][A-Za-z0-9_.-]{4,63}` で token を取っていた。private
# 側で陽性対照 (漏洩していた当時の tree をその語彙で走査する) を走らせたら
# **0 件**だった: 漏れていた語は `…/<語>.<拡張子>:<記号>` の形に埋まっていて、
# token としては拡張子まで含まれ、別の綴りになっていたため。
#
# (この注釈は当初その実例を綴りごと書いていた。**この file は公開されるので、
#  それ自体が同じ種類の漏洩だった。** private 側の走査が当てて分かった —
#  当時この門は自分を全規則から免除していたので、門では捕まらなかった。
#  下の `exempt_paths_rule` はその修理。例は形だけ書く。)
#
# だから英数字の連なりに割ってから、連続する窓を繋いで比べる。窓をどこまで
# 広げるかは語彙 file の `# max_segments:` が**唯一の定義点**で、private 側の
# 生成器が入れる。**書かれていなければ落とす** — 窓の幅を推測で決めると、
# 当たらない語ができたことに誰も気づけない。
SEGMENT_RE = re.compile(r"[A-Za-z0-9]+")


class GuardError(RuntimeError):
    """測れなかった。緑にしない。"""


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise GuardError(f"git {' '.join(args)} が失敗: {proc.stderr.strip()[:200]}")
    return proc.stdout


def tracked_files(repo: Path, ref: str | None) -> list[str]:
    """走査対象。ref を与えれば、その ref の tracked file を見る。"""
    if ref:
        out = _git(repo, "ls-tree", "-r", "--name-only", ref)
    else:
        out = _git(repo, "ls-files")
    files = [line for line in out.splitlines() if line.strip()]
    if not files:
        raise GuardError("tracked file が 0 件 — 走査できていない")
    return files


def read_text(repo: Path, ref: str | None, path: str) -> str | None:
    if ref:
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{path}"],
            capture_output=True, check=False,
        )
        if proc.returncode != 0:
            return None
        raw = proc.stdout
    else:
        fp = repo / path
        if not fp.is_file():
            return None
        raw = fp.read_bytes()
    if b"\0" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def normalize(token: str) -> str:
    return NORM_RE.sub("", token.lower())


def line_windows(line: str, max_segments: int):
    """行から「連続する英数字の窓」を正規化して返す。"""
    segments = SEGMENT_RE.findall(line)
    for start in range(len(segments)):
        joined = ""
        for width in range(max_segments):
            if start + width >= len(segments):
                break
            joined += segments[start + width].lower()
            if len(joined) >= 5:
                yield joined


def load_markers(repo: Path) -> tuple[set[str], str, int]:
    """hash 化された語彙を読む。**無い / 読めない / 生成印が無い → 落とす。**"""
    fp = repo / MARKERS_NAME
    if not fp.is_file():
        raise GuardError(
            f"{MARKERS_NAME} が無い — 語彙で測れない。"
            "private 側の生成器で作って commit すること"
        )
    digests: set[str] = set()
    generated = ""
    max_segments = 0
    for lineno, raw in enumerate(fp.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if line.startswith("#"):
            marker = line.lstrip("#").strip()
            if marker.startswith("generated:"):
                generated = marker.split(":", 1)[1].strip()
            elif marker.startswith("max_segments:"):
                value = marker.split(":", 1)[1].strip()
                if value.isdigit():
                    max_segments = int(value)
            continue
        if not line:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", line):
            raise GuardError(
                f"{MARKERS_NAME}:{lineno} が sha256 の形ではない — "
                "**値を平文で置いていないか確認すること** (置いたらこの file 自体が漏洩)"
            )
        digests.add(line)
    if not generated:
        raise GuardError(
            f"{MARKERS_NAME} の先頭に `# generated: <ISO8601>` が無い — "
            "いつの語彙か分からないものを根拠にしない"
        )
    if max_segments < 1:
        raise GuardError(
            f"{MARKERS_NAME} の先頭に `# max_segments: <n>` が無い — "
            "窓の幅を推測で決めると、当たらない語ができたことに誰も気づけない"
        )
    return digests, generated, max_segments


def load_allow(repo: Path) -> dict[tuple[str, str], str]:
    """宣言された例外。理由が無い行は例外として数えない。"""
    fp = repo / ALLOW_NAME
    allow: dict[tuple[str, str], str] = {}
    if not fp.is_file():
        return allow
    for lineno, raw in enumerate(fp.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 3 or not all(cells[:2]) or not cells[2]:
            raise GuardError(
                f"{ALLOW_NAME}:{lineno} は `<path> | <規則> | <理由>` の形でない "
                "(理由の空欄は宣言ではない)"
            )
        allow[(cells[0], cells[1])] = cells[2]
    return allow


def repo_languages(files: list[str]) -> set[str]:
    """tracked file の拡張子から「この repo の言語」を作る。"""
    langs: set[str] = set(NEUTRAL_LANGS)
    for path in files:
        suffix = Path(path).suffix.lower()
        langs |= SUFFIX_TO_LANGS.get(suffix, set())
    return langs


def _stem(path: str) -> str:
    """拡張子を落とした path。`.d.ts` のような二重拡張子も 1 段だけ落とす。"""
    return re.sub(r"\.[A-Za-z0-9]{1,6}$", "", path)


def scan(repo: Path, ref: str | None) -> tuple[list[str], list[str], dict]:
    files = tracked_files(repo, ref)
    tracked = set(files)
    # 末尾一致でも引けるようにする (`aegis-trust/python/…` のような repo 名つきの
    # 参照を「実在しない」と誤判定しないため)。
    tails: set[str] = set()
    stems: set[str] = set()
    for path in files:
        parts = path.split("/")
        for i in range(len(parts)):
            tail = "/".join(parts[i:])
            tails.add(tail)
            stems.add(_stem(tail))
            # build 後の綴りで書かれた参照も引けるようにする。
            stems.add(_stem(tail.replace("/src/", "/dist/", 1)))

    digests, generated, marker_width = load_markers(repo)
    allow = load_allow(repo)
    langs = repo_languages(files)

    fails: list[str] = []
    notes: list[str] = []
    stats = {
        "files": 0, "skipped": 0, "r1": 0, "r2": 0, "r3": 0,
        "markers": len(digests), "generated": generated,
        "allow": len(allow), "langs": len(langs),
    }

    # 門自身に関わる file の扱い。**規則ごとに分ける。**
    #
    # 最初は「この 3 つは走査しない」で済ませていた。2026-09-17、private 側の走査が
    # **この file の注釈に private の語が書かれている**ことを当てた。公開される file
    # なので、それ自体が同じ種類の漏洩であり、しかも **門が自分を免除していたので
    # 門では捕まらなかった**。免除の粒度が file だったことが欠陥。
    #
    #   語彙 file        全規則から外す (中身は digest であって語ではない)
    #   R1 (実在しない path)  門と例外 file は免除。説明のために実在しない path を
    #                         例示するのはこの 2 つの仕事で、自分の説明文で自分を
    #                         落とす門は統制ではない
    #   R2 / R3          **免除しない。** 説明文が private の語や他言語の code を
    #                    必要とする理由は無い。例は形だけ書けばよい
    GUARD_PATH = "scripts/public_surface_guard.py"
    exempt_all = {MARKERS_NAME}
    exempt_paths_rule = {ALLOW_NAME, GUARD_PATH}

    for path in files:
        if path in exempt_all:
            continue
        if Path(path).suffix.lower() not in TEXT_SUFFIXES:
            stats["skipped"] += 1
            continue
        if Path(path).name in GENERATED_FILES:
            # 道具が書いた file。人の判断が 1 つも入っていないので、走査しても
            # 「誰かが貼った」を見つけることにはならない。
            stats["skipped"] += 1
            continue
        text = read_text(repo, ref, path)
        if text is None:
            stats["skipped"] += 1
            continue
        stats["files"] += 1

        in_fence = False
        for lineno, line in enumerate(text.splitlines(), 1):
            fence = FENCE_RE.match(line)
            if fence and not in_fence:
                in_fence = True
                lang = fence.group(1).lower()
                if lang not in langs and (path, "R2") not in allow:
                    stats["r2"] += 1
                    fails.append(
                        f"R2 {path}:{lineno} — この repo に存在しない言語の "
                        f"code fence (この repo の code ではない code が貼られている)"
                    )
                continue
            if in_fence and re.match(r"^\s*(?:```|~~~)\s*$", line):
                in_fence = False
                continue

            # R1: 実在しない source path への参照。
            is_module_line = bool(MODULE_STMT_RE.search(line))
            for match in ([] if path in exempt_paths_rule
                          else PATH_RE.finditer(line)):
                token = match.group(1)
                if Path(token).suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                # 相対指定子は module の解決先であって repo 内の位置ではない。
                if token.startswith("./") or token.startswith("../"):
                    continue
                if is_module_line:
                    continue
                # 変数展開 (`$SCRIPT_DIR/…`, `${REPO_ROOT}/…`) は実行時に解決される
                # 位置であって、書かれた path ではない。
                before = line[max(0, match.start() - 1):match.start()]
                if before in {"$", "{", "%"}:
                    continue
                segments = token.split("/")
                if re.fullmatch(r"[A-Z][A-Z0-9_]*", segments[0]):
                    continue
                if any(seg.lower() in BUILD_SEGMENTS for seg in segments[:-1]):
                    continue
                head = segments[0].lower()
                if head in PLACEHOLDER_HEADS:
                    continue
                if token in tracked or token in tails:
                    continue
                # 拡張子を跨いで一致させる (`…/index.js` は tracked の
                # `…/index.ts` の build 後の綴り。別 repo の file ではない)。
                if _stem(token) in stems:
                    continue
                if (path, "R1") in allow:
                    continue
                stats["r1"] += 1
                fails.append(
                    f"R1 {path}:{lineno} — この repo に存在しない source path への参照 "
                    f"(別の repo の file を指している)"
                )

            # R3: 語彙 (hash 一致)。
            if digests:
                hit_here = False
                for norm in line_windows(line, marker_width):
                    if hit_here:
                        break
                    if hashlib.sha256(norm.encode()).hexdigest() in digests:
                        if (path, "R3") in allow:
                            continue
                        hit_here = True
                        stats["r3"] += 1
                        fails.append(
                            f"R3 {path}:{lineno} — 公開してはならない語彙に一致 "
                            f"(値はここには出さない。private 側の宣言を見ること)"
                        )

    for (p, rule), reason in sorted(allow.items()):
        notes.append(f"例外 {p} [{rule}] — {reason}")
    return fails, notes, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(REPO_DEFAULT), help="走査する repo")
    ap.add_argument("--ref", default=None, help="この ref の tracked file を見る (既定: 作業ツリー)")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    try:
        fails, notes, stats = scan(repo, args.ref)
    except GuardError as exc:
        # 測れなかったことを緑にしない。
        print(f"FAIL  測れなかった: {exc}")
        return 1

    print("public surface guard — 公開してよいものだけが在るか")
    print(
        f"  走査 {stats['files']} file / 読まなかった {stats['skipped']} 件 / "
        f"この repo の言語 {stats['langs']} 種"
    )
    print(f"  語彙 {stats['markers']} 件 (generated: {stats['generated']}) / 宣言された例外 {stats['allow']} 件")
    for n in notes:
        print(f"  {n}")

    if fails:
        print("")
        for f in fails:
            print(f"  {f}")
        print("")
        print(
            f"public surface guard: 公開してはならないものが {len(fails)} 件 "
            f"(R1 {stats['r1']} / R2 {stats['r2']} / R3 {stats['r3']})"
        )
        print("  **一致した中身はここには出さない** — 公開 CI の log は公開なので、")
        print("  出した時点で再公開になる。file と行を手元で開いて確かめること。")
        return 1

    print("public surface guard: R1/R2/R3/R4 をすべて満たす")
    return 0


if __name__ == "__main__":
    sys.exit(main())
