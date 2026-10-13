#!/usr/bin/env python3
"""
Component map — generated from the repository, never authored by hand.

WHY GENERATED
-------------
A hand-drawn architecture diagram drifts from the code the moment the code changes, and a stale diagram
is an artifact that reads as authoritative but is not. This tool derives every fact from the repo:
  - the module tree            (files on disk)
  - the dependency graph       (cargo metadata, the authoritative source)
  - the public API             (parsed `pub` items)
  - platform/cfg branches      (parsed `#[cfg(...)]` gates)
  - frozen-feature anchors     (plan/ROADMAP.md, cross-checked against git)
If something is in the code it appears; if it is removed it disappears. It cannot drift.

Run:  tools/map.sh            (wrapper)  or  python3 tools/map.py
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(*args):
    """Run a command, return stdout. Never raises on non-zero — callers handle emptiness."""
    try:
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return ""


# ---------------------------------------------------------------- colours (terminal, degrade gracefully)
class C:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    B = "\033[1m" if on else ""
    D = "\033[2m" if on else ""
    R = "\033[0m" if on else ""
    G = "\033[32m" if on else ""
    Y = "\033[33m" if on else ""
    RED = "\033[31m" if on else ""
    CY = "\033[36m" if on else ""
    M = "\033[35m" if on else ""


def head(t):
    print(f"\n{C.B}{C.CY}{'=' * 78}{C.R}\n{C.B}{C.CY}  {t}{C.R}\n{C.B}{C.CY}{'=' * 78}{C.R}")


def sub(t):
    print(f"\n{C.B}{t}{C.R}")


def kv(k, v, colour=""):
    print(f"  {k:<34} {colour}{v}{C.R}")


# ---------------------------------------------------------------- 1. cargo metadata (authoritative deps)
def cargo_metadata():
    raw = sh("cargo", "metadata", "--format-version", "1", "--no-deps")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


# ---------------------------------------------------------------- 2. source files
def rust_files():
    out = []
    for base in ("src", "tokengen-sys/src"):
        d = os.path.join(ROOT, base)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".rs"):
                out.append(os.path.join(base, f))
    return out


def read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as fh:
        return fh.read()


ITEM_RE = re.compile(r"^\s*pub\s+(fn|struct|enum|trait|mod|const)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
CFG_RE = re.compile(r"#\[cfg\(([^)]*)\)\]")
SAFETY_RE = re.compile(r"//\s*SAFETY:")
UNSAFE_RE = re.compile(r"\bunsafe\s*\{")


def strip_comments(src):
    """Remove line comments so a mention of a construct in prose is not mistaken for the construct.

    This matters: tokengen-sys/src/lib.rs *documents* that the main crate has `forbid(unsafe_code)`,
    and a naive substring check reports that the sys crate has it too — a false fact, which is the
    very defect class this tool exists to avoid.
    """
    out = []
    for line in src.splitlines():
        s = line.lstrip()
        if s.startswith("//"):
            out.append("")  # full-line comment (incl. /// and //!)
            continue
        # strip trailing `//` comments, but not inside a string (good enough for this codebase)
        idx = line.find("//")
        if idx != -1 and line[:idx].count('"') % 2 == 0:
            line = line[:idx]
        out.append(line)
    return "\n".join(out)


def has_attr(src, attr):
    """True only if `attr` appears as a real attribute, not inside a comment."""
    return attr in strip_comments(src)


def analyse(path):
    src = read(path)
    items = [(k, n) for k, n in ITEM_RE.findall(src)]
    # drop `pub mod` duplicates of file names when the module is the file itself
    cfgs = sorted(set(CFG_RE.findall(src)))
    return {
        "path": path,
        "lines": src.count("\n") + 1,
        "items": items,
        "cfgs": cfgs,
        "unsafe_blocks": len(UNSAFE_RE.findall(strip_comments(src))),
        "safety_comments": len(SAFETY_RE.findall(src)),
        "has_forbid": has_attr(src, "#![forbid(unsafe_code)]"),
        "has_deny": has_attr(src, "#![deny(unsafe_code)]"),
        "has_allow": has_attr(src, "#[allow(unsafe_code)]"),
        "has_tests": has_attr(src, "#[cfg(test)]"),
    }


# ---------------------------------------------------------------- 3. ROADMAP anchors
def roadmap():
    """Return {feature: (scope, status, anchor)} from plan/ROADMAP.md."""
    p = os.path.join(ROOT, "plan", "ROADMAP.md")
    if not os.path.exists(p):
        return {}
    rows = {}
    for line in open(p, encoding="utf-8"):
        m = re.match(r"^\|\s*\*\*([^*]+)\*\*\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|", line)
        if m:
            feat = m.group(1).strip()
            rows[feat] = (m.group(2).strip(), m.group(3).strip(), m.group(4).strip())
    return rows


def sha_exists(sha):
    if not sha:
        return False
    return bool(sh("git", "cat-file", "-e", f"{sha}^{{commit}}").strip() or
                sh("git", "rev-parse", "--verify", f"{sha}^{{commit}}").strip())


# ---------------------------------------------------------------- 4. tests
def tests():
    out = []
    d = os.path.join(ROOT, "tests")
    if not os.path.isdir(d):
        return out
    for f in sorted(os.listdir(d)):
        if f.endswith(".rs"):
            out.append(f"tests/{f}")
    cf = os.path.join(d, "compile-fail")
    if os.path.isdir(cf):
        cases = [x for x in sorted(os.listdir(cf)) if x.endswith(".rs")]
        # a case is "passes" (inverse) or "fails" (compile-fail) by whether a .stderr exists
        for c in cases:
            has_stderr = os.path.exists(os.path.join(cf, c.replace(".rs", ".stderr")))
            out.append((f"tests/compile-fail/{c}", "compile-fail" if has_stderr else "compiles (inverse)"))
    return out


# ---------------------------------------------------------------- render the map
def main():
    head("TOKENGEN — COMPONENT MAP")
    sha = sh("git", "rev-parse", "--short", "HEAD").strip()
    branch = sh("git", "rev-parse", "--abbrev-ref", "HEAD").strip()
    dirty = sh("git", "status", "--porcelain").strip()
    ahead = sh("git", "rev-list", "--count", "origin/main..HEAD").strip()
    print(f"  {C.D}generated from the repository at {C.R}{C.B}{sha}{C.R}{C.D} on {branch}"
          f"{C.R}   {C.D}(working tree {'dirty' if dirty else 'clean'}){C.R}")
    print(f"  {C.D}not pushed: {ahead} commit(s) ahead of origin/main{C.R}")

    # --- crates and dependencies
    meta = cargo_metadata()
    head("1. CRATES AND DEPENDENCIES")
    if meta:
        for pkg in meta.get("packages", []):
            name = pkg["name"]
            is_main = name == "tokengen"
            role = "main crate (#![forbid(unsafe_code)])" if is_main else "FFI sub-crate (only crate with unsafe)"
            print(f"\n  {C.B}{name}{C.R} {C.D}v{pkg.get('version','?')} — {role}{C.R}")
            deps = pkg.get("dependencies", [])
            normal = [d for d in deps if d.get("kind") is None]
            dev = [d for d in deps if d.get("kind") == "dev"]
            if normal:
                print(f"    {C.D}deps:{C.R} " + ", ".join(d["name"] for d in normal))
            if dev:
                print(f"    {C.D}dev :{C.R} " + ", ".join(d["name"] for d in dev))
            feats = pkg.get("features", {})
            if feats:
                print(f"    {C.D}feats:{C.R} " + ", ".join(feats.keys()))
    else:
        print(f"  {C.Y}cargo metadata unavailable{C.R}")

    # --- module tree with API surface and safety properties
    head("2. MODULES, PUBLIC API, AND SAFETY PROPERTIES")
    files = rust_files()
    infos = [analyse(p) for p in files]
    for info in infos:
        flag = ""
        if info["has_forbid"]:
            flag = f" {C.G}[forbid(unsafe_code)]{C.R}"
        elif info["has_deny"]:
            flag = f" {C.Y}[deny(unsafe_code)]{C.R}"
        mark = f" {C.RED}[contains unsafe]{C.R}" if info["unsafe_blocks"] else ""
        print(f"\n  {C.B}{info['path']}{C.R}{flag}{mark}  {C.D}({info['lines']} lines){C.R}")
        if info["items"]:
            grouped = {}
            for kind, nm in info["items"]:
                grouped.setdefault(kind, []).append(nm)
            for kind in ("struct", "enum", "trait", "mod", "const", "fn"):
                if kind in grouped:
                    print(f"    {C.CY}{kind:<7}{C.R} " + ", ".join(sorted(set(grouped[kind]))))
        if info["cfgs"]:
            print(f"    {C.M}cfg    {C.R} " + ", ".join(info["cfgs"]))
        if info["unsafe_blocks"]:
            ok = info["safety_comments"] >= info["unsafe_blocks"]
            col = C.G if ok else C.RED
            print(f"    {col}unsafe {C.R} {info['unsafe_blocks']} block(s), "
                  f"{info['safety_comments']} SAFETY comment(s) "
                  f"{'✓' if ok else '✗ EVERY BLOCK NEEDS A SAFETY COMMENT'}")

    # --- safety summary (the load-bearing invariant)
    head("3. SAFETY POSTURE (invariant: unsafe confined to tokengen-sys)")
    main_crate = [i for i in infos if i["path"].startswith("src/")]
    sys_crate = [i for i in infos if i["path"].startswith("tokengen-sys/")]
    main_unsafe = sum(i["unsafe_blocks"] for i in main_crate)
    sys_unsafe = sum(i["unsafe_blocks"] for i in sys_crate)
    main_allow = [i["path"] for i in main_crate if i["has_allow"]]
    forbid_ok = any(i["has_forbid"] for i in main_crate)
    kv("main crate has #![forbid(unsafe_code)]", "YES" if forbid_ok else "NO", C.G if forbid_ok else C.RED)
    kv("unsafe blocks in main crate (src/)", str(main_unsafe), C.G if main_unsafe == 0 else C.RED)
    kv("#[allow(unsafe_code)] in src/ (must be none)", ", ".join(main_allow) if main_allow else "none",
       C.RED if main_allow else C.G)
    kv("unsafe blocks in tokengen-sys/", str(sys_unsafe), C.CY)
    ambiguous = [i["path"] for i in sys_crate if i["unsafe_blocks"] and not i["has_allow"]]
    if ambiguous:
        kv("sys files with unsafe but no module #[allow]", ", ".join(ambiguous), C.Y)

    # --- tests
    head("4. TESTS")
    for t in tests():
        if isinstance(t, tuple):
            print(f"  {C.D}{t[0]}{C.R}  {C.D}({t[1]}){C.R}")
        else:
            print(f"  {t}")

    # --- frozen features and anchors
    head("5. FEATURES AND FREEZE ANCHORS  (from plan/ROADMAP.md, cross-checked against git)")
    rm = roadmap()
    if not rm:
        print(f"  {C.Y}plan/ROADMAP.md not found{C.R}")
    for feat, (scope, status, anchor) in rm.items():
        anchor = anchor.strip().replace("`", "").split("+")[0].strip()
        exists = sha_exists(anchor) if re.match(r"^[0-9a-f]{7,40}$", anchor) else None
        if exists is True:
            chk = f"{C.G}✓ in git{C.R}"
        elif exists is False:
            chk = f"{C.RED}✗ NOT IN GIT{C.R}"
        else:
            chk = f"{C.D}—{C.R}"
        stat_col = C.G if "FROZEN" in status.upper() else (C.Y if "BLUEPRINT" in status.upper() or "REVIEW" in status.upper() else C.D)
        print(f"\n  {C.B}{feat}{C.R}  {stat_col}{status}{C.R}  {chk}")
        if scope:
            print(f"    {C.D}{scope}{C.R}")

    # --- file-level dependency edges (module -> external crate)
    head("6. HOW IT CONNECTS  (module → crate/OS)")
    edges = []
    for i in infos:
        src = read(i["path"])
        ext = []
        for lib in ("getrandom", "zeroize", "libc", "windows_sys", "tokengen_sys"):
            if re.search(rf"\b{lib}\b", src):
                ext.append(lib)
        if i["unsafe_blocks"]:
            ext.append("OS syscalls (unsafe)")
        if ext:
            edges.append((i["path"], sorted(set(ext))))
    for path, ext in edges:
        print(f"  {path:<28} {C.D}→{C.R} {', '.join(ext)}")
    if not edges:
        print(f"  {C.D}(no cross-module edges detected){C.R}")

    print(f"\n{C.D}{'—' * 78}\n  Every fact above is derived from the repository. Re-run tools/map.sh after any change.\n{C.R}")


if __name__ == "__main__":
    main()
