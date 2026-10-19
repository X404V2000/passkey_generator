#!/usr/bin/env python3
"""
Claim audit — every claim traced to its evidence and status.

WHAT IT IS
----------
The Founder asked for "the full audit: every claim with its evidence and status". This extracts, from the
repository, each factual claim made in a report or message (its verification-log rows), the evidence
recorded for it, and whether that evidence is *measured* or *reasoned* — plus the open items and defects.

WHY GENERATED
-------------
A traceability matrix kept by hand is stale the moment a claim is added. Every row here comes from a file
in the repo: the verification-log tables that the project's own protocol requires. If a claim is recorded
without evidence, this tool shows it as lacking — which is the point.

Run:  tools/audit.sh                 (summary + all claims)
      tools/audit.sh <feature>       (filter, e.g. F3, F3.5, CI)
      tools/audit.sh --open          (only open items / unverified / defects)
"""

import os
import re
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


# a table row with >=3 cells: | claim | method | result |
ROW_RE = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$")
SEP_RE = re.compile(r"^\|[\s:|-]+\|$")

VERIFICATION_HEAD = re.compile(r"verification log|evidence|gate result", re.I)
OPEN_RE = re.compile(r"\bOPEN\b|\bNOT DONE\b|\bPENDING\b|\bAWAITING\b|\bBLOCKED\b|\bnot yet\b|\bNOT RUN\b|\bnot implemented\b", re.I)
DEFECT_RE = re.compile(r"\bDEFECT\b|\bFAIL\b|\bWRONG\b|\bE0797|E0[0-9]{3}\b|\bnot discriminating\b|\bpassed against\b", re.I)
MEASURED_RE = re.compile(r"measured|ran |reproduced|exit [01]|PASS|FAIL|verified by", re.I)
REASONED_RE = re.compile(r"reasoned|reasoning|believed|estimated|assumed|expected", re.I)

# Requires the marker to be a bold token (**X**), a checkbox state, or a table cell containing it —
# so prose like "open-source" is not mistaken for an open item.
ATTENTION_RE = re.compile(
    r"\*\*\s*(DEFECT|STOP-WORK|BLOCKED|NOT DONE|NOT RUN|NOT WRITTEN|OPEN|AWAITING[^*]*|PENDING|UNVERIFIED|REJECTED)\s*\*\*"
    r"|- \[ \]"                      # an unchecked acceptance criterion
    r"|\|\s*(NOT DONE|NOT RUN|NOT WRITTEN|BLOCKED|OPEN|DEFECT)\s*\|"
    r"|\bE0[0-9]{3}\b",              # a compiler error code
    re.I,
)


def doc_paths():
    pats = [
        "plan/reports/**/*.md",
        "plan/mailroom/threads/*.md",
        "plan/PROJECT_PLAN.md",
    ]
    out = []
    for p in pats:
        out += glob.glob(os.path.join(ROOT, p), recursive=True)
    return sorted(set(out))


def extract_claims(path):
    """Pull (section, claim, evidence, result) rows that live under a verification/evidence heading,
    plus every table row that carries a Measured/Reasoned label anywhere."""
    text = open(path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()
    claims = []
    section = ""
    in_verif = False
    for ln in lines:
        if ln.startswith("#"):
            section = ln.strip("# ").strip()
            in_verif = bool(VERIFICATION_HEAD.search(section))
            continue
        m = ROW_RE.match(ln)
        if not m or SEP_RE.match(ln):
            continue
        a, b, c = (x.strip() for x in m.groups())
        low = (a + " " + b + " " + c)
        # skip header rows
        if a.lower() in ("claim", "#", "item", "step", "failure", "risk", "property", "status", "feature", "decision", "statement"):
            continue
        labelled = ("measured" in low.lower()) or ("reasoned" in low.lower())
        if in_verif or labelled:
            kind = "measured" if MEASURED_RE.search(c) and not REASONED_RE.search(c) else \
                   ("reasoned" if REASONED_RE.search(c) and not MEASURED_RE.search(c) else "")
            claims.append((section, a, b, c, kind, path))
    return claims


def main():
    args = sys.argv[1:]
    only_open = "--open" in args
    term = None
    rest = [a for a in args if a != "--open"]
    if rest:
        term = rest[0].lower()

    print(f"\n{C.B}{C.CY}{'=' * 78}{C.R}\n{C.B}{C.CY}  TOKENGEN — CLAIM AUDIT (evidence traceability){C.R}\n{C.B}{C.CY}{'=' * 78}{C.R}")
    print(f"  {C.D}every claim, its evidence, and its status — extracted from the reports and threads.{C.R}")
    if term:
        print(f"  {C.D}filter: {C.R}{C.B}{term}{C.R}")

    docs = doc_paths()
    all_claims = []
    for p in docs:
        rel = os.path.relpath(p, ROOT)
        if term and term not in rel.lower():
            # also allow filtering by content
            body = open(p, encoding="utf-8", errors="replace").read().lower()
            if term not in body:
                continue
        for cl in extract_claims(p):
            all_claims.append(cl)

    # ---- section 1: open items and defects across the record
    print(f"\n{C.B}1. OPEN ITEMS, DEFECTS AND UNVERIFIED CLAIMS  (what needs attention){C.R}")
    print(f"  {C.D}Scanning reports, threads and the plan for OPEN / NOT DONE / DEFECT / NOT RUN markers.{C.R}\n")
    hits = 0
    # Only *live* documents: settled history is not "needs attention". A debugging view that flags the
    # entire history is noise, and a noisy check is one people learn to ignore.
    for p in docs:
        rel = os.path.relpath(p, ROOT)
        if term and term not in rel.lower() and term not in open(p, encoding="utf-8", errors="replace").read().lower():
            continue
        for ln in open(p, encoding="utf-8", errors="replace"):
            s = ln.strip()
            if not s.startswith(("-", "|", "*", ">")) or len(s) < 8:
                continue
            if ATTENTION_RE.search(s):
                col = C.RED if DEFECT_RE.search(s) else C.Y
                hits += 1
                line = s if len(s) < 150 else s[:147] + "..."
                print(f"  {col}•{C.R} {C.D}{rel}{C.R}\n      {line}")
    if hits == 0:
        print(f"  {C.G}(nothing open found){C.R}")

    # ---- section 2: extracted verification-log claims
    print(f"\n{C.B}2. CLAIMS WITH RECORDED EVIDENCE  ({len(all_claims)} rows){C.R}")
    print(f"  {C.D}Each row: the claim, the method/evidence, and whether it is measured or reasoned.{C.R}\n")
    by_doc = {}
    for cl in all_claims:
        by_doc.setdefault(os.path.relpath(cl[5], ROOT), []).append(cl)
    for rel, rows in by_doc.items():
        print(f"  {C.B}{rel}{C.R}")
        for section, claim, method, result, kind, _ in rows:
            if only_open and kind:
                continue
            kcol = C.G if kind == "measured" else (C.Y if kind == "reasoned" else C.D)
            kstr = f" {kcol}[{kind}]{C.R}" if kind else ""
            claim_s = claim if len(claim) < 70 else claim[:67] + "..."
            result_s = result if len(result) < 60 else result[:57] + "..."
            print(f"      {claim_s:<70} {C.D}{result_s}{C.R}{kstr}")
        print()

    # ---- section 3: coverage summary
    print(f"{C.B}3. SUMMARY{C.R}")
    measured = sum(1 for c in all_claims if c[4] == "measured")
    reasoned = sum(1 for c in all_claims if c[4] == "reasoned")
    unlabelled = sum(1 for c in all_claims if not c[4])
    print(f"  claims with evidence recorded   {C.B}{len(all_claims)}{C.R}")
    print(f"    labelled measured             {C.G}{measured}{C.R}")
    print(f"    labelled reasoned             {C.Y}{reasoned}{C.R}")
    print(f"    no explicit label             {unlabelled}")
    print(f"  attention markers above         {C.RED if hits else C.G}{hits}{C.R}")
    print(f"\n{C.D}  A claim with no label is not necessarily wrong — but per the anchor rule it should name\n"
          f"  how it was checked. Run tools/audit.sh --open to see only the items needing attention.\n{C.R}")


if __name__ == "__main__":
    main()
