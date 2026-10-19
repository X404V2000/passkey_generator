#!/usr/bin/env python3
"""
Conversation viewer — the employees' communication, rendered from the repository.

WHAT IT SHOWS
-------------
Every message exchanged between employees and the Founder, drawn from:
  - plan/mailroom/threads/*.md      (current, org-era conversations)

WHY GENERATED
-------------
The messages already exist as files; this renders them in order and highlights the things that matter
for debugging — defects, stop-work notices, "not verified" markers, review verdicts — so a failure can be
traced back to the message that raised it. Read from the repo, never transcribed.

Run:  tools/conversation.sh                 (all)
      tools/conversation.sh <search-term>   (filter)
      tools/conversation.sh --recent 5      (last N messages)
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

# markers worth surfacing, with their colour and emoji-free label
MARKERS = [
    (re.compile(r"\bDEFECT\b|\bFINDING\b", re.I), "DEFECT", C.RED),
    (re.compile(r"\bSTOP-WORK\b", re.I), "STOP-WORK", C.RED),
    (re.compile(r"\bNOT ACCEPTED\b|\brefused\b|\bREJECTED\b|\bBLOCKED\b", re.I), "BLOCK", C.RED),
    (re.compile(r"not verified|never run|NOT RUN|unverified|unevidenced|not evidenced", re.I), "UNVERIFIED", C.Y),
    (re.compile(r"\bRETAIN|retracted\b|\bCORRECTION\b|\bWRONG\b", re.I), "CORRECTION", C.M),
    (re.compile(r"APPROVED WITH FIXES|AWAITING REVIEW|PENDING", re.I), "PENDING", C.Y),
    (re.compile(r"\bSTATED LIMITATION\b|\bW-item\b|\bdeferred\b", re.I), "LIMITATION", C.CY),
]


def md_paths():
    out = []
    for pat in ("plan/mailroom/threads/*.md",):
        out += sorted(glob.glob(os.path.join(ROOT, pat)))
    return out


def title_of(path):
    for line in open(path, encoding="utf-8"):
        if line.strip().startswith("# "):
            return line.strip("# ").strip()
    return os.path.basename(path)


def status_of(path):
    for line in open(path, encoding="utf-8"):
        m = re.match(r"\*\*Status:\*\*\s*(.+)", line.strip())
        if m:
            return m.group(1).strip()
    return ""


def messages_in(path):
    """Split a file into messages on '## Message N' headers."""
    text = open(path, encoding="utf-8").read()
    parts = re.split(r"(?m)^##\s+(Message\s+\d+.*)$", text)
    msgs = []
    if len(parts) == 1:
        msgs.append(("(whole file)", text))
    else:
        # parts[0] is preamble; then alternating header, body
        for i in range(1, len(parts), 2):
            header = parts[i].strip()
            body = parts[i + 1] if i + 1 < len(parts) else ""
            msgs.append((header, body))
    return msgs


def scan(body):
    """Return the distinct markers present in a message body."""
    found = []
    for rx, label, _ in MARKERS:
        if rx.search(body):
            found.append(label)
    return found


def main():
    args = sys.argv[1:]
    recent = None
    term = None
    if args and args[0] == "--recent":
        recent = int(args[1]) if len(args) > 1 else 5
    elif args:
        term = " ".join(args)

    print(f"\n{C.B}{C.CY}{'=' * 78}{C.R}\n{C.B}{C.CY}  TOKENGEN — EMPLOYEE CONVERSATION LOG{C.R}\n{C.B}{C.CY}{'=' * 78}{C.R}")
    print(f"  {C.D}mailroom threads + historical exchange. Generated from the repo; never transcribed.{C.R}")
    if term:
        print(f"  {C.D}filter: {C.R}{C.B}{term}{C.R}")

    files = md_paths()
    # gather (path, threadtitle, status, [msgs])
    threads = []
    for p in files:
        rel = os.path.relpath(p, ROOT)
        threads.append((rel, title_of(p), status_of(p), messages_in(p)))

    # apply filters
    if term:
        t = term.lower()
        kept = []
        for rel, title, status, msgs in threads:
            if t in rel.lower() or t in title.lower() or any(t in b.lower() for _, b in msgs):
                kept.append((rel, title, status, msgs))
        threads = kept
    if recent:
        threads = threads[-recent:]

    # summary table
    print(f"\n{C.B}  THREADS ({len(threads)}){C.R}")
    for rel, title, status, msgs in threads:
        sc = C.G if "CLOSED" in status.upper() else (C.Y if "AWAITING" in status.upper() or "OPEN" in status.upper() else C.D)
        marks = []
        for _, body in msgs:
            for m in scan(body):
                if m not in marks:
                    marks.append(m)
        mstr = ("  " + " ".join(f"{C.RED if m in ('DEFECT', 'STOP-WORK', 'BLOCK') else C.Y}[{m}]{C.R}" for m in marks)) if marks else ""
        print(f"\n  {C.B}{rel}{C.R}")
        print(f"    {title}")
        if status:
            print(f"    {sc}status: {status}{C.R}{mstr}")

    # full render
    print(f"\n{C.B}{C.CY}{'─' * 78}{C.R}")
    for rel, title, status, msgs in threads:
        print(f"\n{C.B}[{rel}]{C.R}  {C.B}{title}{C.R}")
        if status:
            print(f"  {C.D}status: {status}{C.R}")
        for header, body in msgs:
            marks = scan(body)
            mstr = ("  " + " ".join(f"{C.RED if m in ('DEFECT','STOP-WORK','BLOCK') else C.Y}◆{m}{C.R}" for m in marks)) if marks else ""
            print(f"\n  {C.B}{C.CY}▸ {header}{C.R}{mstr}")
            # render body, highlighting marker lines
            for line in body.splitlines():
                hit = None
                for rx, label, col in MARKERS:
                    if rx.search(line):
                        hit = col
                        break
                if hit:
                    print(f"    {hit}{line}{C.R}")
                else:
                    print(f"    {line}")
        print(f"\n  {C.D}{'·' * 74}{C.R}")

    print(f"\n{C.D}  Trace a failure: find the DEFECT/BLOCK line above, then read the message it appears in.\n"
          f"  For claims and their evidence, run tools/audit.sh instead.\n{C.R}")


if __name__ == "__main__":
    main()
