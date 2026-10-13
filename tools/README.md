# TokenGen — Founder's Tools

Three generated views over the repository, for the Founder. **No dependencies** beyond `python3` (already
present) and `git`. **No browser, no server, no cost** — plain terminal output, so they work over SSH and fit
a USB-resident project.

## The one rule that makes these trustworthy

**Every fact is derived from the repository. None is authored by hand.** A diagram or a status table that a
human maintains drifts from reality the moment reality changes — and a stale view is an artifact that *reads*
as authoritative but is not. That is the failure this project fights, so these tools cannot drift: if
something is in the code it appears; if it is removed it disappears.

If a tool ever shows something wrong, **the bug is in the tool, and it should be fixed — not worked around.**

## The tools

| Tool | Run | What it shows |
|---|---|---|
| **Component map** | `tools/map.sh` | Every crate, module, public API, `cfg` branch, test, and feature anchor — and how they connect. Includes the safety posture (`unsafe` confinement). |
| **Conversation log** | `tools/conversation.sh` | What the employees and Founder communicated, thread by thread, with `DEFECT` / `STOP-WORK` / `UNVERIFIED` markers highlighted for debugging. |
| **Claim audit** | `tools/audit.sh` | The traceability matrix: every claim, its recorded evidence, and whether that evidence is *measured* or *reasoned* — plus everything still open. |

### Examples

```bash
tools/map.sh                        # the whole component map
tools/conversation.sh T-0002        # one thread, or a search term
tools/conversation.sh --recent 5    # the last five threads
tools/audit.sh --open               # only what needs attention
tools/audit.sh F3.5                 # everything about F3.5
```

## What each is for

- **map.sh** — "what exists, and how does it fit together?" Use it after a change to see the shape of the
  system without reading every file.
- **conversation.sh** — "who said what, and where did this go wrong?" Trace a failure back to the message
  that raised it. The highlights jump you to the relevant lines.
- **audit.sh** — "what have we claimed, and can we prove it?" The `--open` view is the work queue: every
  unchecked criterion and every marker of something unfinished.

## Keeping them current

They read the repo live — there is nothing to refresh. Just re-run after a change. To always see the latest
shape:

```bash
tools/map.sh && tools/audit.sh --open
```

## Adding a tool

Put it in `tools/` as a small `python3` script with a `.sh` wrapper, and **derive everything from the repo**.
Do not add a curated data file that a human must update — that reintroduces the drift these tools exist to
eliminate. If a view needs interpretation, put the interpretation in the report or blueprint, and let the
tool show only what is verifiable.

## Honest limits

- The tools show **what the repository says**, not what is true about the world. A claim recorded as verified
  is displayed as *recorded*, not re-verified — only a real run does that.
- The conversation view reads `plan/mailroom/threads/` (current) and `plan/conversation/` (history). It does
  not include chat outside the repository.
- The audit view extracts claims from tables that follow the project's protocol; a claim written as loose
  prose may not be captured. Structured records are the point.
