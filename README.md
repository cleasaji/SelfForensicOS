# 🕵️ SelfForensicOS

An OS-level event model that **automatically reconstructs an incident
timeline** and produces conclusions where every claim traces back to the
specific events that support it — not "AI detected malware," but a
process ancestry chain and event IDs you can go read yourself.

> Cybersecurity portfolio project focused on **evidence-linked
> reasoning**: the requirement that a conclusion always carries a
> pointer back to the raw evidence, not just a verdict.

---

## The example this reconstructs

```
10:31:02  User opened PDF
10:31:04  PDF spawned a process
10:31:05  Process accessed a credential file
10:31:07  Process opened a network connection
```

→ Conclusion: **"Suspicious credential access"**, with evidence
pointing to the exact `process_start`, `file_access`, and
`network_connection` events (and their process lineage) that produced it.

## Causation by process lineage, not just timing

`timeline.py` builds a real process ancestry tree from `parent_process_id`
links — `descendants_of()` and `process_lineage()` — so the reasoner in
`reasoner.py` can ask "did a network connection happen from *this
process or something it spawned*," which is a materially stronger claim
than "did a network connection happen around the same time as a file
access." Two unrelated events close in time would not connect; a child
process making the connection, correctly does.

## Every conclusion is forced to cite its evidence

```python
@dataclass(frozen=True)
class Conclusion:
    text: str
    severity: str
    evidence_ids: List[str]      # must resolve to real events in the timeline
    process_lineage: List[int]
```

There's no code path that produces a `Conclusion` without populating
`evidence_ids` from actual `LogEvent.event_id`s in the timeline — the
data model itself enforces the "point back to evidence" requirement, and
the test suite checks every cited ID resolves to a real event.

## Example

```python
from events import LogEvent
from timeline import build_timeline
from reasoner import analyze, explain

events = [
    LogEvent("e1", 10.0, "process_start", 1000, None, "AcroRead.exe"),
    LogEvent("e2", 10.5, "process_start", 1001, 1000, "unknown_helper.exe"),
    LogEvent("e3", 11.0, "file_access", 1001, 1000, "credential_store.db"),
    LogEvent("e4", 12.5, "network_connection", 1001, 1000, "203.0.113.44:443"),
]
timeline = build_timeline(events)
for c in analyze(timeline):
    print(explain(timeline, c))
```

```
CONCLUSION: Suspicious credential access (severity=high)
Evidence:
  [e1] t=10.0 pid=1000 process_start: AcroRead.exe
  [e2] t=10.5 pid=1001 process_start: unknown_helper.exe
  [e3] t=11.0 pid=1001 file_access: credential_store.db
  [e4] t=12.5 pid=1001 network_connection: 203.0.113.44:443
```

## Why this over "AI detected malware"

A verdict with no evidence trail can't be checked, appealed, or used to
improve detection rules. Forcing every conclusion to carry the specific
events it rests on means an analyst (or an automated review) can verify
the reasoning independently — and a conclusion the reasoner can't back
with real evidence_ids simply doesn't get produced.

## Tests

```bash
pip install -r requirements.txt
cd tests && python -m pytest -v
```

9 tests: timeline sorting, parent-child relationship construction,
transitive descendant lookup, root-first lineage ordering, the incident
scenario correctly producing a flagged conclusion, every cited evidence
ID resolving to a real event, a benign session producing zero
conclusions, a network connection outside the correlation window *not*
triggering a false conclusion, and the human-readable trace only
referencing evidence the conclusion actually cites.

## Project layout

```
src/
  events.py       # LogEvent model + sensitive-file detection
  timeline.py       # sorted timeline + process ancestry tree
  reasoner.py         # evidence-linked conclusion generation + explain()
tests/
  test_selfforensicos.py
```

## Honest scope

Rule-based correlation over a single scenario type (sensitive file
access followed by network activity within a time window, traced through
process lineage) — not a general-purpose forensic engine covering every
attack pattern. The architectural contribution is the evidence-linking
discipline itself (conclusions that can't exist without citable event
IDs), which generalizes to more rules the same data model already
supports.
