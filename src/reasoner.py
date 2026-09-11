"""
Draws conclusions that are required to cite the specific events backing
them -- a Conclusion without evidence_ids pointing at real LogEvents in
the timeline isn't representable by this module's data model, which is
the whole point: "AI detected malware" isn't an acceptable output shape
here, "sensitive file access at t=12 by pid 4021, network connection at
t=14 by the same pid, spawned from AcroRead.exe at t=10" is.
"""

from dataclasses import dataclass
from typing import List

from events import LogEvent
from timeline import Timeline


@dataclass(frozen=True)
class Conclusion:
    text: str
    severity: str                  # high, medium, low
    evidence_ids: List[str]         # LogEvent.event_id values that support this conclusion
    process_lineage: List[int]       # root-first pid chain implicated


def _find_process_start(timeline: Timeline, pid: int) -> LogEvent:
    for e in timeline.events:
        if e.event_type == "process_start" and e.process_id == pid:
            return e
    return None


def analyze(timeline: Timeline, network_window_seconds: float = 5.0) -> List[Conclusion]:
    conclusions: List[Conclusion] = []

    sensitive_accesses = [e for e in timeline.events if e.touches_sensitive_file()]

    for access in sensitive_accesses:
        pid = access.process_id
        watched_pids = {pid} | set(timeline.descendants_of(pid))

        network_events = [
            e for e in timeline.events
            if e.event_type == "network_connection"
            and e.process_id in watched_pids
            and access.timestamp < e.timestamp <= access.timestamp + network_window_seconds
        ]
        if not network_events:
            continue

        network_event = min(network_events, key=lambda e: e.timestamp)
        lineage = timeline.process_lineage(pid)
        lineage_start_events = [_find_process_start(timeline, p) for p in lineage]
        lineage_start_events = [e for e in lineage_start_events if e is not None]

        evidence_ids = [e.event_id for e in lineage_start_events] + [access.event_id, network_event.event_id]

        conclusions.append(Conclusion(
            text="Suspicious credential access",
            severity="high",
            evidence_ids=evidence_ids,
            process_lineage=lineage,
        ))

    return conclusions


def explain(timeline: Timeline, conclusion: Conclusion) -> str:
    """Render a human-readable evidence trace for a conclusion -- every
    line traces to one of the event_ids the conclusion actually cites."""
    lines = [f"CONCLUSION: {conclusion.text} (severity={conclusion.severity})", "Evidence:"]
    by_id = {e.event_id: e for e in timeline.events}
    for eid in conclusion.evidence_ids:
        e = by_id.get(eid)
        if e:
            lines.append(f"  [{e.event_id}] t={e.timestamp} pid={e.process_id} {e.event_type}: {e.detail}")
    return "\n".join(lines)
