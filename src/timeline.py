"""
Reconstructs an ordered timeline and a process ancestry tree from
unordered raw events. The ancestry tree is what lets later reasoning
answer "was this network connection made by something that traces back
to the PDF the user opened," not just "did a network connection happen
around the same time" -- causation-by-process-lineage, not just
temporal proximity.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from events import LogEvent


@dataclass
class Timeline:
    events: List[LogEvent] = field(default_factory=list)
    children_of: Dict[int, List[int]] = field(default_factory=dict)
    parent_of: Dict[int, Optional[int]] = field(default_factory=dict)

    def events_for_process(self, pid: int) -> List[LogEvent]:
        return [e for e in self.events if e.process_id == pid]

    def descendants_of(self, pid: int) -> List[int]:
        """All process ids spawned (directly or transitively) by pid."""
        result = []
        frontier = list(self.children_of.get(pid, []))
        while frontier:
            child = frontier.pop()
            result.append(child)
            frontier.extend(self.children_of.get(child, []))
        return result

    def process_lineage(self, pid: int) -> List[int]:
        """pid and all its ancestors, root-first -- e.g. [1000, 1042, 1099]
        for a process 1099 spawned by 1042 spawned by 1000."""
        chain = [pid]
        current = self.parent_of.get(pid)
        while current is not None:
            chain.append(current)
            current = self.parent_of.get(current)
        return list(reversed(chain))


def build_timeline(events: List[LogEvent]) -> Timeline:
    ordered = sorted(events, key=lambda e: e.timestamp)
    timeline = Timeline(events=ordered)

    for e in ordered:
        if e.event_type == "process_start" and e.parent_process_id is not None:
            timeline.children_of.setdefault(e.parent_process_id, []).append(e.process_id)
            timeline.parent_of[e.process_id] = e.parent_process_id
        elif e.process_id not in timeline.parent_of:
            timeline.parent_of.setdefault(e.process_id, e.parent_process_id)

    return timeline
