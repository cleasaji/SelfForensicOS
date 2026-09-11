import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from events import LogEvent
from timeline import build_timeline
from reasoner import analyze, explain


def build_incident_events():
    # User opened a PDF (pid 1000), which spawned pid 1001, which
    # accessed a credential file, then made a network connection.
    return [
        LogEvent("e1", 10.0, "process_start", 1000, None, "AcroRead.exe"),
        LogEvent("e2", 10.5, "process_start", 1001, 1000, "unknown_helper.exe"),
        LogEvent("e3", 11.0, "file_access", 1001, 1000, "C:/Users/creds/credential_store.db"),
        LogEvent("e4", 12.5, "network_connection", 1001, 1000, "203.0.113.44:443"),
        LogEvent("e5", 20.0, "process_exit", 1001, 1000, "exit_code=0"),
    ]


def build_benign_events():
    return [
        LogEvent("e1", 10.0, "process_start", 2000, None, "notepad.exe"),
        LogEvent("e2", 11.0, "file_access", 2000, None, "C:/Users/docs/notes.txt"),
    ]


def test_timeline_sorts_events_by_timestamp():
    events = list(reversed(build_incident_events()))
    timeline = build_timeline(events)
    timestamps = [e.timestamp for e in timeline.events]
    assert timestamps == sorted(timestamps)


def test_timeline_builds_parent_child_relationships():
    timeline = build_timeline(build_incident_events())
    assert timeline.children_of[1000] == [1001]
    assert timeline.parent_of[1001] == 1000


def test_descendants_of_finds_transitive_children():
    events = build_incident_events() + [
        LogEvent("e6", 13.0, "process_start", 1002, 1001, "grandchild.exe"),
    ]
    timeline = build_timeline(events)
    assert set(timeline.descendants_of(1000)) == {1001, 1002}


def test_process_lineage_is_root_first():
    events = build_incident_events() + [
        LogEvent("e6", 13.0, "process_start", 1002, 1001, "grandchild.exe"),
    ]
    timeline = build_timeline(events)
    assert timeline.process_lineage(1002) == [1000, 1001, 1002]


def test_sensitive_file_access_followed_by_network_flags_conclusion():
    timeline = build_timeline(build_incident_events())
    conclusions = analyze(timeline)
    assert len(conclusions) == 1
    assert conclusions[0].text == "Suspicious credential access"


def test_conclusion_evidence_ids_all_resolve_to_real_events():
    timeline = build_timeline(build_incident_events())
    conclusions = analyze(timeline)
    by_id = {e.event_id for e in timeline.events}
    for c in conclusions:
        assert all(eid in by_id for eid in c.evidence_ids)
        assert len(c.evidence_ids) >= 2  # at minimum: the file access + the network event


def test_benign_session_produces_no_conclusions():
    timeline = build_timeline(build_benign_events())
    conclusions = analyze(timeline)
    assert conclusions == []


def test_network_outside_window_does_not_trigger_conclusion():
    events = [
        LogEvent("e1", 10.0, "process_start", 1000, None, "AcroRead.exe"),
        LogEvent("e2", 11.0, "file_access", 1000, None, "credential_store.db"),
        LogEvent("e3", 200.0, "network_connection", 1000, None, "203.0.113.44:443"),  # far too late
    ]
    timeline = build_timeline(events)
    conclusions = analyze(timeline, network_window_seconds=5.0)
    assert conclusions == []


def test_explain_produces_trace_referencing_only_cited_evidence():
    timeline = build_timeline(build_incident_events())
    conclusions = analyze(timeline)
    text = explain(timeline, conclusions[0])
    assert "Suspicious credential access" in text
    for eid in conclusions[0].evidence_ids:
        assert eid in text
