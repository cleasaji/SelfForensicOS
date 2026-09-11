"""
The raw signal a self-forensic OS reconstructs a story from: individual
log events, each carrying enough identity (event_id, process/parent
process ids) that later conclusions can point back to the *exact* events
that support them, rather than a vague "the logs showed something bad."
"""

from dataclasses import dataclass
from typing import Optional


SENSITIVE_FILE_KEYWORDS = ("credential", "password", "wallet", "keychain", "private_key", ".pem")


@dataclass(frozen=True)
class LogEvent:
    event_id: str
    timestamp: float           # seconds, monotonic within a session
    event_type: str             # process_start, process_exit, file_access, network_connection
    process_id: int
    parent_process_id: Optional[int] = None
    detail: str = ""             # e.g. filename, destination host, exit code

    def touches_sensitive_file(self) -> bool:
        if self.event_type != "file_access":
            return False
        detail_lower = self.detail.lower()
        return any(kw in detail_lower for kw in SENSITIVE_FILE_KEYWORDS)
