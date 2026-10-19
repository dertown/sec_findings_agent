"""Finding Evidence Advisor core library.

Pure Python used by Splunk custom commands, REST handlers, and unit tests.
Does not import Splunk modules so it can run outside the search head.
"""

from .findings import normalize_finding
from .recommendations import recommend_searches
from .scoring import analyze_finding
from .triage import normalize_triage

__all__ = [
    "analyze_finding",
    "normalize_finding",
    "normalize_triage",
    "recommend_searches",
]
