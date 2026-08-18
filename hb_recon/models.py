from dataclasses import dataclass, field
from typing import List, Dict, Set

@dataclass
class EndpointInfo:
    endpoints: List[str] = field(default_factory=list)
    params: Dict[str, List[str]] = field(default_factory=dict)
    file_types: List[str] = field(default_factory=list)
    suspected_post_forms: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)

@dataclass
class RiskEndpoint:
    url: str
    score: int

@dataclass
class ReportSummary:
    subdomains: int = 0
    alive_hosts: int = 0
    endpoints: int = 0
    params_with_input: List[str] = field(default_factory=list)
    file_types: List[str] = field(default_factory=list)
    tech_detected: Dict[str, str] = field(default_factory=dict)
    gf_matches: Dict[str, int] = field(default_factory=dict)
