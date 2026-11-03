"""Evidence container retained by the scorer. This app makes no live lookups."""
from dataclasses import dataclass, field


@dataclass
class Enrichment:
    urls: dict[str, dict] = field(default_factory=dict)
    domains: dict[str, dict] = field(default_factory=dict)
    hashes: dict[str, dict] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
