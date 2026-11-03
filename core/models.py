"""Data models shared by every module."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    extension: str


@dataclass
class AuthResults:
    spf: Optional[str] = None      # pass / fail / softfail / neutral / none
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    available: bool = False        # Header present; does NOT establish trust.
    trusted: bool = False          # Set only for explicitly trusted ingestion.
    authserv_id: Optional[str] = None


@dataclass
class Link:
    url: str                       # real href target
    text: str = ""                 # visible anchor text ("" for bare URLs)


@dataclass
class ParsedEmail:
    message_id: str
    subject: str
    from_display: str
    from_address: str
    from_domain: str
    reply_to: Optional[str]
    return_path: Optional[str]
    to: list[str]
    date: Optional[str]
    body_text: str
    body_html: str
    links: list[Link]
    attachments: list[Attachment]
    phone_numbers: list[str]
    auth: AuthResults
    headers: dict[str, str]
    reporter: Optional[str] = None       # who reported it (wrapper From)
    unwrapped: bool = False              # True if original came from an attached .eml
    source_file: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    has_form: bool = False
    has_password_input: bool = False

    @property
    def domains(self) -> list[str]:
        from core.normalize import registered_domain, host_of
        out = []
        for l in self.links:
            d = registered_domain(host_of(l.url))
            if d and d not in out:
                out.append(d)
        return out

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Signal:
    name: str
    points: int
    evidence: str


@dataclass
class Verdict:
    verdict: str                 # malicious / uncertain / benign / simulation
    score: int
    signals: list[Signal] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)

    @property
    def evidence(self) -> list[str]:
        return [f"[{s.points:+d}] {s.evidence}" for s in self.signals]

    @property
    def summary(self) -> str:
        head = f"Verdict: {self.verdict.upper()} (score {self.score})"
        return "\n".join([head, *self.evidence])

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "score": self.score,
                "attack_techniques": self.attack_techniques,
                "evidence": self.evidence}


def parsed_from_dict(d: dict) -> ParsedEmail:
    """Validate and rebuild data from a trusted connector event, never raw mail JSON."""
    if not isinstance(d, dict):
        raise ValueError("Parsed email must be an object")
    d = dict(d)
    for name in ("message_id", "subject", "from_display", "from_address", "from_domain", "body_text", "body_html"):
        if not isinstance(d.get(name), str):
            raise ValueError(f"Parsed email {name} must be a string")
    for name in ("reply_to", "return_path", "date", "reporter", "source_file"):
        if d.get(name) is not None and not isinstance(d[name], str):
            raise ValueError(f"Parsed email {name} must be a string or null")
    for name in ("unwrapped", "has_form", "has_password_input"):
        if name in d and type(d[name]) is not bool:
            raise ValueError(f"Parsed email {name} must be a boolean")
    for name in ("to", "phone_numbers", "warnings"):
        items = d.get(name, [])
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
            raise ValueError(f"Parsed email {name} must be a string list")
    headers = d.get("headers")
    if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        raise ValueError("Parsed email headers must map strings to strings")
    auth = d.get("auth", {})
    if not isinstance(auth, dict):
        raise ValueError("Parsed email auth must be an object")
    for name in ("available", "trusted"):
        if name in auth and type(auth[name]) is not bool:
            raise ValueError(f"Authentication {name} must be a boolean")
    for name in ("spf", "dkim", "dmarc", "authserv_id"):
        if auth.get(name) is not None and not isinstance(auth[name], str):
            raise ValueError(f"Authentication {name} must be a string or null")
    try:
        links = d.get("links", [])
        attachments = d.get("attachments", [])
        if not isinstance(links, list) or not isinstance(attachments, list):
            raise ValueError("Links and attachments must be arrays")
        for item in links:
            if not isinstance(item, dict) or not isinstance(item.get("url"), str) or not isinstance(item.get("text", ""), str):
                raise ValueError("Invalid link object")
        for item in attachments:
            if not isinstance(item, dict) or any(not isinstance(item.get(k), str) for k in ("filename", "content_type", "sha256", "extension")):
                raise ValueError("Invalid attachment object")
            if type(item.get("size")) is not int or item["size"] < 0:
                raise ValueError("Invalid attachment size")
        d["links"] = [Link(**item) for item in links]
        d["attachments"] = [Attachment(**item) for item in attachments]
        d["auth"] = AuthResults(**auth)
        return ParsedEmail(**d)
    except TypeError as exc:
        raise ValueError("Invalid parsed email schema") from exc
