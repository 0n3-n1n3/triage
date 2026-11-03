"""Campaign clustering.

Built-in SOAR alert grouping matches if ANY entity overlaps and cannot
require several to match. Attackers also randomise per-recipient URLs.
So each email gets a 4-part fingerprint and two emails are the same
campaign when >= MIN_MATCHES of the 4 parts agree:

  1. url      - normalized URL set overlaps (tokens/query stripped)
  2. subject  - normalized subject equal (numbers/email addresses/RE:/FW: normalized)
  3. body     - SimHash Hamming distance <= BODY_MAX_DISTANCE (heuristic, not a text-similarity percentage)
  4. infra    - shares landing domain, attachment hash, or callback phone

Clusters are transitive (union-find): if A~B and B~C, all three are one case.
"""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass, field

from core.models import ParsedEmail
from core.normalize import host_of, normalize_subject, normalize_url, registered_domain

MIN_MATCHES = 2
BODY_MAX_DISTANCE = 10      # of 64 bits
MIN_BODY_TOKENS = 8         # tiny bodies make SimHash meaningless


def _tokens(text: str) -> list[str]:
    text = re.sub(r"https?://\S+", " ", text.lower())
    text = re.sub(r"\d+", "0", text)
    return re.findall(r"[a-z0]+", text)


def simhash(text: str, bits: int = 64) -> int | None:
    if type(bits) is not int or not 1 <= bits <= 64:
        raise ValueError("bits must be an integer between 1 and 64")
    toks = _tokens(text)
    if len(toks) < MIN_BODY_TOKENS:
        return None
    shingles = [" ".join(toks[i:i + 3]) for i in range(len(toks) - 2)]
    v = [0] * bits
    for sh in shingles:
        h = int.from_bytes(hashlib.sha256(sh.encode()).digest()[:8], "big")
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    return sum(1 << i for i in range(bits) if v[i] > 0)


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


@dataclass
class Fingerprint:
    urls: frozenset[str]
    subject: str
    body: int | None
    infra: frozenset[str]

    def to_dict(self) -> dict:
        return {"urls": sorted(self.urls), "subject": self.subject,
                "body_simhash": f"{self.body:016x}" if self.body is not None else None,
                "infra": sorted(self.infra)}


def fingerprint(e: ParsedEmail) -> Fingerprint:
    urls = frozenset(url for l in e.links if (url := normalize_url(l.url)))
    infra = set()
    for l in e.links:
        d = registered_domain(host_of(l.url))
        if d:
            infra.add(f"dom:{d}")
    infra |= {f"sha256:{a.sha256}" for a in e.attachments}
    infra |= {f"phone:{p}" for p in e.phone_numbers}
    return Fingerprint(urls, normalize_subject(e.subject), simhash(e.body_text), frozenset(infra))


def match_reasons(a: Fingerprint, b: Fingerprint) -> list[str]:
    r = []
    if a.urls and a.urls & b.urls:
        r.append("url")
    if a.subject and a.subject == b.subject:
        r.append("subject")
    if a.body is not None and b.body is not None and hamming(a.body, b.body) <= BODY_MAX_DISTANCE:
        r.append("body")
    if a.infra & b.infra:
        r.append("infra")
    return r


def same_campaign(a: Fingerprint, b: Fingerprint) -> bool:
    reasons = set(match_reasons(a, b))
    # URL and its domain are correlated, not two independent pieces of evidence.
    return len(reasons) >= MIN_MATCHES and bool(reasons & {"subject", "body"})


@dataclass
class Campaign:
    campaign_id: str
    members: list[int] = field(default_factory=list)   # indexes into input list

    @property
    def size(self) -> int:
        return len(self.members)


def campaign_key(fp: Fingerprint, discriminator: str = "") -> str:
    """Canonical, unambiguous ID including body; caller supplies scope/identity."""
    data = json.dumps([fp.to_dict(), discriminator], sort_keys=True, separators=(",", ":"))
    return "CMP-" + hashlib.sha256(data.encode()).hexdigest()[:20].upper()


def cluster(emails: list[ParsedEmail], partitions: list[str] | None = None) -> list[Campaign]:
    """O(n^2) pairwise union-find; benchmark representative volumes before scaling."""
    if partitions is not None and len(partitions) != len(emails):
        raise ValueError("partitions length must match emails")
    fps = [fingerprint(e) for e in emails]
    parent = list(range(len(emails)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(fps)):
        for j in range(i + 1, len(fps)):
            if (partitions is None or partitions[i] == partitions[j]) and same_campaign(fps[i], fps[j]):
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[rj] = ri

    groups: dict[int, list[int]] = {}
    for i in range(len(emails)):
        groups.setdefault(find(i), []).append(i)
    out = []
    used_ids = set()
    for _, members in sorted(groups.items(), key=lambda item: -len(item[1])):
        canonical = min((fps[index] for index in members), key=lambda fp: json.dumps(fp.to_dict(), sort_keys=True))
        identities = sorted({json.dumps([emails[index].message_id, emails[index].from_address,
                                        emails[index].subject, emails[index].body_text,
                                        fps[index].to_dict()], sort_keys=True)
                             for index in members})
        scope = partitions[members[0]] if partitions is not None else ""
        discriminator = json.dumps([scope, identities], separators=(",", ":"))
        cid = campaign_key(canonical, discriminator)
        ordinal = 1
        while cid in used_ids:
            cid = campaign_key(canonical, discriminator + f":{ordinal}")
            ordinal += 1
        used_ids.add(cid)
        out.append(Campaign(cid, members))
    return out
