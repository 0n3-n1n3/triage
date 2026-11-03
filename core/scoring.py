"""Explainable weighted scoring. Every point added is recorded as a Signal
with human-readable evidence, so an analyst can verify a verdict in seconds.

Design rules:
  * A signal fires at most once per email (no double counting 10 bad links).
  * Allowlisting never applies when authentication FAILED (spoofed partner).
  * Missing headers are reported, not guessed.
"""
from __future__ import annotations
import re
from typing import Optional

from core import config
from core.models import ParsedEmail, Signal, Verdict
from core.normalize import canonical_url, domain_matches, host_of, registered_domain
from core.validation import validate_config
from urllib.parse import urlsplit
from core.intelligence import Enrichment

DOMAINISH = re.compile(r"([a-z0-9-]+\.)+[a-z]{2,}", re.I)


class Scorer:
    def __init__(self, cfg: Optional[dict] = None, brands: Optional[dict] = None,
                 internal: Optional[dict] = None, allowlist: Optional[dict] = None):
        self.cfg = validate_config("scoring", cfg) if cfg is not None else config.load("scoring")
        self.w = self.cfg["weights"]
        self.brands = {k: v for k, v in (validate_config("brands", brands) if brands is not None else config.load("brands")).items() if not k.startswith("_")}
        self.internal = validate_config("internal", internal) if internal is not None else config.load("internal")
        self.allow = validate_config("allowlist", allowlist) if allowlist is not None else config.load("allowlist")
        self.corp = {d.lower() for d in self.internal.get("corporate_domains", [])}

    # ---------------------------------------------------------------- helpers
    def _legit_for_brand(self, brand: str, domain: str) -> bool:
        return any(domain_matches(domain, allowed) for allowed in [*self.brands.get(brand, []), *self.corp])

    def _claimed_brand(self, email: ParsedEmail) -> Optional[str]:
        hay = f"{email.from_display} {email.subject}".lower()
        for brand in self.brands:
            if re.search(rf"\b{re.escape(brand)}\b", hay) and not self._legit_for_brand(brand, email.from_domain):
                return brand
        return None

    def _is_external(self, email: ParsedEmail) -> bool:
        return not (email.auth.trusted and email.auth.dmarc == "pass"
                    and any(domain_matches(email.from_domain, d) for d in self.corp))

    def _external_link_domains(self, email: ParsedEmail) -> list[str]:
        sender = registered_domain(email.from_domain)
        out = []
        for l in email.links:
            d = registered_domain(host_of(l.url))
            if d and d != sender and d not in self.corp and d not in out:
                out.append(d)
        return out

    # ---------------------------------------------------------------- scoring
    def score(self, email: ParsedEmail, enr: Enrichment) -> Verdict:
        s: list[Signal] = []
        def add(name, evidence):
            s.append(Signal(name, self.w[name], evidence))

        invalid_intel = False

        def count(value):
            nonlocal invalid_intel
            try:
                if isinstance(value, bool) or value is None:
                    raise ValueError
                number = int(value)
                if number < 0 or float(value) != number:
                    raise ValueError
                return number
            except (TypeError, ValueError, OverflowError):
                invalid_intel = True
                return 0
        body = f"{email.subject}\n{email.body_text}".lower()
        external = self._is_external(email)

        # 1. Threat intel (strongest external evidence)
        mal_min = self.cfg["intel_malicious_min_engines"]
        sus_min = self.cfg["intel_suspicious_min_engines"]
        hits = []
        for kind, table in (("URL", enr.urls), ("domain", enr.domains), ("file", enr.hashes)):
            for ind, result in table.items():
                if not isinstance(result, dict):
                    invalid_intel = True
                    continue
                hits.append((count(result.get("malicious", 0)), count(result.get("suspicious", 0)), kind, ind))
        malicious = max(hits, key=lambda hit: hit[0], default=None)
        suspicious = max(hits, key=lambda hit: hit[0] + hit[1], default=None)
        if malicious and malicious[0] >= mal_min:
            m, _, kind, ind = malicious
            add("intel_malicious", f"Threat intel: {m} engines flag {kind} {ind}")
        elif suspicious and suspicious[0] + suspicious[1] >= sus_min:
            m, su, kind, ind = suspicious
            add("intel_suspicious", f"Threat intel: {m} malicious / {su} suspicious on {kind} {ind}")

        # 2. Young infrastructure; invalid age is unknown, not 'young'.
        young = []
        for domain, result in enr.domains.items():
            if not isinstance(result, dict) or result.get("age_days") is None:
                continue
            before = invalid_intel
            age_value = result["age_days"]
            try:
                if isinstance(age_value, bool) or float(age_value) < 0 or float(age_value) != int(age_value):
                    raise ValueError
                age = int(age_value)
            except (ValueError, TypeError, OverflowError):
                invalid_intel = True
                continue
            invalid_intel = before
            if age < self.cfg["young_domain_days"]:
                young.append((domain, age))
        if young:
            domain, age = min(young, key=lambda item: item[1])
            add("young_domain", f"Domain {domain} registered {age} days ago")

        # 3. Sender authentication
        brand = self._claimed_brand(email)
        a = email.auth
        if not a.available:
            s.append(Signal("headers_unavailable", 0,
                            "Authentication headers unavailable (inline forward?) - auth signals skipped, lower confidence"))
        if a.available and not a.trusted:
            s.append(Signal("auth_untrusted", 0, "Authentication header provenance is not trusted"))
        if a.dmarc == "fail" and brand:
            add("dmarc_fail_brand", f"DMARC fail while claiming to be {brand}")
        elif any(value in ("fail", "softfail", "temperror", "permerror") for value in (a.spf, a.dkim, a.dmarc)):
            add("auth_fail", f"Auth failure: spf={a.spf} dkim={a.dkim} dmarc={a.dmarc}")

        # 4. Impersonation
        if brand:
            add("brand_impersonation",
                f"Claims '{brand}' in name/subject but sent from {email.from_domain or 'unknown domain'}")
        disp = email.from_display.lower()
        for ex in self.internal.get("executives", []):
            if ex.lower() in disp and external:
                add("exec_impersonation", f"Display name '{email.from_display}' matches executive, sender is external {email.from_address}")
                break

        if email.reply_to and email.from_address:
            rt_dom = registered_domain(email.reply_to.split("@")[-1])
            if rt_dom != registered_domain(email.from_domain):
                add("reply_to_mismatch", f"Reply-To {email.reply_to} differs from From {email.from_address}")

        # 5. Link deception
        for l in email.links:
            m = DOMAINISH.search(l.text or "")
            if m and (l.text.lower().startswith(("http", "www")) or "/" in l.text or m.group(0) == l.text.strip().lower()):
                shown = registered_domain(host_of(m.group(0)))
                real = registered_domain(host_of(l.url))
                if shown and real and shown != real:
                    add("link_text_mismatch", f"Link text shows {shown} but points to {real}")
                    break
        prefixes = self.internal.get("sharepoint_prefixes", [])

        def approved_tenant(url):
            normalized = canonical_url(url)
            if not normalized:
                return False
            target = urlsplit(normalized)
            if target.username is not None or target.scheme != "https":
                return False
            for prefix in prefixes:
                expected = canonical_url(prefix)
                if not expected:
                    continue
                base = urlsplit(expected)
                # Ambiguous encoding/dot segments cannot authorize an internal path.
                if '%' in target.path or any(x in ('.', '..') for x in target.path.split('/')):
                    return False
                prefix_path = base.path.rstrip('/')
                if (base.scheme == 'https' and base.username is None and target.netloc == base.netloc
                        and (target.path == prefix_path or target.path.startswith(prefix_path + '/'))):
                    return True
            return False
        for l in email.links:
            mentions = any(k in f"{l.text} {l.url}".lower() for k in ("sharepoint", "onedrive"))
            if mentions and not approved_tenant(l.url):
                add("fake_internal_link", f"SharePoint/OneDrive link not on corporate tenant: {l.url}")
                break

        # 6. Credential harvest
        ext_links = self._external_link_domains(email)
        login_hit = next((u for u, r in enr.urls.items() if isinstance(r, dict) and r.get("login_page") is True), None)
        cred_terms = any(t in body for t in self.cfg["credential_terms"])
        if email.has_password_input:
            add("credential_harvest", "Password input detected in email HTML")
        elif login_hit:
            add("credential_harvest", f"Login page detected at {login_hit}")
        elif cred_terms and ext_links and (brand or young or any(x.name == "fake_internal_link" for x in s)):
            add("credential_harvest", f"Credential lure text + external link to {ext_links[0]}")

        # 7. Attachments
        risky = [a for a in email.attachments if a.extension.lower() in self.cfg["risky_extensions"]]
        if risky:
            add("risky_attachment", f"Risky attachment type: {', '.join(a.filename for a in risky)}")

        # 8. Social engineering language
        if external and any(t in body for t in self.cfg["urgency_terms"]):
            add("urgency_external", "Urgency language from external sender")

        # 9. TOAD / callback phishing (no link, no attachment, phone number)
        if email.phone_numbers and not email.links and not email.attachments \
                and any(t in body for t in self.cfg["toad_terms"]) and external:
            add("toad_callback", f"Callback scam pattern: phone {email.phone_numbers[0]} + billing lure, no links")

        # 10. Reducers require trusted positive authentication and no risk signal.
        # A negative score must not erase intel, an attachment, or another warning.
        auth_failed = any(value in ("fail", "softfail", "temperror", "permerror")
                          for value in (a.spf, a.dkim, a.dmarc))
        authenticated = a.trusted and a.dmarc == "pass" and not auth_failed
        risk_names = {signal.name for signal in s if signal.name in self.w and self.w[signal.name] >= 0}
        incomplete = bool(email.warnings or enr.errors or enr.truncated or invalid_intel)
        can_reduce = authenticated and not risk_names and not incomplete
        if can_reduce and (any(domain_matches(email.from_domain, d) for d in self.allow.get("sender_domains", []))
                           or email.from_address.lower() in {a.lower() for a in self.allow.get("sender_addresses", [])}):
            add("allowlisted_sender", f"Allowlisted sender {email.from_address} with trusted passing DMARC")
        headers = {key.lower(): value for key, value in email.headers.items()}
        if can_reduce and ("list-unsubscribe" in headers or headers.get("precedence", "").lower() == "bulk"):
            add("bulk_marketing", "Authenticated bulk/marketing mail with no detected risk signals")
        for warning in email.warnings:
            s.append(Signal("parse_warning", 0, warning))
        if enr.errors:
            s.append(Signal("enrichment_error", 0, "Threat-intel lookup failures; analyst review required"))
        if enr.truncated:
            s.append(Signal("enrichment_limited", 0, "Indicator limits reached; not all indicators inspected"))
        if invalid_intel:
            s.append(Signal("invalid_intel", 0, "Malformed intelligence values; treated as unknown"))

        score = max(0, sum(signal.points for signal in s))
        thresholds = self.cfg["thresholds"]
        verdict = "malicious" if score >= thresholds["malicious"] else "benign" if score <= thresholds["benign"] else "uncertain"
        if verdict == "benign" and (not authenticated or risk_names or incomplete):
            verdict = "uncertain"
            s.append(Signal("review_required", 0, "Low score is not proof of safety; authentication, risk, or completeness requires review"))
        return Verdict(verdict, score, s, self._attack(email, s, verdict))

    def _attack(self, email: ParsedEmail, s: list[Signal], verdict: str) -> list[str]:
        if verdict == "benign":
            return []
        m = self.cfg["attack_mapping"]
        names = {x.name for x in s}
        out = []
        if email.links:
            out.append(m["link"])
        if email.attachments:
            out.append(m["attachment"])
        if "toad_callback" in names:
            out.append(m["voice"])
        if "credential_harvest" in names:
            out.append(m["credential_harvest"])
        return out
