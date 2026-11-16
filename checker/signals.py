"""Verification signals: checks that look at WHO is writing and WHERE links go.

These look outside the wording. They report signals, not proof: a new domain or a
free-email address does not make a message a scam, but real employers rarely do these.

Domain-age lookups are optional and off by default. When enabled, only the domain name
(never the message text) is sent to the public RDAP registry.
"""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Callable, Optional

from .core import Finding

EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
URL_RX = re.compile(r"(?:https?://|www\.)[^\s<>\)\]\"']+", re.I)
BARE_DOMAIN_RX = re.compile(r"\b((?:forms\.gle|bit\.ly|tinyurl\.com|t\.ly|rb\.gy|cutt\.ly|is\.gd|ow\.ly|shorturl\.at)/\S*)", re.I)

FREE_EMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
              "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com", "live.com",
              "msn.com", "zoho.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "rb.gy", "cutt.ly", "is.gd", "ow.ly", "buff.ly",
              "shorturl.at", "goo.gl"}
FORM_HOSTS = ("forms.gle", "docs.google.com/forms", "typeform.com", "jotform.com", "forms.office.com",
              "airtable.com/shr", "surveymonkey.com", "forms.zohopublic.com")
SUSPICIOUS_TLDS = {"xyz", "top", "click", "work", "buzz", "icu", "loan", "rest", "gq", "tk", "ml", "cf", "ga"}

# company -> official email/web domains. Small on purpose: only names students often see impersonated.
KNOWN_COMPANIES: dict[str, set[str]] = {
    "amazon": {"amazon.com", "amazon.jobs", "a2z.com", "amazon.co.uk", "amazon.in"},
    "google": {"google.com", "goog.com"},
    "microsoft": {"microsoft.com"},
    "meta": {"meta.com", "fb.com", "facebook.com"},
    "apple": {"apple.com"},
    "netflix": {"netflix.com"},
    "deloitte": {"deloitte.com"},
    "accenture": {"accenture.com"},
    "ibm": {"ibm.com"},
    "oracle": {"oracle.com"},
    "cisco": {"cisco.com"},
    "intel": {"intel.com"},
    "nvidia": {"nvidia.com"},
    "salesforce": {"salesforce.com"},
    "walmart": {"walmart.com", "walmartlabs.com"},
    "tesla": {"tesla.com"},
    "jpmorgan": {"jpmorgan.com", "jpmchase.com", "chase.com"},
    "goldman sachs": {"gs.com", "goldmansachs.com"},
    "linkedin": {"linkedin.com"},
    "adp": {"adp.com"},
}

Fetcher = Callable[[str], Optional[datetime]]


def _domain_matches(domain: str, official: set[str]) -> bool:
    d = domain.lower()
    return any(d == o or d.endswith("." + o) for o in official)


def _host(url: str) -> str:
    u = re.sub(r"^(?:https?://)?(?:www\.)?", "", url, flags=re.I)
    return re.split(r"[/?#:]", u, maxsplit=1)[0].lower()


@lru_cache(maxsize=256)
def rdap_registration_date(domain: str) -> Optional[datetime]:
    """Look up when a domain was registered. Returns None on any failure."""
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}",
                                     headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
    except Exception:
        return None
    return None


def find(lines: list[tuple[int, str]], lookup: bool = False, fetcher: Optional[Fetcher] = None,
         now: Optional[datetime] = None) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info = {"domains_checked": 0, "lookups_failed": 0}
    now = now or datetime.now(timezone.utc)
    full = "\n".join(t for _, t in lines)
    mentioned = [c for c in KNOWN_COMPANIES if re.search(rf"\b{re.escape(c)}\b", full, re.I)]
    sender_domains: dict[str, int] = {}   # domain -> first line id
    for lid, text in lines:
        for m in EMAIL_RX.finditer(text):
            sender_domains.setdefault(m.group(1).lower(), lid)

    # 1. Free-email address used by someone claiming to hire
    hiring_words = re.search(r"recruit|hiring|talent|\bhr\b|human resources|interview|position|opening", full, re.I)
    for dom, lid in sender_domains.items():
        if dom in FREE_EMAIL and hiring_words:
            findings.append(Finding(
                "Recruiter uses a free email address",
                "Real recruiters almost always write from a company address, not a free email account."
                + (f" Here the message also names {mentioned[0].title()}, which makes impersonation more likely."
                   if mentioned else ""),
                "high" if mentioned else "medium", [lid], quote=_email_on(lines, lid, dom),
                rule_id="free_email_recruiter",
                advice="Ask for a company email address and check it on the company's own site.", kind="signal"))

    # 2. Claimed company vs. sender domain
    for company in mentioned:
        official = KNOWN_COMPANIES[company]
        for dom, lid in sender_domains.items():
            if dom in FREE_EMAIL or _domain_matches(dom, official):
                continue
            flat = dom.replace("-", "").replace(".", "").translate(str.maketrans("01345", "oleas"))
            lookalike = company.replace(" ", "") in flat or company.replace(" ", "") in flat.replace("rn", "m")
            findings.append(Finding(
                f"Email domain does not match {company.title()}" + (" (look-alike)" if lookalike else ""),
                f"The message mentions {company.title()}, but it comes from {dom}, which is not one of that "
                f"company's known domains." + (" The name is embedded in a different domain, a common impersonation trick." if lookalike else ""),
                "high" if lookalike else "medium", [lid], quote=dom, rule_id="domain_mismatch",
                advice=f"Find a recruiter through {company.title()}'s official careers site instead of replying.",
                kind="signal"))

    # 3. Links
    seen_hosts: set[str] = set()
    for lid, text in lines:
        links = [m.group(0) for m in URL_RX.finditer(text)] + [m.group(1) for m in BARE_DOMAIN_RX.finditer(text)]
        for link in links:
            host = _host(link if re.match(r"(?:https?://|www\.)", link, re.I) else "http://" + link)
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if host in SHORTENERS:
                findings.append(Finding("Shortened link hides the destination",
                                        "You cannot see where this link really goes.", "medium", [lid], quote=link,
                                        rule_id="link_shortener", advice="Do not click. Ask for the full link.", kind="signal"))
            elif any(h in link.lower() for h in FORM_HOSTS):
                findings.append(Finding("Link to a form that collects your details",
                                        "A form can collect personal data before you know who the employer is.",
                                        "medium", [lid], quote=link, rule_id="form_link",
                                        advice="Verify the employer before filling anything in.", kind="signal"))
            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                findings.append(Finding("Link goes to a raw IP address",
                                        "Legitimate employers use named websites, not numbers.", "high", [lid],
                                        quote=link, rule_id="ip_link", advice="Do not click.", kind="signal"))
            elif tld in SUSPICIOUS_TLDS:
                findings.append(Finding("Link uses an unusual domain ending",
                                        f"Domains ending in .{tld} are heavily used for throwaway sites.", "low",
                                        [lid], quote=link, rule_id="odd_tld",
                                        advice="Check the company's real website independently.", kind="signal"))

    # 4. Optional: how new is the sender's domain?
    if lookup:
        get = fetcher or rdap_registration_date
        for dom, lid in sender_domains.items():
            if dom in FREE_EMAIL or any(_domain_matches(dom, o) for o in KNOWN_COMPANIES.values()):
                continue
            info["domains_checked"] += 1
            created = get(dom)
            if created is None:
                info["lookups_failed"] += 1
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).days
            if age < 90:
                findings.append(Finding(
                    "Sender's domain is very new",
                    f"{dom} was registered {age} days ago. Established employers rarely email from brand-new domains.",
                    "high" if age < 30 else "medium", [lid], quote=dom, rule_id="new_domain",
                    advice="Check that the company has a real, older website and listings.", kind="signal"))
    return findings, info


def _email_on(lines: list[tuple[int, str]], lid: int, dom: str) -> str:
    text = dict(lines)[lid]
    m = re.search(rf"[A-Za-z0-9._%+-]+@{re.escape(dom)}", text, re.I)
    return m.group(0) if m else dom
