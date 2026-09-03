from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from django.utils import timezone

if TYPE_CHECKING:
    from intel.models import Item


ACTIVE_EXPLOITATION = "active_exploitation"
RANSOMWARE = "ransomware"
VULNERABILITY = "vulnerability"
THREAT_NEWS = "threat_news"
RESEARCH = "research"
NORDIC = "nordic"

HIGH_SIGNAL_MIN_SCORE = 20
CONCISE_SUMMARY_MAX_CHARS = 2_000
SUMMARY_LEAD_MAX_CHARS = 1_200

EVIDENCE_AUTHORITATIVE = "authoritative"
EVIDENCE_TITLE = "title"
EVIDENCE_SUMMARY = "summary"
EVIDENCE_METADATA = "metadata"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
ACTIVE_EXPLOITATION_PATTERNS = (
    re.compile(r"\bactively exploited\b", re.IGNORECASE),
    re.compile(r"\bactive exploitation\b", re.IGNORECASE),
    re.compile(r"\bexploited in the wild\b", re.IGNORECASE),
    re.compile(r"\bin[- ]the[- ]wild exploitation\b", re.IGNORECASE),
    re.compile(r"\bexploitation in the wild\b", re.IGNORECASE),
)
TITLE_ACTIVE_EXPLOITATION_PATTERNS = ACTIVE_EXPLOITATION_PATTERNS + (
    re.compile(
        r"\b(?:attackers?|hackers?|cyber actors?|threat actors?)\s+"
        r"(?:(?:are|were|have been)\s+)?(?:actively\s+)?"
        r"exploit(?:s|ed|ing)?\b",
        re.IGNORECASE,
    ),
)
EXPLOITATION_NEGATION_PATTERNS = (
    re.compile(
        r"\bnot\s+"
        r"(?:(?:known|reported|observed|believed|confirmed)\s+to\s+be\s+|"
        r"currently\s+|yet\s+|being\s+|been\s+|actively\s+)*"
        r"(?:actively\s+)?exploited(?:\s+in\s+the\s+wild)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:no|without)\s+"
        r"(?:(?:known|credible|reported)\s+)?(?:evidence\s+of\s+)?"
        r"(?:any\s+)?(?:active\s+)?exploitation(?:\s+in\s+the\s+wild)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bnot\s+(?:currently\s+)?aware\s+of\s+(?:any\s+)?"
        r"(?:active\s+)?exploitation(?:\s+in\s+the\s+wild)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:active\s+|in[- ]the[- ]wild\s+)?exploitation\s+"
        r"(?:has|have|had|is|was|were)\s+not\s+(?:been\s+)?"
        r"(?:observed|reported|confirmed|seen|detected)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bnone\s+(?:(?:are|were|is|was)\s+)?(?:listed\s+as\s+)?"
        r"(?:being\s+|actively\s+)*exploited\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bno longer\s+(?:being\s+|actively\s+)*"
        r"exploited(?:\s+in\s+the\s+wild)?\b",
        re.IGNORECASE,
    ),
)
RANSOMWARE_TERMS = (
    "ransomware",
    "extortion",
    "leak site",
    "victim listing",
)
RANSOMWARE_PATTERNS = tuple(
    re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    for term in RANSOMWARE_TERMS
)
RANSOMWARE_NEGATION_PATTERNS = (
    re.compile(r"\b(?:not|never)\s+(?:a\s+)?ransomware\b", re.IGNORECASE),
    re.compile(
        r"\b(?:no|without|absence\s+of)\s+"
        r"(?:(?:any|known|financial)\s+)*extortion\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:not|never)\s+(?:an?\s+)?extortion\b", re.IGNORECASE),
)
BROAD_COLLECTION_TITLE_RE = re.compile(
    r"\b(?:security update review|security updates? review|"
    r"patch(?:es)? (?:review|roundup)|patch tuesday|"
    r"(?:monthly|weekly) (?:security )?(?:review|roundup|digest))\b",
    re.IGNORECASE,
)
VULNERABILITY_TERMS = (
    "vulnerability",
    "security advisory",
    "remote code execution",
    "authentication bypass",
    "zero-day",
    "0day",
)
URGENT_TERMS = ("critical", "urgent", "emergency")
HIGH_CVSS_RE = re.compile(
    r"\bcvss(?:\s+score)?\s*(?:of|:|=)?\s*(?:9(?:\.\d+)?|10(?:\.0+)?)\b",
    re.IGNORECASE,
)
LOW_SIGNAL_TITLE_HINTS = (
    "release notes",
    "release note",
    "maintenance release",
    "maintenance update",
    "version ",
    "version:",
    "product update",
    "feature update",
    "service update",
    "platform update",
    "minor update",
    "release announcement",
    "now available",
)
NORDIC_TEXT_TERMS = (
    "sweden",
    "swedish",
    "sverige",
    "nordic",
    "norway",
    "norwegian",
    "denmark",
    "danish",
    "finland",
    "finnish",
    "iceland",
    "icelandic",
)
NORDIC_SOURCE_TAGS = frozenset(
    {"sweden", "nordic", "norway", "denmark", "finland", "iceland"}
)
NORDIC_COUNTRIES = frozenset(
    {"sweden", "se", "norway", "no", "denmark", "dk", "finland", "fi", "iceland", "is"}
)
NORDIC_TEXT_PATTERNS = tuple(
    re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    for term in NORDIC_TEXT_TERMS
)


@dataclass(frozen=True, slots=True)
class SignalProfile:
    primary_category: str
    categories: tuple[str, ...]
    score: int
    priority: str
    reasons: tuple[str, ...]
    cves: tuple[str, ...]
    active_exploitation: bool
    active_exploitation_evidence: str
    ransomware: bool
    ransomware_evidence: str
    vulnerability: bool
    threat_news: bool
    research: bool
    nordic_relevance: bool
    nordic_evidence: str
    urgent: bool
    high_signal: bool
    is_low_signal_title: bool

    @property
    def primary_reason(self) -> str:
        return self.reasons[0] if self.reasons else ""

    @property
    def signal_label(self) -> str:
        if self.active_exploitation:
            return "Active exploitation"
        if self.ransomware:
            return "Ransomware"
        if self.vulnerability and self.cves and self.urgent:
            return "Critical CVE"
        if self.vulnerability and self.cves:
            return "CVE-driven"
        if self.vulnerability:
            return "Vulnerability"
        if self.urgent:
            return "Urgent"
        if self.nordic_relevance:
            return "Nordic"
        if self.research:
            return "Research"
        if self.threat_news:
            return "Threat news"
        return ""

    @property
    def signal_tone(self) -> str:
        if self.active_exploitation or self.urgent:
            return "amber"
        if self.ransomware:
            return "rose"
        return "sky"


def extract_cve_ids(text: str) -> tuple[str, ...]:
    seen = set()
    cves = []
    for match in CVE_RE.findall(text or ""):
        cve = match.upper()
        if cve in seen:
            continue
        seen.add(cve)
        cves.append(cve)
    return tuple(cves)


def item_text(item: Item) -> str:
    return f"{item.title or ''}\n{item.summary or ''}"


def _summary_signal_text(item: Item) -> str:
    summary = item.summary or ""
    # A long roundup describes multiple independent events. Its covered-item
    # wording is not evidence that the collection itself is an exploitation,
    # ransomware, or regional event; structured and title evidence still win.
    if len(summary) > CONCISE_SUMMARY_MAX_CHARS and BROAD_COLLECTION_TITLE_RE.search(
        item.title or ""
    ):
        return ""
    if len(summary) <= CONCISE_SUMMARY_MAX_CHARS:
        return summary
    return summary[:SUMMARY_LEAD_MAX_CHARS]


def _match_is_negated(
    text: str,
    match: re.Match,
    negation_patterns: tuple[re.Pattern, ...],
) -> bool:
    context_start = max(0, match.start() - 120)
    context_end = min(len(text), match.end() + 120)
    context = text[context_start:context_end]
    for pattern in negation_patterns:
        for negation in pattern.finditer(context):
            negation_start = context_start + negation.start()
            negation_end = context_start + negation.end()
            if negation_start <= match.start() and negation_end >= match.end():
                return True
    return False


def _has_signal_match(
    text: str,
    patterns: tuple[re.Pattern, ...],
    *,
    negation_patterns: tuple[re.Pattern, ...] = (),
) -> bool:
    for pattern in patterns:
        for match in pattern.finditer(text):
            if not _match_is_negated(text, match, negation_patterns):
                return True
    return False


def normalize_source_tags(tags) -> frozenset[str]:
    return frozenset(
        str(tag).strip().lower()
        for tag in (tags or [])
        if str(tag).strip()
    )


def _source_tags(item: Item) -> frozenset[str]:
    source = getattr(item, "source", None)
    return normalize_source_tags(getattr(source, "tags", None))


def _raw_country(item: Item) -> str:
    raw_payload = getattr(item, "raw_payload", None)
    if not isinstance(raw_payload, dict):
        return ""
    return str(raw_payload.get("country") or "").strip().lower()


def _activity_at(item: Item, now: datetime) -> datetime:
    return (
        getattr(item, "activity_at", None)
        or getattr(item, "published_at", None)
        or getattr(item, "created_at", None)
        or now
    )


def _priority_for_score(score: int) -> str:
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= HIGH_SIGNAL_MIN_SCORE:
        return "P3"
    return "P4"


def classify_item(item: Item, *, now: datetime | None = None) -> SignalProfile:
    now = now or timezone.now()
    text = item_text(item)
    lowered_text = text.lower()
    lowered_title = (item.title or "").lower()
    title = item.title or ""
    summary_signal_text = _summary_signal_text(item)
    feed = getattr(item, "feed", None)
    source = getattr(item, "source", None)
    adapter_key = (getattr(feed, "adapter_key", "") or "").strip().lower()
    section = (getattr(feed, "section", "") or "").strip().lower()
    source_slug = (getattr(source, "slug", "") or "").strip().lower()
    source_tags = _source_tags(item)
    raw_payload = getattr(item, "raw_payload", None)
    raw_payload = raw_payload if isinstance(raw_payload, dict) else {}

    cves = extract_cve_ids(text)
    is_cisa_kev = adapter_key == "cisa_kev"
    # EPSS describes probability, and its generated summary contains predictive
    # "exploitation in the wild" wording. It is not observed exploitation.
    title_exploitation = adapter_key != "epss" and _has_signal_match(
        title,
        TITLE_ACTIVE_EXPLOITATION_PATTERNS,
        negation_patterns=EXPLOITATION_NEGATION_PATTERNS,
    )
    summary_exploitation = adapter_key != "epss" and _has_signal_match(
        summary_signal_text,
        ACTIVE_EXPLOITATION_PATTERNS,
        negation_patterns=EXPLOITATION_NEGATION_PATTERNS,
    )
    if is_cisa_kev:
        active_exploitation_evidence = EVIDENCE_AUTHORITATIVE
    elif title_exploitation:
        active_exploitation_evidence = EVIDENCE_TITLE
    elif summary_exploitation:
        active_exploitation_evidence = EVIDENCE_SUMMARY
    else:
        active_exploitation_evidence = ""
    explicit_exploitation = bool(active_exploitation_evidence) and not is_cisa_kev
    active_exploitation = bool(active_exploitation_evidence)

    ransomware_live_victim = adapter_key == "ransomware_live_victims"
    known_ransomware_use = is_cisa_kev and str(
        raw_payload.get("knownRansomwareCampaignUse") or ""
    ).strip().lower() == "known"
    title_ransomware = _has_signal_match(
        title,
        RANSOMWARE_PATTERNS,
        negation_patterns=RANSOMWARE_NEGATION_PATTERNS,
    )
    summary_ransomware = _has_signal_match(
        summary_signal_text,
        RANSOMWARE_PATTERNS,
        negation_patterns=RANSOMWARE_NEGATION_PATTERNS,
    )
    if ransomware_live_victim or known_ransomware_use:
        ransomware_evidence = EVIDENCE_AUTHORITATIVE
    elif title_ransomware:
        ransomware_evidence = EVIDENCE_TITLE
    elif summary_ransomware:
        ransomware_evidence = EVIDENCE_SUMMARY
    else:
        ransomware_evidence = ""
    ransomware = bool(ransomware_evidence)

    vulnerability = bool(cves) or adapter_key in {"cisa_kev", "epss"}
    vulnerability = vulnerability or section == "advisories" or "vendor" in source_tags
    vulnerability = vulnerability or any(term in lowered_text for term in VULNERABILITY_TERMS)

    research = section == "research" or "research" in source_tags
    threat_news = "news" in source_tags
    nordic_metadata = (
        section == "sweden"
        or source_slug == "cert-se"
        or bool(source_tags & NORDIC_SOURCE_TAGS)
        or _raw_country(item) in NORDIC_COUNTRIES
    )
    if nordic_metadata:
        nordic_evidence = EVIDENCE_METADATA
    elif _has_signal_match(title, NORDIC_TEXT_PATTERNS):
        nordic_evidence = EVIDENCE_TITLE
    elif _has_signal_match(summary_signal_text, NORDIC_TEXT_PATTERNS):
        nordic_evidence = EVIDENCE_SUMMARY
    else:
        nordic_evidence = ""
    nordic_relevance = bool(nordic_evidence)
    urgent = any(term in lowered_text for term in URGENT_TERMS) or bool(
        HIGH_CVSS_RE.search(text)
    )
    is_low_signal_title = any(hint in lowered_title for hint in LOW_SIGNAL_TITLE_HINTS)

    categories = tuple(
        category
        for category, present in (
            (ACTIVE_EXPLOITATION, active_exploitation),
            (RANSOMWARE, ransomware),
            (VULNERABILITY, vulnerability),
            (RESEARCH, research),
            (THREAT_NEWS, threat_news),
            (NORDIC, nordic_relevance),
        )
        if present
    )
    primary_category = categories[0] if categories else "uncategorized"

    score = 0
    reasons = []

    if is_cisa_kev:
        score += 52
        reasons.append("CISA KEV")
    elif explicit_exploitation:
        score += 40
        if active_exploitation_evidence == EVIDENCE_TITLE:
            reasons.append("Active exploitation in title")
        else:
            reasons.append("Active exploitation in summary")

    if ransomware:
        score += 32
        if ransomware_live_victim:
            reasons.append("Ransomware.live victim")
        elif known_ransomware_use:
            reasons.append("Known ransomware campaign use")
        elif ransomware_evidence == EVIDENCE_TITLE:
            reasons.append("Ransomware or extortion in title")
        else:
            reasons.append("Ransomware or extortion in summary")

    if vulnerability:
        score += 8
        if cves:
            score += 18 + min(len(cves), 3) * 2
            reasons.append("CVE referenced")
        else:
            reasons.append("Vulnerability advisory context")

    if urgent:
        score += 10
        reasons.append("Urgent security wording")
    if nordic_relevance:
        score += 8
        if nordic_evidence == EVIDENCE_METADATA:
            reasons.append("Nordic source or metadata")
        elif nordic_evidence == EVIDENCE_TITLE:
            reasons.append("Nordic relevance in title")
        else:
            reasons.append("Nordic relevance in summary")
    if research:
        score += 4
        reasons.append("Research source or feed")
    if threat_news:
        score += 3
        reasons.append("Security news source")

    activity_at = _activity_at(item, now)
    age_hours = max((now - activity_at).total_seconds() / 3600, 0)
    if age_hours <= 24:
        score += 10
        reasons.append("Published within 24 hours")
    elif age_hours <= 72:
        score += 6
        reasons.append("Published within 72 hours")
    else:
        score += 3
        reasons.append("Recent stored item")

    if is_low_signal_title and not (
        active_exploitation or ransomware or vulnerability or urgent
    ):
        score -= 18
        reasons.append("Routine release wording")

    score = max(0, min(score, 100))
    return SignalProfile(
        primary_category=primary_category,
        categories=categories,
        score=score,
        priority=_priority_for_score(score),
        reasons=tuple(reasons),
        cves=cves,
        active_exploitation=active_exploitation,
        active_exploitation_evidence=active_exploitation_evidence,
        ransomware=ransomware,
        ransomware_evidence=ransomware_evidence,
        vulnerability=vulnerability,
        threat_news=threat_news,
        research=research,
        nordic_relevance=nordic_relevance,
        nordic_evidence=nordic_evidence,
        urgent=urgent,
        high_signal=score >= HIGH_SIGNAL_MIN_SCORE,
        is_low_signal_title=is_low_signal_title,
    )
