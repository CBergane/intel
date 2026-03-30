import hashlib
import html
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
NOISE_BLOCK_RE = re.compile(
    r"<(script|style|noscript|template|svg|canvas|iframe|object|embed|meta|link)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
NAV_BLOCK_RE = re.compile(
    r"<(header|nav|footer|aside|form)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
BODY_RE = re.compile(r"<body[^>]*>(.*?)</body>", re.IGNORECASE | re.DOTALL)
MAIN_RE = re.compile(r"<(article|main)[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
STRUCTURED_LINE_BREAK_RE = re.compile(
    r"(?i)<br\s*/?>|</(?:p|div|li|td|th|tr|h1|h2|h3|h4|section|article|ul|ol)>"
)
CONTENT_CONTAINER_RE = re.compile(
    r'<(section|div)[^>]*(?:id|class)\s*=\s*["\'][^"\']*(?:content|article|post|entry|story|main|body|text|markdown)[^"\']*["\'][^>]*>(.*?)</\1>',
    re.IGNORECASE | re.DOTALL,
)
HREF_RE = re.compile(
    r"""<a[^>]+href=["'](?P<href>[^"']+)["'][^>]*>""",
    re.IGNORECASE,
)
ANCHOR_TEXT_RE = re.compile(
    r"""<a[^>]+href=["'](?P<href>[^"']+)["'][^>]*>(?P<label>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
RECORD_TITLE_RE = re.compile(
    r"<(h1|h2|h3|h4|strong|b|th)[^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
INCIDENT_HEADING_RE = re.compile(
    r"<(h2|h3|h4)[^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
OPEN_BLOCK_RE = re.compile(r"<(?P<tag>article|section|div|li)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
TABLE_RE = re.compile(r"<table[^>]*>.*?</table>", re.IGNORECASE | re.DOTALL)
ROW_RE = re.compile(r"<tr[^>]*>.*?</tr>", re.IGNORECASE | re.DOTALL)
CELL_RE = re.compile(r"<(td|th)[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"\s+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
URL_TEXT_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
INTEGER_RE = re.compile(r"\b\d[\d,]*\b")
CSS_JUNK_RE = re.compile(
    r"(?i)(font-family|display\s*:|margin\s*:|padding\s*:|background\s*:|var\(|@media|{[^}]{1,200}})"
)
BOILERPLATE_SENTENCE_RE = re.compile(
    r"(?i)\b(cookie|privacy policy|terms of service|subscribe|newsletter|all rights reserved|sign in|sign up|accept cookies|advertisement|skip to content)\b"
)
NEWSLIKE_HOST_HINTS = (
    "blog",
    "news",
    "research",
    "securityweek",
    "krebsonsecurity",
    "bleepingcomputer",
    "therecord",
    "arstechnica",
    "threatpost",
    "medium",
)
GROUP_BLOCK_HINTS = (
    "card",
    "item",
    "entry",
    "profile",
    "group",
    "gang",
    "actor",
)
MAX_STRUCTURED_RECORD_TEXT = 2800
STRUCTURED_CONTENT_HINT_RE = re.compile(
    r"(?i)\b("
    r"attack|attacks|actor|actors|activity|active|breach|breached|breaching|campaign|claim|claimed|"
    r"compromise|compromised|details|disclosure|disclosures|disclosed|disclosing|discussion|entry|entries|"
    r"extortion|group|groups|incident|indicators|initial access|leak|leaked|leaking|malware|"
    r"negotiation|operator|operators|posted|posting|published|publishing|ransomware|report|"
    r"reported|target|targeting|targets|timeline|update|updates|victim|victims"
    r")\b"
)
GROUP_NAME_LABELS = (
    "group name",
    "ransomware group",
    "threat group",
    "threat actor",
    "actor",
    "group",
    "gang",
    "operator",
)
VICTIM_NAME_LABELS = ("victim name", "victim", "company", "organization")
COUNTRY_LABELS = (
    "country",
    "victim country",
    "country / region",
    "country/region",
    "location",
    "headquarters",
    "hq",
)
INDUSTRY_LABELS = ("industry", "sector")
VICTIM_COUNT_LABELS = ("victim count", "victims", "listed victims")
LAST_ACTIVITY_LABELS = ("last activity", "last seen", "last update", "updated", "activity")
WEBSITE_LABELS = ("company website", "official website", "website", "site")
GENERIC_INCIDENT_TITLE_RE = re.compile(
    r"(?i)\b("
    r"ransom-db\s*\|\s*live threat command center|"
    r"live threat command center|"
    r"threat groups|"
    r"api access|"
    r"blog|"
    r"documentation|"
    r"latest updates"
    r")\b"
)
INCIDENT_NAV_TEXT_RE = re.compile(
    r"(?i)\b("
    r"blog|"
    r"api access|"
    r"threat groups|"
    r"documentation|"
    r"contact|"
    r"about|"
    r"pricing|"
    r"dashboard"
    r")\b"
)
INCIDENT_FRAGMENT_CUTOFF_RE = re.compile(
    r"(?i)\b("
    r"showing\s+\d+\s+of\s+\d+\s+results|"
    r"free plan limits search|"
    r"page\s+\d+\s+of\s+\d+|"
    r"pro users see all|"
    r"upgrade to researcher|"
    r"view pricing plans"
    r")\b"
)
INCIDENT_CARD_SIGNAL_RE = re.compile(
    r"(?i)\b("
    r"breach|"
    r"claim|claimed|"
    r"compromise|compromised|"
    r"disclosure|disclosed|"
    r"extortion|"
    r"leak|leaked|"
    r"negotiation|"
    r"posted|published|"
    r"ransom|"
    r"victim"
    r")\b"
)
COUNTRY_VALUE_SPLIT_RE = re.compile(r"\s*(?:/|\||;)\s*")
COUNTRY_NORMALIZATION_RULES = (
    ("United States", "US", ("united states", "united states of america", "us", "usa", "u.s.", "u.s.a.", "america")),
    ("United Kingdom", "GB", ("united kingdom", "uk", "u.k.", "great britain", "britain", "england")),
    ("Canada", "CA", ("canada", "ca")),
    ("Mexico", "MX", ("mexico", "mx")),
    ("Brazil", "BR", ("brazil", "br", "brasil")),
    ("Argentina", "AR", ("argentina", "ar")),
    ("Iceland", "IS", ("iceland", "is", "island")),
    ("Ireland", "IE", ("ireland", "ie")),
    ("Portugal", "PT", ("portugal", "pt")),
    ("Spain", "ES", ("spain", "es", "espana", "españa")),
    ("France", "FR", ("france", "fr")),
    ("Belgium", "BE", ("belgium", "be")),
    ("Netherlands", "NL", ("netherlands", "nl", "holland")),
    ("Switzerland", "CH", ("switzerland", "ch")),
    ("Germany", "DE", ("germany", "de", "deutschland")),
    ("Denmark", "DK", ("denmark", "dk", "danmark")),
    ("Norway", "NO", ("norway", "no", "norge")),
    ("Sweden", "SE", ("sweden", "se", "sverige")),
    ("Finland", "FI", ("finland", "fi", "suomi")),
    ("Estonia", "EE", ("estonia", "ee")),
    ("Latvia", "LV", ("latvia", "lv")),
    ("Lithuania", "LT", ("lithuania", "lt")),
    ("Poland", "PL", ("poland", "pl")),
    ("Czechia", "CZ", ("czechia", "cz", "czech republic")),
    ("Austria", "AT", ("austria", "at")),
    ("Italy", "IT", ("italy", "it")),
    ("Romania", "RO", ("romania", "ro")),
    ("Ukraine", "UA", ("ukraine", "ua")),
    ("Greece", "GR", ("greece", "gr")),
    ("Turkey", "TR", ("turkey", "tr", "turkiye", "türkiye")),
    ("Israel", "IL", ("israel", "il")),
    ("Saudi Arabia", "SA", ("saudi arabia", "sa")),
    ("United Arab Emirates", "AE", ("united arab emirates", "uae", "u.a.e.", "ae")),
    ("South Africa", "ZA", ("south africa", "za")),
    ("India", "IN", ("india", "in")),
    ("China", "CN", ("china", "cn")),
    ("South Korea", "KR", ("south korea", "korea, republic of", "republic of korea", "kr")),
    ("Japan", "JP", ("japan", "jp")),
    ("Australia", "AU", ("australia", "au")),
    ("New Zealand", "NZ", ("new zealand", "nz")),
)
COUNTRY_PLACEHOLDER_VALUES = {
    "",
    "-",
    "--",
    "n/a",
    "na",
    "none",
    "unknown",
    "global",
    "worldwide",
    "multiple",
    "various",
    "international",
}
COUNTRY_ALIAS_TO_DISPLAY = {
    alias: display
    for display, _code, aliases in COUNTRY_NORMALIZATION_RULES
    for alias in aliases
}
COUNTRY_DISPLAY_TO_CODE = {
    display: code for display, code, _aliases in COUNTRY_NORMALIZATION_RULES
}


@dataclass(frozen=True, slots=True)
class ExtractedRecord:
    title: str
    text: str
    excerpt: str
    url: str
    raw: str
    record_type: str = ""
    group_name: str = ""
    victim_name: str = ""
    country: str = ""
    industry: str = ""
    website_url: str = ""
    victim_count: int | None = None
    last_activity_text: str = ""


@dataclass(frozen=True, slots=True)
class WatchMatchResult:
    keywords: list[str]
    regex: list[str]
    fields: list[str]


def _strip_markup_noise(markup: str) -> str:
    cleaned = COMMENT_RE.sub(" ", markup or "")
    cleaned = NOISE_BLOCK_RE.sub(" ", cleaned)
    cleaned = NAV_BLOCK_RE.sub(" ", cleaned)
    return cleaned


def _extract_primary_fragment(markup: str) -> str:
    cleaned = _strip_markup_noise(markup)
    candidates = []
    for match in MAIN_RE.finditer(cleaned):
        candidates.append(match.group(2))
    for match in CONTENT_CONTAINER_RE.finditer(cleaned):
        candidates.append(match.group(2))

    if candidates:
        best_fragment = ""
        best_score = -1
        for fragment in candidates:
            text = normalize_text(html.unescape(TAG_RE.sub(" ", fragment)))
            score = len(text) - (len(CSS_JUNK_RE.findall(text)) * 80)
            if score > best_score:
                best_score = score
                best_fragment = fragment
        if best_fragment:
            return best_fragment

    body_match = BODY_RE.search(cleaned)
    if body_match:
        return body_match.group(1)
    return cleaned


def _drop_boilerplate_sentences(text: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", normalize_text(text))
    filtered = []
    for sentence in sentences:
        cleaned = sentence.strip()
        if not cleaned:
            continue
        if BOILERPLATE_SENTENCE_RE.search(cleaned):
            continue
        if CSS_JUNK_RE.search(cleaned) and len(cleaned) < 260:
            continue
        filtered.append(cleaned)

    combined = normalize_text(" ".join(filtered))
    if len(combined) >= 80:
        return combined
    return normalize_text(text)


def extract_main_text(markup: str) -> str:
    fragment = _extract_primary_fragment(markup or "")
    text = TAG_RE.sub(" ", fragment)
    text = normalize_text(html.unescape(text))
    return _drop_boilerplate_sentences(text)


def parse_watch_keywords(raw: str) -> list[str]:
    return [part.strip().lower() for part in (raw or "").split(",") if part.strip()]


def parse_watch_regex(raw: str) -> list[str]:
    patterns = []
    for line in (raw or "").splitlines():
        cleaned = line.strip()
        if cleaned:
            patterns.append(cleaned)
    return patterns


def extract_title(markup: str) -> str:
    match = TITLE_RE.search(markup or "")
    if not match:
        return "Untitled"
    return normalize_text(match.group(1)) or "Untitled"


def strip_tags(markup: str) -> str:
    return extract_main_text(markup or "")


def normalize_text(value: str) -> str:
    return WHITESPACE_RE.sub(" ", (value or "").strip())


def build_excerpt(text: str, limit: int = 280) -> str:
    cleaned = normalize_text(CSS_JUNK_RE.sub(" ", text or ""))
    if len(cleaned) <= limit:
        return cleaned
    cutoff = cleaned.rfind(" ", 0, limit - 3)
    if cutoff < int(limit * 0.55):
        cutoff = limit - 3
    return cleaned[:cutoff].rstrip() + "..."


def matched_keywords(text: str, raw_keywords: str) -> list[str]:
    lowered = (text or "").lower()
    matches = []
    for keyword in parse_watch_keywords(raw_keywords):
        if keyword in lowered and keyword not in matches:
            matches.append(keyword)
    return matches


def matched_regex(text: str, raw_regex: str) -> list[str]:
    matches = []
    for pattern in parse_watch_regex(raw_regex):
        try:
            if re.search(pattern, text or "", flags=re.IGNORECASE):
                matches.append(pattern)
        except re.error:
            continue
    return matches


def _record_match_field_pairs(
    *,
    title: str = "",
    text: str = "",
    excerpt: str = "",
    victim_name: str = "",
    group_name: str = "",
    country: str = "",
    industry: str = "",
    website_url: str = "",
    last_activity_text: str = "",
) -> list[tuple[str, str]]:
    fields = []
    normalized_title = normalize_text(title)
    normalized_victim = normalize_text(victim_name)
    normalized_group = normalize_text(group_name)
    normalized_country = normalize_text(country)
    normalized_industry = normalize_text(industry)
    normalized_website = normalize_text(website_url)
    normalized_last_activity = normalize_text(last_activity_text)
    normalized_details = normalize_text(_strip_title_from_text(text or excerpt, normalized_title))

    if normalized_title:
        fields.append(("title", normalized_title))
    if normalized_victim and normalized_victim.lower() != normalized_title.lower():
        fields.append(("victim_name", normalized_victim))
    if normalized_group:
        fields.append(("group_name", normalized_group))
    if normalized_country:
        fields.append(("country", normalized_country))
    if normalized_industry:
        fields.append(("industry", normalized_industry))
    if normalized_website:
        fields.append(("website_url", normalized_website))
    if normalized_last_activity:
        fields.append(("last_activity_text", normalized_last_activity))
    if normalized_details:
        fields.append(("details", normalized_details))
    return fields


def evaluate_record_watch_matches(
    *,
    raw_keywords: str = "",
    raw_regex: str = "",
    title: str = "",
    text: str = "",
    excerpt: str = "",
    victim_name: str = "",
    group_name: str = "",
    country: str = "",
    industry: str = "",
    website_url: str = "",
    last_activity_text: str = "",
) -> WatchMatchResult:
    keywords = parse_watch_keywords(raw_keywords)
    regex_patterns = parse_watch_regex(raw_regex)
    field_pairs = _record_match_field_pairs(
        title=title,
        text=text,
        excerpt=excerpt,
        victim_name=victim_name,
        group_name=group_name,
        country=country,
        industry=industry,
        website_url=website_url,
        last_activity_text=last_activity_text,
    )

    field_matches = []
    for field_name, value in field_pairs:
        lowered = value.lower()
        keyword_matches = [keyword for keyword in keywords if keyword in lowered]
        regex_matches = []
        for pattern in regex_patterns:
            try:
                if re.search(pattern, value, flags=re.IGNORECASE):
                    regex_matches.append(pattern)
            except re.error:
                continue
        field_matches.append((field_name, keyword_matches, regex_matches))

    matched_keywords_list = [
        keyword
        for keyword in keywords
        if any(keyword in keyword_matches for _field_name, keyword_matches, _regex_matches in field_matches)
    ]
    matched_regex_list = [
        pattern
        for pattern in regex_patterns
        if any(pattern in regex_matches for _field_name, _keyword_matches, regex_matches in field_matches)
    ]
    matched_fields = [
        field_name
        for field_name, keyword_matches, regex_matches in field_matches
        if keyword_matches or regex_matches
    ]
    return WatchMatchResult(
        keywords=matched_keywords_list,
        regex=matched_regex_list,
        fields=matched_fields,
    )


def build_content_hash(*, url: str, title: str, text: str) -> str:
    payload = "\n".join([url or "", title or "", normalize_text(text)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_record_identity_hash(
    *,
    record_type: str = "",
    title: str = "",
    victim_name: str = "",
    group_name: str = "",
    url: str = "",
    fallback_url: str = "",
) -> str:
    stable_name = normalize_text(victim_name or group_name or title).lower()
    stable_url = normalize_text(url)
    fallback = normalize_text(fallback_url)
    if stable_url and fallback and stable_url.lower() == fallback.lower():
        stable_url = ""
    payload = "\n".join(
        part
        for part in (
            normalize_text(record_type).lower() or "page",
            stable_name,
            stable_url.lower(),
        )
        if part
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _fallback_record_title(text: str) -> str:
    cleaned = normalize_text(text)
    if not cleaned:
        return "Untitled"
    sentence = re.split(r"(?<=[.!?])\s+", cleaned, maxsplit=1)[0]
    words = sentence.split()
    if len(words) > 10:
        return " ".join(words[:10]) + "..."
    return sentence or "Untitled"


def _fragment_text(fragment: str) -> str:
    return _drop_boilerplate_sentences(normalize_text(html.unescape(TAG_RE.sub(" ", fragment or ""))))


def _fragment_title(fragment: str, fallback_text: str) -> str:
    title_match = RECORD_TITLE_RE.search(fragment or "")
    if title_match:
        title = normalize_text(html.unescape(TAG_RE.sub(" ", title_match.group(2))))
        if title:
            return title
    for match in ANCHOR_TEXT_RE.finditer(fragment or ""):
        label = normalize_text(html.unescape(TAG_RE.sub(" ", match.group("label"))))
        if len(label) >= 4:
            return label
    return _fallback_record_title(fallback_text)


def _fragment_url(fragment: str, base_url: str) -> str:
    for match in HREF_RE.finditer(fragment or ""):
        href = (match.group("href") or "").strip()
        if not href:
            continue
        context = fragment[max(0, match.start() - 160) : match.start()]
        context_text = normalize_text(html.unescape(TAG_RE.sub(" ", context))).lower()
        if any(label in context_text for label in ("company website", "website", "site")):
            continue
        absolute = urljoin(base_url, href)
        try:
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in {"http", "https"}:
            continue
        return absolute
    return ""


def _clean_structured_text(value: str, *, max_length: int = 255) -> str:
    cleaned = normalize_text(value)
    if not cleaned:
        return ""
    return cleaned[:max_length].strip()


def _country_display_fallback(value: str) -> str:
    cleaned = _clean_structured_text(value, max_length=120)
    if not cleaned:
        return ""
    if cleaned.islower():
        return cleaned.title()
    return cleaned


def normalize_dark_country(value: str) -> tuple[str, str]:
    cleaned = _clean_structured_text(value, max_length=120)
    if not cleaned:
        return "", ""

    candidates = [cleaned]
    for part in COUNTRY_VALUE_SPLIT_RE.split(cleaned):
        part = _clean_structured_text(part, max_length=120)
        if part and part not in candidates:
            candidates.append(part)

    for candidate in candidates:
        lowered = normalize_text(candidate).lower().replace("&", "and").strip(" .:-")
        if lowered in COUNTRY_PLACEHOLDER_VALUES:
            continue
        display = COUNTRY_ALIAS_TO_DISPLAY.get(lowered)
        if display:
            return display, COUNTRY_DISPLAY_TO_CODE.get(display, "")

    lowered_cleaned = normalize_text(cleaned).lower().replace("&", "and").strip(" .:-")
    if lowered_cleaned in COUNTRY_PLACEHOLDER_VALUES:
        return "", ""

    fallback = _country_display_fallback(cleaned)
    return fallback, COUNTRY_DISPLAY_TO_CODE.get(fallback, "")


def resolve_group_name(
    *,
    record_type: str = "",
    group_name: str = "",
    title: str = "",
    victim_name: str = "",
) -> str:
    normalized_group_name = _clean_structured_text(group_name)
    if normalized_group_name:
        return normalized_group_name

    normalized_title = _clean_structured_text(title)
    if record_type == "group" and normalized_title:
        return normalized_title
    if record_type == "table_row" and normalized_title and not normalize_text(victim_name):
        return normalized_title
    return ""


def _absolute_http_url(value: str, *, base_url: str = "") -> str:
    candidate = (value or "").strip()
    if not candidate:
        return ""
    absolute = urljoin(base_url, candidate)
    try:
        parts = urlsplit(absolute)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"}:
        return ""
    return absolute


def _fragment_lines(fragment: str) -> list[str]:
    marked = STRUCTURED_LINE_BREAK_RE.sub("\n", fragment or "")
    marked = COMMENT_RE.sub(" ", marked)
    marked = NOISE_BLOCK_RE.sub(" ", marked)
    lines = []
    for part in marked.splitlines():
        cleaned = _clean_structured_text(html.unescape(TAG_RE.sub(" ", part)))
        if not cleaned:
            continue
        if not lines or lines[-1] != cleaned:
            lines.append(cleaned)
    return lines


def _extract_labeled_line_value(lines: list[str], labels: tuple[str, ...], *, max_length: int = 255) -> str:
    label_pattern = "|".join(re.escape(label) for label in sorted(labels, key=len, reverse=True))
    with_separator = re.compile(
        rf"^(?:{label_pattern})\s*(?::|-|\|)\s*(.+)$",
        re.IGNORECASE,
    )
    without_separator = re.compile(
        rf"^(?:{label_pattern})\s+(.+)$",
        re.IGNORECASE,
    )
    for line in lines:
        match = with_separator.match(line) or without_separator.match(line)
        if not match:
            continue
        value = _clean_structured_text(match.group(1), max_length=max_length)
        if value:
            return value
    return ""


def _extract_anchor_after_label(fragment: str, labels: tuple[str, ...], *, base_url: str) -> str:
    for match in HREF_RE.finditer(fragment or ""):
        context = fragment[max(0, match.start() - 160) : match.start()]
        context_text = normalize_text(html.unescape(TAG_RE.sub(" ", context))).lower()
        if not any(label.lower() in context_text for label in labels):
            continue
        url = _absolute_http_url(match.group("href") or "", base_url=base_url)
        if url:
            return url
    return ""


def _extract_website_url(fragment: str, lines: list[str], *, base_url: str) -> str:
    labeled_anchor = _extract_anchor_after_label(fragment, WEBSITE_LABELS, base_url=base_url)
    if labeled_anchor:
        return labeled_anchor
    labeled_text = _extract_labeled_line_value(lines, WEBSITE_LABELS, max_length=1500)
    if labeled_text:
        url_match = URL_TEXT_RE.search(labeled_text)
        if url_match:
            return _absolute_http_url(url_match.group(0), base_url=base_url)
        return _absolute_http_url(labeled_text, base_url=base_url)
    inline_pattern = re.compile(
        r"(?i)\b(?:company website|official website|website|site)\s*:\s*(https?://[^\s<>\"]+)"
    )
    for line in lines:
        match = inline_pattern.search(line)
        if match:
            return _absolute_http_url(match.group(1), base_url=base_url)
    fragment_text = normalize_text(html.unescape(TAG_RE.sub(" ", fragment or "")))
    match = inline_pattern.search(fragment_text)
    if match:
        return _absolute_http_url(match.group(1), base_url=base_url)
    return ""


def _extract_integer(value: str) -> int | None:
    match = INTEGER_RE.search(value or "")
    if not match:
        return None
    try:
        return int(match.group(0).replace(",", ""))
    except ValueError:
        return None


def _strip_title_from_text(text: str, title: str) -> str:
    cleaned = normalize_text(text)
    normalized_title = normalize_text(title)
    if not cleaned or not normalized_title:
        return cleaned
    pattern = re.compile(
        r"^" + re.escape(normalized_title) + r"(?:[\s:|\-/,.]+)?",
        re.IGNORECASE,
    )
    stripped = pattern.sub("", cleaned, count=1).strip()
    return stripped or cleaned


def _looks_fragment_only(text: str) -> bool:
    cleaned = normalize_text(text)
    if not cleaned:
        return True
    words = cleaned.split()
    if len(words) <= 2:
        return True
    if len(cleaned) < 24 and len(words) <= 4:
        return True
    if STRUCTURED_CONTENT_HINT_RE.search(cleaned):
        return False
    if len(words) <= 6 and not any(mark in cleaned for mark in ".!?"):
        return True
    return False


def _structured_metadata_for_profile(
    *,
    fragment: str,
    lines: list[str],
    title: str,
    profile: str,
    base_url: str,
) -> dict:
    country_name, _country_code = normalize_dark_country(
        _extract_labeled_line_value(lines, COUNTRY_LABELS, max_length=120)
    )
    metadata = {
        "record_type": "",
        "group_name": "",
        "victim_name": "",
        "country": country_name,
        "industry": _extract_labeled_line_value(lines, INDUSTRY_LABELS, max_length=120),
        "website_url": _extract_website_url(fragment, lines, base_url=base_url),
        "victim_count": None,
        "last_activity_text": _extract_labeled_line_value(
            lines, LAST_ACTIVITY_LABELS, max_length=255
        ),
    }

    if profile == "incident_cards":
        metadata["record_type"] = "incident"
        metadata["victim_name"] = _clean_structured_text(title)
        metadata["group_name"] = resolve_group_name(
            record_type="incident",
            group_name=_extract_labeled_line_value(lines, GROUP_NAME_LABELS, max_length=255),
        )
        return metadata

    if profile == "group_cards":
        metadata["record_type"] = "group"
        metadata["group_name"] = resolve_group_name(
            record_type="group",
            group_name=_extract_labeled_line_value(lines, GROUP_NAME_LABELS, max_length=255),
            title=title,
        )
        metadata["victim_count"] = _extract_integer(
            _extract_labeled_line_value(lines, VICTIM_COUNT_LABELS)
        )
        return metadata

    return metadata


def _heading_title(fragment: str) -> str:
    title_match = RECORD_TITLE_RE.search(fragment or "")
    if not title_match:
        return ""
    return normalize_text(html.unescape(TAG_RE.sub(" ", title_match.group(2))))


def _count_labeled_lines(lines: list[str], labels: tuple[str, ...]) -> int:
    label_pattern = "|".join(re.escape(label) for label in sorted(labels, key=len, reverse=True))
    pattern = re.compile(
        rf"^(?:{label_pattern})\s*(?::|-|\||\s)\s*.+$",
        re.IGNORECASE,
    )
    return sum(1 for line in lines if pattern.match(line))


def _incident_card_title(fragment: str, lines: list[str]) -> str:
    heading_title = _heading_title(fragment)
    if heading_title:
        return heading_title
    victim_title = _extract_labeled_line_value(lines, VICTIM_NAME_LABELS, max_length=255)
    if victim_title:
        return victim_title
    return ""


def _looks_generic_incident_card(title: str, detail_text: str) -> bool:
    normalized_title = normalize_text(title)
    normalized_detail = normalize_text(detail_text)
    if not normalized_title:
        return True
    if GENERIC_INCIDENT_TITLE_RE.search(normalized_title):
        return True
    if (
        INCIDENT_NAV_TEXT_RE.findall(normalized_detail)
        and not STRUCTURED_CONTENT_HINT_RE.search(normalized_detail)
    ):
        return True
    return False


def _has_repeated_incident_metadata(lines: list[str]) -> bool:
    label_groups = (
        GROUP_NAME_LABELS,
        COUNTRY_LABELS,
        INDUSTRY_LABELS,
        WEBSITE_LABELS,
        VICTIM_NAME_LABELS,
    )
    return any(_count_labeled_lines(lines, labels) > 1 for labels in label_groups)


def _looks_valid_incident_card(metadata: dict, detail_text: str) -> bool:
    has_structured_fields = any(
        metadata.get(field)
        for field in ("group_name", "country", "industry", "website_url")
    )
    if has_structured_fields:
        return True
    normalized_detail = normalize_text(detail_text)
    return bool(
        INCIDENT_CARD_SIGNAL_RE.search(normalized_detail)
        and len(normalized_detail) >= 48
    )


def _looks_group_metadata_title(title: str) -> bool:
    normalized = normalize_text(title)
    if not normalized:
        return True
    lowered = normalized.lower()
    simplified = lowered.strip(".:|- ")
    if simplified in {"loading", "recent activity timeline", "recent activity", "activity timeline"}:
        return True
    metadata_labels = (
        "last activity",
        "victim count",
        "victims",
        "country",
        "industry",
        "website",
        "company website",
    )
    if simplified in metadata_labels:
        return True
    return any(lowered.startswith(f"{label}:") for label in metadata_labels)


def _build_record(fragment: str, *, base_url: str, profile: str = "") -> ExtractedRecord | None:
    text = _fragment_text(fragment)
    if len(text) < 24 or len(text) > MAX_STRUCTURED_RECORD_TEXT:
        return None
    lines = _fragment_lines(fragment)
    if profile == "incident_cards":
        title = _incident_card_title(fragment, lines)
    else:
        title = _fragment_title(fragment, text)
    if not title:
        return None
    detail_text = _strip_title_from_text(text, title)
    if _looks_fragment_only(detail_text):
        return None
    metadata = _structured_metadata_for_profile(
        fragment=fragment,
        lines=lines,
        title=title,
        profile=profile,
        base_url=base_url,
    )
    if profile == "incident_cards":
        if _looks_generic_incident_card(title, detail_text):
            return None
        if _has_repeated_incident_metadata(lines):
            return None
        if not _looks_valid_incident_card(metadata, detail_text):
            return None
    if profile == "group_cards" and _looks_group_metadata_title(title):
        return None
    match_text = normalize_text("\n".join(part for part in (title, detail_text) if part))
    return ExtractedRecord(
        title=title,
        text=match_text,
        excerpt=build_excerpt(detail_text, limit=240),
        url=_fragment_url(fragment, base_url),
        raw=(fragment or "")[:4000],
        record_type=metadata["record_type"],
        group_name=metadata["group_name"],
        victim_name=metadata["victim_name"],
        country=metadata["country"],
        industry=metadata["industry"],
        website_url=metadata["website_url"],
        victim_count=metadata["victim_count"],
        last_activity_text=metadata["last_activity_text"],
    )


def _extract_balanced_block(markup: str, start_match) -> str:
    tag = start_match.group("tag")
    open_re = re.compile(rf"<{tag}\b[^>]*>", re.IGNORECASE)
    close_re = re.compile(rf"</{tag}>", re.IGNORECASE)
    position = start_match.end()
    depth = 1
    while depth > 0:
        next_open = open_re.search(markup, position)
        next_close = close_re.search(markup, position)
        if not next_close:
            return markup[start_match.start() :]
        if next_open and next_open.start() < next_close.start():
            depth += 1
            position = next_open.end()
            continue
        depth -= 1
        position = next_close.end()
    return markup[start_match.start() : position]


def _dedupe_records(records: list[ExtractedRecord]) -> list[ExtractedRecord]:
    indexed_records = []
    seen = set()
    for index, record in enumerate(records):
        key = (record.title.lower(), normalize_text(record.text).lower(), record.url or "")
        if key in seen:
            continue
        seen.add(key)
        indexed_records.append((index, record))

    kept = []
    for index, record in sorted(
        indexed_records,
        key=lambda pair: len(normalize_text(pair[1].text)),
        reverse=True,
    ):
        candidate_text = normalize_text(record.text).lower()
        candidate_title = normalize_text(record.title).lower()
        shadowed = False
        for _, existing in kept:
            existing_text = normalize_text(existing.text).lower()
            existing_title = normalize_text(existing.title).lower()
            if candidate_text == existing_text:
                shadowed = True
                break
            if (
                len(candidate_text) < len(existing_text)
                and candidate_text
                and candidate_text in existing_text
                and (
                    candidate_title == existing_title
                    or not record.url
                    or record.url == existing.url
                )
            ):
                shadowed = True
                break
        if shadowed:
            continue
        kept.append((index, record))

    return [record for _, record in sorted(kept, key=lambda pair: pair[0])]


def _extract_card_records(
    markup: str,
    *,
    base_url: str,
    hints: tuple[str, ...],
    profile: str,
) -> list[ExtractedRecord]:
    cleaned = _strip_markup_noise(markup or "")
    hint_pattern = re.compile(
        r"(?:"
        + "|".join(re.escape(hint) for hint in hints)
        + r")",
        re.IGNORECASE,
    )
    records = []
    for match in OPEN_BLOCK_RE.finditer(cleaned):
        attrs = match.group("attrs") or ""
        if not hint_pattern.search(attrs):
            continue
        fragment = _extract_balanced_block(cleaned, match)
        record = _build_record(fragment, base_url=base_url, profile=profile)
        if record is None:
            continue
        records.append(record)
    return _dedupe_records(records)


def _extract_incident_records(markup: str, *, base_url: str) -> list[ExtractedRecord]:
    cleaned = _strip_markup_noise(markup or "")
    heading_matches = list(INCIDENT_HEADING_RE.finditer(cleaned))
    if not heading_matches:
        return []

    records = []
    for index, match in enumerate(heading_matches):
        fragment_start = match.start()
        fragment_end = (
            heading_matches[index + 1].start()
            if index + 1 < len(heading_matches)
            else len(cleaned)
        )
        fragment = cleaned[fragment_start:fragment_end]
        cutoff_match = INCIDENT_FRAGMENT_CUTOFF_RE.search(fragment)
        if cutoff_match:
            fragment = fragment[:cutoff_match.start()]
        record = _build_record(fragment, base_url=base_url, profile="incident_cards")
        if record is None:
            continue
        records.append(record)
    return _dedupe_records(records)


def _extract_table_records(markup: str, *, base_url: str) -> list[ExtractedRecord]:
    cleaned = _strip_markup_noise(markup or "")
    records = []
    for table_match in TABLE_RE.finditer(cleaned):
        table_markup = table_match.group(0)
        headers = []
        table_rows = []
        for row_match in ROW_RE.finditer(table_markup):
            row_markup = row_match.group(0)
            if "<th" in row_markup.lower() and "<td" not in row_markup.lower():
                headers = [
                    _clean_structured_text(
                        html.unescape(TAG_RE.sub(" ", cell_match.group(2)))
                    ).lower()
                    for cell_match in CELL_RE.finditer(row_markup)
                ]
                continue
            if "<td" not in row_markup.lower():
                continue
            cells = [
                _clean_structured_text(
                    html.unescape(TAG_RE.sub(" ", cell_match.group(2))),
                    max_length=255,
                )
                for cell_match in CELL_RE.finditer(row_markup)
            ]
            cells = [cell for cell in cells if cell]
            if len(cells) < 2:
                continue
            metadata = {
                "record_type": "table_row",
                "group_name": "",
                "victim_name": "",
                "country": "",
                "industry": "",
                "website_url": "",
                "victim_count": None,
                "last_activity_text": "",
            }
            for index, cell in enumerate(cells):
                header = headers[index] if index < len(headers) else ""
                if any(token in header for token in ("group", "actor", "gang")) or header == "name":
                    metadata["group_name"] = _clean_structured_text(cell)
                    metadata["record_type"] = "group"
                elif any(token in header for token in ("victim count", "victims")):
                    metadata["victim_count"] = _extract_integer(cell)
                elif any(token in header for token in ("victim", "company", "organization")):
                    metadata["victim_name"] = _clean_structured_text(cell)
                elif any(token in header for token in ("country", "location")):
                    metadata["country"] = normalize_dark_country(cell)[0]
                elif any(token in header for token in ("industry", "sector")):
                    metadata["industry"] = _clean_structured_text(cell, max_length=120)
                elif "website" in header or "domain" in header:
                    metadata["website_url"] = _absolute_http_url(cell, base_url=base_url)
                elif any(token in header for token in ("activity", "updated", "last")):
                    metadata["last_activity_text"] = _clean_structured_text(cell)

            metadata["group_name"] = resolve_group_name(
                record_type=metadata["record_type"],
                group_name=metadata["group_name"],
                title=cells[0],
                victim_name=metadata["victim_name"],
            )
            title = metadata["group_name"] or metadata["victim_name"] or cells[0]
            detail_parts = []
            for cell in cells[1:]:
                if cell != title:
                    detail_parts.append(cell)
            detail_text = " | ".join(detail_parts)
            row_text = normalize_text("\n".join(part for part in (title, detail_text) if part))
            if len(row_text) < 16 or _looks_fragment_only(detail_text):
                continue
            row_url = _fragment_url(row_markup, base_url)
            table_rows.append(
                ExtractedRecord(
                    title=title,
                    text=row_text,
                    excerpt=build_excerpt(detail_text, limit=240),
                    url=row_url,
                    raw=row_markup[:4000],
                    record_type=metadata["record_type"],
                    group_name=metadata["group_name"],
                    victim_name=metadata["victim_name"],
                    country=metadata["country"],
                    industry=metadata["industry"],
                    website_url=metadata["website_url"],
                    victim_count=metadata["victim_count"],
                    last_activity_text=metadata["last_activity_text"],
                )
            )
        if len(table_rows) >= 2:
            records.extend(table_rows)
    return _dedupe_records(records)


def extract_profile_records(markup: str, *, profile: str, base_url: str = "") -> list[ExtractedRecord]:
    if profile == "incident_cards":
        return _extract_incident_records(markup, base_url=base_url)
    if profile == "group_cards":
        return _extract_card_records(
            markup,
            base_url=base_url,
            hints=GROUP_BLOCK_HINTS,
            profile=profile,
        )
    if profile == "table_rows":
        return _extract_table_records(markup, base_url=base_url)

    text = strip_tags(markup)
    if not text:
        return []
    title = extract_title(markup)
    return [
        ExtractedRecord(
            title=title,
            text=text,
            excerpt=build_excerpt(text, limit=240),
            url=base_url or "",
            raw=(markup or "")[:4000],
            record_type="page",
        )
    ]


def summarize_profile_content(markup: str, *, profile: str, base_url: str = "") -> dict:
    records = extract_profile_records(markup, profile=profile, base_url=base_url)
    generic_text = strip_tags(markup)
    records_text = "\n\n".join(
        normalize_text("\n".join(part for part in (record.title, record.text) if part))
        for record in records
        if record.text
    )
    text = records_text or generic_text
    page_title = extract_title(markup)
    title = page_title
    if title == "Untitled" and records:
        title = records[0].title
    excerpt = build_excerpt(text, limit=280)
    return {
        "title": title,
        "text": text,
        "excerpt": excerpt,
        "records": records,
    }


def extract_links(markup: str, *, base_url: str, max_links: int = 50) -> list[str]:
    links: list[str] = []
    seen = set()
    base_parts = urlsplit(base_url)
    base_host = (base_parts.hostname or "").lower()
    for match in HREF_RE.finditer(markup or ""):
        href = (match.group("href") or "").strip()
        if not href:
            continue
        absolute = urljoin(base_url, href)
        try:
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in {"http", "https"}:
            continue
        host = (parts.hostname or "").lower()
        if not host:
            continue
        # For passive index crawling: only same host + subpaths.
        if host != base_host:
            continue
        normalized = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
        if parts.query:
            normalized = f"{normalized}?{parts.query}"
        if normalized in seen:
            continue
        seen.add(normalized)
        links.append(normalized)
        if len(links) >= max_links:
            break
    return links


def contains_cve(text: str) -> bool:
    return bool(CVE_RE.search(text or ""))


def dark_source_suitability_warning(url: str, source_type: str) -> str:
    try:
        parsed = urlsplit((url or "").strip())
    except ValueError:
        return ""

    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    if not host:
        return ""

    if source_type != "feed" and (
        path.endswith((".rss", ".atom", ".xml")) or "feed" in path
    ):
        return "URL looks like a structured feed endpoint. Prefer source_type=feed."

    if host.endswith(".onion"):
        return ""

    looks_news_like = any(token in host for token in NEWSLIKE_HOST_HINTS) or any(
        token in path for token in ("/news", "/research", "/blog", "/advis", "/article", "/posts")
    )
    if source_type in {"single_page", "index_page"} and looks_news_like:
        return (
            "This looks like a normal news/research/advisory site. Prefer standard intel feeds "
            "unless dark passive monitoring is explicitly required."
        )
    return ""
