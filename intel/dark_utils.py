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
OPEN_BLOCK_RE = re.compile(r"<(?P<tag>article|section|div|li)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
TABLE_RE = re.compile(r"<table[^>]*>.*?</table>", re.IGNORECASE | re.DOTALL)
ROW_RE = re.compile(r"<tr[^>]*>.*?</tr>", re.IGNORECASE | re.DOTALL)
CELL_RE = re.compile(r"<(td|th)[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"\s+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
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
INCIDENT_BLOCK_HINTS = (
    "card",
    "item",
    "entry",
    "listing",
    "victim",
    "case",
    "post",
    "incident",
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


@dataclass(frozen=True, slots=True)
class ExtractedRecord:
    title: str
    text: str
    excerpt: str
    url: str
    raw: str


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


def build_content_hash(*, url: str, title: str, text: str) -> str:
    payload = "\n".join([url or "", title or "", normalize_text(text)])
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
        absolute = urljoin(base_url, href)
        try:
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in {"http", "https"}:
            continue
        return absolute
    return base_url or ""


def _build_record(fragment: str, *, base_url: str) -> ExtractedRecord | None:
    text = _fragment_text(fragment)
    if len(text) < 24 or len(text) > MAX_STRUCTURED_RECORD_TEXT:
        return None
    title = _fragment_title(fragment, text)
    return ExtractedRecord(
        title=title,
        text=text,
        excerpt=build_excerpt(text, limit=240),
        url=_fragment_url(fragment, base_url),
        raw=(fragment or "")[:4000],
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
    deduped = []
    seen = set()
    for record in records:
        key = (record.title.lower(), normalize_text(record.text).lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def _extract_card_records(markup: str, *, base_url: str, hints: tuple[str, ...]) -> list[ExtractedRecord]:
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
        record = _build_record(fragment, base_url=base_url)
        if record is None:
            continue
        records.append(record)
    records = _dedupe_records(records)
    if len(records) >= 2:
        return records

    fallback_records = []
    repeated_tag_re = re.compile(r"<(?P<tag>article|li)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
    for match in repeated_tag_re.finditer(cleaned):
        fragment = _extract_balanced_block(cleaned, match)
        record = _build_record(fragment, base_url=base_url)
        if record is None:
            continue
        fallback_records.append(record)
    fallback_records = _dedupe_records(fallback_records)
    return fallback_records if len(fallback_records) >= 2 else records


def _extract_table_records(markup: str, *, base_url: str) -> list[ExtractedRecord]:
    cleaned = _strip_markup_noise(markup or "")
    records = []
    for table_match in TABLE_RE.finditer(cleaned):
        table_markup = table_match.group(0)
        table_rows = []
        for row_match in ROW_RE.finditer(table_markup):
            row_markup = row_match.group(0)
            if "<td" not in row_markup.lower():
                continue
            cells = [
                normalize_text(html.unescape(TAG_RE.sub(" ", cell_match.group(2))))
                for cell_match in CELL_RE.finditer(row_markup)
            ]
            cells = [cell for cell in cells if cell]
            if len(cells) < 2:
                continue
            row_text = " | ".join(cells)
            if len(row_text) < 16:
                continue
            table_rows.append(
                ExtractedRecord(
                    title=cells[0],
                    text=row_text,
                    excerpt=build_excerpt(row_text, limit=240),
                    url=_fragment_url(row_markup, base_url),
                    raw=row_markup[:4000],
                )
            )
        if len(table_rows) >= 2:
            records.extend(table_rows)
    return _dedupe_records(records)


def extract_profile_records(markup: str, *, profile: str, base_url: str = "") -> list[ExtractedRecord]:
    if profile == "incident_cards":
        return _extract_card_records(markup, base_url=base_url, hints=INCIDENT_BLOCK_HINTS)
    if profile == "group_cards":
        return _extract_card_records(markup, base_url=base_url, hints=GROUP_BLOCK_HINTS)
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
