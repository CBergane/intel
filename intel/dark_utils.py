import hashlib
import html
import re
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
