import hashlib
import html
import re
from urllib.parse import urljoin, urlsplit


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
HREF_RE = re.compile(
    r"""<a[^>]+href=["'](?P<href>[^"']+)["'][^>]*>""",
    re.IGNORECASE,
)
WHITESPACE_RE = re.compile(r"\s+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


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
    text = TAG_RE.sub(" ", markup or "")
    return normalize_text(html.unescape(text))


def normalize_text(value: str) -> str:
    return WHITESPACE_RE.sub(" ", (value or "").strip())


def build_excerpt(text: str, limit: int = 280) -> str:
    cleaned = normalize_text(text)
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


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
