import hashlib
import html
import re


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")


def parse_watch_keywords(raw: str) -> list[str]:
    return [part.strip().lower() for part in (raw or "").split(",") if part.strip()]


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


def build_content_hash(*, url: str, title: str, text: str, matched: list[str]) -> str:
    payload = "\n".join([url or "", title or "", normalize_text(text), ",".join(matched)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
