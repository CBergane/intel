import time
from urllib.parse import urlsplit

import feedparser
import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from intel.dark_utils import (
    build_content_hash,
    build_excerpt,
    extract_links,
    extract_title,
    matched_keywords,
    matched_regex,
    strip_tags,
)
from intel.models import DarkDocument, DarkFetchRun, DarkHit, DarkSnapshot, DarkSource
from intel.utils import canonicalize_url, sanitize_summary


class Command(BaseCommand):
    help = (
        "Passive allowlist-only dark intel ingestion. "
        "GET requests only; no auth, no forms, no interactions."
    )

    def handle(self, *args, **options):
        sources = DarkSource.objects.filter(enabled=True).order_by("name")
        if not sources.exists():
            self.stdout.write(self.style.WARNING("No enabled dark sources matched."))
            return

        for source in sources:
            self._run_source(source)

    def _run_source(self, source: DarkSource):
        started_at = timezone.now()
        run = DarkFetchRun.objects.create(dark_source=source, started_at=started_at)
        started = time.monotonic()
        bytes_received_total = 0
        docs_discovered = 0
        docs_fetched = 0
        hits_new = 0
        hits_updated = 0
        errors = []

        try:
            candidate_urls, root_status, root_final_url, root_bytes = self._discover_documents(source)
            bytes_received_total += root_bytes
            docs_discovered = len(candidate_urls)
            run.http_status = root_status
            run.final_url = root_final_url

            for doc_url in candidate_urls:
                try:
                    markup, status, final_url, doc_bytes = self._fetch_with_retries(doc_url, source)
                    bytes_received_total += doc_bytes
                    docs_fetched += 1
                    hit_created, hit_updated = self._upsert_document_and_hits(
                        source=source,
                        doc_url=doc_url,
                        final_url=final_url,
                        status=status,
                        markup=markup,
                    )
                    if hit_created:
                        hits_new += 1
                    if hit_updated:
                        hits_updated += 1
                except Exception as exc:
                    errors.append(f"{doc_url}: {exc}")

            run.ok = len(errors) == 0
            if errors:
                run.error = "; ".join(errors)[:4000]
            run.bytes_received = bytes_received_total
            run.documents_discovered = docs_discovered
            run.documents_fetched = docs_fetched
            run.hits_new = hits_new
            run.hits_updated = hits_updated
            run.finished_at = timezone.now()
            run.duration_ms = int((time.monotonic() - started) * 1000)
            run.save()

            style = self.style.SUCCESS if run.ok else self.style.WARNING
            self.stdout.write(
                style(
                    f"[{source.id}] {source.name}: "
                    f"docs={docs_fetched}/{docs_discovered} "
                    f"hits_new={hits_new} hits_updated={hits_updated} "
                    f"bytes={bytes_received_total}"
                )
            )
        except Exception as exc:
            run.ok = False
            run.error = str(exc)[:4000]
            run.finished_at = timezone.now()
            run.duration_ms = int((time.monotonic() - started) * 1000)
            run.bytes_received = bytes_received_total
            run.documents_discovered = docs_discovered
            run.documents_fetched = docs_fetched
            run.hits_new = hits_new
            run.hits_updated = hits_updated
            run.save()
            self.stderr.write(self.style.ERROR(f"[{source.id}] {source.name}: {exc}"))

    def _discover_documents(self, source: DarkSource):
        source_type = source.source_type
        if source_type == DarkSource.SourceType.SINGLE_PAGE:
            return [source.url], None, source.url, 0

        markup, status, final_url, bytes_received = self._fetch_with_retries(source.url, source)
        if source_type == DarkSource.SourceType.INDEX_PAGE:
            links = extract_links(
                markup,
                base_url=final_url or source.url,
                max_links=settings.DARK_INDEX_MAX_LINKS,
            )
            # Include the index itself for change tracking.
            docs = [source.url]
            docs.extend([link for link in links if link != source.url])
            return docs, status, final_url, bytes_received

        if source_type == DarkSource.SourceType.FEED:
            parsed = feedparser.parse(markup)
            if getattr(parsed, "bozo", False) and getattr(parsed, "entries", None) is None:
                raise ValueError(f"Invalid dark feed payload: {parsed.bozo_exception}")
            docs = []
            source_host = (urlsplit(source.url).hostname or "").lower()
            for entry in parsed.entries:
                link = (
                    entry.get("link")
                    or entry.get("id")
                    or ""
                ).strip()
                if not link:
                    continue
                try:
                    host = (urlsplit(link).hostname or "").lower()
                except ValueError:
                    continue
                if source_host and host and host != source_host:
                    continue
                docs.append(link)
                if len(docs) >= settings.DARK_INDEX_MAX_LINKS:
                    break
            return docs, status, final_url, bytes_received

        raise ValueError(f"Unsupported dark source type: {source_type}")

    def _upsert_document_and_hits(self, *, source, doc_url, final_url, status, markup):
        title = extract_title(markup)
        text = strip_tags(markup)
        excerpt = sanitize_summary(build_excerpt(text))
        content_hash = build_content_hash(url=final_url or doc_url, title=title, text=text)
        canonical_url = canonicalize_url(final_url or doc_url)

        now = timezone.now()
        with transaction.atomic():
            document, created = DarkDocument.objects.select_for_update().get_or_create(
                dark_source=source,
                canonical_url=canonical_url,
                defaults={
                    "url": doc_url,
                    "title": title,
                    "excerpt": excerpt,
                    "content_hash": content_hash,
                    "first_seen": now,
                    "last_seen": now,
                    "last_fetched_at": now,
                    "last_http_status": status,
                    "last_error": "",
                    "active": True,
                },
            )
            if not created:
                previous_hash = document.content_hash
                document.url = doc_url
                document.title = title
                document.excerpt = excerpt
                document.content_hash = content_hash
                document.last_seen = now
                document.last_fetched_at = now
                document.last_http_status = status
                document.last_error = ""
                document.active = True
                document.save()
                if previous_hash != content_hash:
                    DarkSnapshot.objects.create(
                        dark_document=document,
                        content_hash=content_hash,
                        title=title,
                        excerpt=excerpt,
                        raw=markup[:4000],
                    )
            else:
                DarkSnapshot.objects.create(
                    dark_document=document,
                    content_hash=content_hash,
                    title=title,
                    excerpt=excerpt,
                    raw=markup[:4000],
                )

            match_text = f"{title}\n{text}"
            keyword_matches = matched_keywords(match_text, source.watch_keywords)
            regex_matches = matched_regex(match_text, source.watch_regex)
            if not keyword_matches and not regex_matches:
                return False, False

            hit, hit_created = DarkHit.objects.select_for_update().get_or_create(
                dark_source=source,
                dark_document=document,
                content_hash=content_hash,
                defaults={
                    "matched_keywords": keyword_matches,
                    "matched_regex": regex_matches,
                    "title": title,
                    "excerpt": excerpt,
                    "url": final_url or doc_url,
                    "raw": markup[:4000],
                    "last_seen_at": now,
                },
            )
            if hit_created:
                return True, False

            hit.matched_keywords = keyword_matches
            hit.matched_regex = regex_matches
            hit.title = title
            hit.excerpt = excerpt
            hit.url = final_url or doc_url
            hit.raw = markup[:4000]
            hit.last_seen_at = now
            hit.save()
            return False, True

    def _fetch_with_retries(self, url: str, source: DarkSource):
        retries = max(settings.DARK_FETCH_RETRIES, 1)
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                return self._fetch_once(url, source)
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(2 ** (attempt - 1))
        raise RuntimeError(f"Failed to fetch after {retries} attempt(s): {last_error}")

    def _fetch_once(self, url: str, source: DarkSource):
        kwargs = self._request_kwargs(url, source)
        response = requests.get(url, **kwargs)
        response.raise_for_status()

        size = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size > settings.DARK_MAX_BYTES:
                raise ValueError(
                    f"Dark source response exceeded max_bytes={settings.DARK_MAX_BYTES}"
                )
            chunks.append(chunk)
        markup = b"".join(chunks).decode("utf-8", errors="replace")
        return markup, response.status_code, response.url, size

    def _request_kwargs(self, url: str, source: DarkSource):
        kwargs = {
            "headers": {"User-Agent": settings.INTEL_USER_AGENT},
            "timeout": settings.DARK_FETCH_TIMEOUT,
            "stream": True,
        }
        if self._should_use_tor(url, source):
            kwargs["proxies"] = {
                "http": settings.DARK_TOR_SOCKS_URL,
                "https": settings.DARK_TOR_SOCKS_URL,
            }
        return kwargs

    def _should_use_tor(self, url: str, source: DarkSource) -> bool:
        if source.use_tor:
            return True
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            return False
        return host.endswith(".onion")
