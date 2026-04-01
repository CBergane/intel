import time
from urllib.parse import urlsplit

import feedparser
import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from intel.dark_utils import (
    build_record_identity_hash,
    build_content_hash,
    evaluate_record_watch_matches,
    extract_links,
    resolve_group_name,
    summarize_profile_content,
)
from intel.models import DarkDocument, DarkFetchRun, DarkHit, DarkSnapshot, DarkSource
from intel.notifications import (
    build_dark_hit_alert_fingerprint,
    build_dark_hit_alert_identity,
    dark_hit_alert_reason,
    send_dark_hit_alert,
    should_emit_dark_hit_alert,
)
from intel.utils import canonicalize_url, sanitize_summary


def _latest_alerted_dark_hit(*, source, hit, alert_identity_hash: str):
    if (
        hit is not None
        and hit.last_alerted_at is not None
        and hit.last_alert_fingerprint
    ):
        return hit
    queryset = DarkHit.objects.filter(
        dark_source=source,
        alert_identity_hash=alert_identity_hash,
        last_alerted_at__isnull=False,
    )
    if hit is not None and hit.pk:
        queryset = queryset.exclude(pk=hit.pk)
    return queryset.order_by("-last_alerted_at", "-id").first()


class Command(BaseCommand):
    help = (
        "Passive allowlist-only dark intel ingestion. "
        "GET requests only; no auth, no forms, no interactions."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--source",
            action="append",
            dest="source_filters",
            default=[],
            help="Dark source slug/name to ingest. May be used multiple times.",
        )

    def handle(self, *args, **options):
        sources = DarkSource.objects.filter(enabled=True).order_by("name")
        source_filters = [value.strip() for value in options.get("source_filters", []) if value.strip()]
        if source_filters:
            source_query = Q()
            for value in source_filters:
                source_query |= Q(slug=value) | Q(name=value)
            sources = sources.filter(source_query)
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
                    created_count, updated_count = self._upsert_document_and_hits(
                        source=source,
                        doc_url=doc_url,
                        final_url=final_url,
                        status=status,
                        markup=markup,
                    )
                    hits_new += created_count
                    hits_updated += updated_count
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
        summary = summarize_profile_content(
            markup,
            profile=source.extractor_profile,
            base_url=final_url or doc_url,
        )
        title = summary["title"]
        text = summary["text"]
        excerpt = sanitize_summary(summary["excerpt"])
        records = summary["records"]
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

            hits_new = 0
            hits_updated = 0
            store_structured_records = source.extractor_profile in {
                DarkSource.ExtractorProfile.INCIDENT_CARDS,
                DarkSource.ExtractorProfile.GROUP_CARDS,
                DarkSource.ExtractorProfile.TABLE_ROWS,
            }
            existing_hits = list(
                DarkHit.objects.select_for_update()
                .filter(dark_source=source, dark_document=document)
                .order_by("id")
            )
            hits_by_hash = {hit.content_hash: hit for hit in existing_hits}
            structured_hits_by_identity = {}
            fallback_hit_url = final_url or doc_url
            for existing_hit in existing_hits:
                if existing_hit.record_type not in {"incident", "group", "table_row"}:
                    continue
                identity_hash = build_record_identity_hash(
                    record_type=existing_hit.record_type,
                    title=existing_hit.title,
                    victim_name=existing_hit.victim_name,
                    group_name=existing_hit.group_name,
                    url=existing_hit.url,
                    fallback_url=fallback_hit_url,
                )
                structured_hits_by_identity.setdefault(identity_hash, existing_hit)

            for record in records:
                normalized_group_name = resolve_group_name(
                    record_type=record.record_type,
                    group_name=record.group_name,
                    title=record.title,
                    victim_name=record.victim_name,
                )
                match_result = evaluate_record_watch_matches(
                    raw_keywords=source.watch_keywords,
                    raw_regex=source.watch_regex,
                    title=record.title,
                    text=record.text,
                    excerpt=record.excerpt,
                    victim_name=record.victim_name,
                    group_name=normalized_group_name,
                    country=record.country,
                    industry=record.industry,
                    website_url=record.website_url,
                    last_activity_text=record.last_activity_text,
                )
                keyword_matches = match_result.keywords
                regex_matches = match_result.regex
                is_watch_match = bool(keyword_matches or regex_matches)
                if not is_watch_match and not store_structured_records:
                    continue
                record_values = {
                    "matched_keywords": keyword_matches,
                    "matched_regex": regex_matches,
                    "is_watch_match": is_watch_match,
                    "record_type": record.record_type,
                    "group_name": normalized_group_name,
                    "victim_name": record.victim_name,
                    "country": record.country,
                    "industry": record.industry,
                    "website_url": record.website_url,
                    "victim_count": record.victim_count,
                    "last_activity_text": record.last_activity_text,
                    "title": record.title,
                    "excerpt": sanitize_summary(record.excerpt),
                    "url": record.url or fallback_hit_url,
                    "raw": record.raw,
                }
                alert_identity_hash = build_dark_hit_alert_identity(
                    source_id=source.id,
                    record_type=record.record_type,
                    title=record.title,
                    victim_name=record.victim_name,
                    group_name=normalized_group_name,
                    url=record_values["url"],
                )
                alert_fingerprint = build_dark_hit_alert_fingerprint(
                    record_type=record.record_type,
                    title=record.title,
                    excerpt=record_values["excerpt"],
                    victim_name=record.victim_name,
                    group_name=normalized_group_name,
                    country=record.country,
                    industry=record.industry,
                    website_url=record.website_url,
                    url=record_values["url"],
                    matched_keywords=keyword_matches,
                    matched_regex=regex_matches,
                )
                if store_structured_records:
                    hit_hash = build_record_identity_hash(
                        record_type=record.record_type,
                        title=record.title,
                        victim_name=record.victim_name,
                        group_name=normalized_group_name,
                        url=record_values["url"],
                        fallback_url=fallback_hit_url,
                    )
                    hit = structured_hits_by_identity.get(hit_hash)
                else:
                    hit_hash = build_content_hash(
                        url=record_values["url"],
                        title=record.title,
                        text=record.text,
                    )
                    hit = hits_by_hash.get(hit_hash)

                if hit is None:
                    previous_alert_hit = _latest_alerted_dark_hit(
                        source=source,
                        hit=None,
                        alert_identity_hash=alert_identity_hash,
                    )
                    hit = DarkHit.objects.create(
                        dark_source=source,
                        dark_document=document,
                        content_hash=hit_hash,
                        alert_identity_hash=alert_identity_hash,
                        last_seen_at=now,
                        **record_values,
                    )
                    hits_by_hash[hit_hash] = hit
                    if store_structured_records:
                        structured_hits_by_identity[hit_hash] = hit
                    if should_emit_dark_hit_alert(
                        is_watch_match=is_watch_match,
                        record_type=record.record_type,
                        current_alert_fingerprint=alert_fingerprint,
                        previous_alert_hit=previous_alert_hit,
                    ):
                        alert_reason = dark_hit_alert_reason(
                            previous_alert_hit,
                            record_values=record_values,
                            keyword_matches=keyword_matches,
                            regex_matches=regex_matches,
                        )
                        send_dark_hit_alert(
                            hit,
                            matched_fields=match_result.fields,
                            why_alerted=alert_reason,
                        )
                        hit.last_alerted_at = now
                        hit.last_alert_fingerprint = alert_fingerprint
                        hit.save(update_fields=["last_alerted_at", "last_alert_fingerprint"])
                    elif (
                        previous_alert_hit is not None
                        and previous_alert_hit.last_alert_fingerprint == alert_fingerprint
                    ):
                        hit.last_alerted_at = previous_alert_hit.last_alerted_at
                        hit.last_alert_fingerprint = previous_alert_hit.last_alert_fingerprint
                        hit.save(update_fields=["last_alerted_at", "last_alert_fingerprint"])
                    hits_new += 1
                    continue

                previous_alert_hit = _latest_alerted_dark_hit(
                    source=source,
                    hit=hit,
                    alert_identity_hash=alert_identity_hash,
                )
                alert_reason = None
                if should_emit_dark_hit_alert(
                    is_watch_match=is_watch_match,
                    record_type=record.record_type,
                    current_alert_fingerprint=alert_fingerprint,
                    previous_alert_hit=previous_alert_hit,
                ):
                    alert_reason = dark_hit_alert_reason(
                        previous_alert_hit,
                        record_values=record_values,
                        keyword_matches=keyword_matches,
                        regex_matches=regex_matches,
                    )

                hit.matched_keywords = keyword_matches
                hit.matched_regex = regex_matches
                hit.is_watch_match = is_watch_match
                hit.alert_identity_hash = alert_identity_hash
                hit.record_type = record_values["record_type"]
                hit.group_name = record_values["group_name"]
                hit.victim_name = record_values["victim_name"]
                hit.country = record_values["country"]
                hit.industry = record_values["industry"]
                hit.website_url = record_values["website_url"]
                hit.victim_count = record_values["victim_count"]
                hit.last_activity_text = record_values["last_activity_text"]
                hit.title = record_values["title"]
                hit.excerpt = record_values["excerpt"]
                hit.url = record_values["url"]
                hit.raw = record_values["raw"]
                hit.content_hash = hit_hash
                hit.last_seen_at = now
                hit.save()
                hits_by_hash[hit_hash] = hit
                if store_structured_records:
                    structured_hits_by_identity[hit_hash] = hit
                if alert_reason:
                    send_dark_hit_alert(
                        hit,
                        matched_fields=match_result.fields,
                        why_alerted=alert_reason,
                    )
                    hit.last_alerted_at = now
                    hit.last_alert_fingerprint = alert_fingerprint
                    hit.save(update_fields=["last_alerted_at", "last_alert_fingerprint"])
                elif (
                    previous_alert_hit is not None
                    and previous_alert_hit.last_alert_fingerprint == alert_fingerprint
                    and (
                        hit.last_alerted_at != previous_alert_hit.last_alerted_at
                        or hit.last_alert_fingerprint != previous_alert_hit.last_alert_fingerprint
                    )
                ):
                    hit.last_alerted_at = previous_alert_hit.last_alerted_at
                    hit.last_alert_fingerprint = previous_alert_hit.last_alert_fingerprint
                    hit.save(update_fields=["last_alerted_at", "last_alert_fingerprint"])
                hits_updated += 1
            return hits_new, hits_updated

    def _fetch_with_retries(self, url: str, source: DarkSource):
        retries = max(source.effective_fetch_retries(), 1)
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

        max_bytes = source.effective_max_bytes()
        size = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(
                    f"Dark source response exceeded max_bytes={max_bytes}"
                )
            chunks.append(chunk)
        markup = b"".join(chunks).decode("utf-8", errors="replace")
        return markup, response.status_code, response.url, size

    def _request_kwargs(self, url: str, source: DarkSource):
        kwargs = {
            "headers": {"User-Agent": settings.INTEL_USER_AGENT},
            "timeout": source.effective_timeout_seconds(),
            "stream": True,
        }
        if self._should_use_tor(url, source) and settings.TOR_ENABLED:
            socks_url = settings.DARK_TOR_SOCKS_URL
            kwargs["proxies"] = {
                "http": socks_url,
                "https": socks_url,
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
