from django import forms
from django.core.exceptions import ValidationError

from .dark_utils import dark_source_suitability_warning
from .models import DarkSource, Feed, Source


_INPUT_CLASS = (
    "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 "
    "placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"
)
_CHECKBOX_CLASS = "h-4 w-4 rounded border-slate-700 bg-slate-950 text-sky-400 focus:ring-sky-400"


class _BaseFeedForm(forms.ModelForm):
    ALLOWED_ADAPTER_KEYS = {"", "cisa_kev", "generic_json"}

    def clean_adapter_key(self):
        normalized = (self.cleaned_data.get("adapter_key") or "").strip().lower()
        if normalized not in self.ALLOWED_ADAPTER_KEYS:
            raise ValidationError("Unsupported adapter key.")
        return normalized

    def clean(self):
        cleaned = super().clean()
        feed_type = cleaned.get("feed_type")
        adapter_key = cleaned.get("adapter_key") or ""
        if feed_type in {Feed.FeedType.RSS, Feed.FeedType.ATOM} and adapter_key:
            self.add_error("adapter_key", "Adapter key should be empty for RSS/Atom feeds.")
        if feed_type == Feed.FeedType.JSON and not adapter_key:
            cleaned["adapter_key"] = "generic_json"
        return cleaned

    def clean_max_age_days(self):
        value = int(self.cleaned_data["max_age_days"])
        if value < 1 or value > 36500:
            raise ValidationError("Max age days must be between 1 and 36500.")
        return value

    def clean_max_items_per_run(self):
        value = int(self.cleaned_data["max_items_per_run"])
        if value < 1 or value > 50000:
            raise ValidationError("Max items per run must be between 1 and 50000.")
        return value

    def clean_timeout_seconds(self):
        value = int(self.cleaned_data["timeout_seconds"])
        if value < 1 or value > 120:
            raise ValidationError("Timeout must be between 1 and 120 seconds.")
        return value

    def clean_max_bytes(self):
        value = int(self.cleaned_data["max_bytes"])
        if value < 1024 or value > 25_000_000:
            raise ValidationError("Max bytes must be between 1024 and 25000000.")
        return value

    def clean_expanded_max_items_per_run(self):
        value = self.cleaned_data.get("expanded_max_items_per_run")
        if value is None:
            return value
        if value < 1 or value > 200000:
            raise ValidationError("Expanded max items must be between 1 and 200000.")
        return value

    def clean_expanded_max_age_days(self):
        value = self.cleaned_data.get("expanded_max_age_days")
        if value is None:
            return value
        if value < 1 or value > 36500:
            raise ValidationError("Expanded max age must be between 1 and 36500.")
        return value

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = _CHECKBOX_CLASS
            else:
                widget.attrs["class"] = _INPUT_CLASS


class FeedCreateForm(_BaseFeedForm):
    class Meta:
        model = Feed
        fields = [
            "source",
            "name",
            "url",
            "feed_type",
            "adapter_key",
            "section",
            "priority",
            "enabled",
            "expanded_collection",
            "expanded_max_age_days",
            "expanded_max_items_per_run",
            "timeout_seconds",
            "max_bytes",
            "max_age_days",
            "max_items_per_run",
        ]


class FeedEditForm(_BaseFeedForm):
    class Meta:
        model = Feed
        fields = [
            "source",
            "name",
            "url",
            "feed_type",
            "adapter_key",
            "section",
            "priority",
            "enabled",
            "expanded_collection",
            "expanded_max_age_days",
            "expanded_max_items_per_run",
            "timeout_seconds",
            "max_bytes",
            "max_age_days",
            "max_items_per_run",
        ]


class _BaseSourceForm(forms.ModelForm):
    tags = forms.CharField(required=False, help_text="Comma-separated tags.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["tags"].initial = ", ".join(self.instance.tags or [])
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = _CHECKBOX_CLASS
            else:
                widget.attrs["class"] = _INPUT_CLASS

    def clean_slug(self):
        slug = self.cleaned_data["slug"]
        queryset = Source.objects.filter(slug=slug)
        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A source with this slug already exists.")
        return slug

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        queryset = Source.objects.filter(name=name)
        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A source with this name already exists.")
        return name

    def clean_tags(self):
        raw = self.cleaned_data.get("tags", "")
        return [tag.strip() for tag in raw.split(",") if tag.strip()]


class SourceCreateForm(_BaseSourceForm):
    class Meta:
        model = Source
        fields = ["name", "slug", "homepage", "tags"]


class SourceEditForm(_BaseSourceForm):
    class Meta:
        model = Source
        fields = ["name", "slug", "homepage", "tags", "enabled"]


class _BaseDarkSourceForm(forms.ModelForm):
    tags = forms.CharField(required=False, help_text="Comma-separated tags.")
    watch_keywords = forms.CharField(
        required=False, help_text="Comma-separated keywords for passive matching."
    )
    watch_regex = forms.CharField(
        required=False,
        help_text="Optional regex rules, one per line.",
        widget=forms.Textarea(attrs={"rows": 4}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.suitability_hint = ""
        if self.instance.pk:
            self.fields["tags"].initial = ", ".join(self.instance.tags or [])
            self.fields["watch_keywords"].initial = self.instance.watch_keywords
            self.fields["watch_regex"].initial = self.instance.watch_regex
        self.fields["source_type"].help_text = (
            "single_page = one page, index_page = same-host discovery, feed = RSS/Atom links."
        )
        self.fields["url"].help_text = (
            "Use dark allowlisted endpoints. Normal public news/research/advisory feeds should usually use standard intel feeds."
        )
        self.fields["use_tor"].help_text = "Onion URLs always use Tor. Enable to force Tor for clearnet."
        self.fields["timeout_seconds"].help_text = (
            "Optional per-source timeout override. Leave blank to use DARK_FETCH_TIMEOUT."
        )
        self.fields["max_bytes"].help_text = (
            "Optional per-source max response bytes. Leave blank to use DARK_MAX_BYTES."
        )
        self.fields["fetch_retries"].help_text = (
            "Optional retry override. Leave blank to use DARK_FETCH_RETRIES."
        )
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = _CHECKBOX_CLASS
            else:
                widget.attrs["class"] = _INPUT_CLASS

        url_value = self._bound_or_initial("url")
        source_type = self._bound_or_initial("source_type")
        self.suitability_hint = dark_source_suitability_warning(url_value, source_type)

    def _bound_or_initial(self, name: str):
        if self.is_bound:
            return self.data.get(self.add_prefix(name), "")
        if name in self.initial:
            return self.initial.get(name) or ""
        return getattr(self.instance, name, "") or ""

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        queryset = DarkSource.objects.filter(name=name)
        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A dark source with this name already exists.")
        return name

    def clean_slug(self):
        slug = self.cleaned_data["slug"]
        queryset = DarkSource.objects.filter(slug=slug)
        if self.instance.pk:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A dark source with this slug already exists.")
        return slug

    def clean_tags(self):
        raw = self.cleaned_data.get("tags", "")
        return [tag.strip() for tag in raw.split(",") if tag.strip()]

    def clean_watch_keywords(self):
        raw = self.cleaned_data.get("watch_keywords", "")
        normalized = [part.strip().lower() for part in raw.split(",") if part.strip()]
        return ", ".join(normalized)

    def clean_watch_regex(self):
        raw = self.cleaned_data.get("watch_regex", "")
        normalized_lines = []
        for line in str(raw).splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            normalized_lines.append(cleaned)
        return "\n".join(normalized_lines)

    def clean_timeout_seconds(self):
        value = self.cleaned_data.get("timeout_seconds")
        if value in (None, ""):
            return None
        value = int(value)
        if value < 1 or value > 120:
            raise ValidationError("Timeout must be between 1 and 120 seconds.")
        return value

    def clean_max_bytes(self):
        value = self.cleaned_data.get("max_bytes")
        if value in (None, ""):
            return None
        value = int(value)
        if value < 1024 or value > 25_000_000:
            raise ValidationError("Max bytes must be between 1024 and 25000000.")
        return value

    def clean_fetch_retries(self):
        value = self.cleaned_data.get("fetch_retries")
        if value in (None, ""):
            return None
        value = int(value)
        if value < 1 or value > 10:
            raise ValidationError("Retries must be between 1 and 10.")
        return value


class DarkSourceCreateForm(_BaseDarkSourceForm):
    class Meta:
        model = DarkSource
        fields = [
            "name",
            "slug",
            "homepage",
            "url",
            "source_type",
            "enabled",
            "use_tor",
            "timeout_seconds",
            "max_bytes",
            "fetch_retries",
            "tags",
            "watch_keywords",
            "watch_regex",
        ]


class DarkSourceEditForm(_BaseDarkSourceForm):
    class Meta:
        model = DarkSource
        fields = [
            "name",
            "slug",
            "homepage",
            "url",
            "source_type",
            "enabled",
            "use_tor",
            "timeout_seconds",
            "max_bytes",
            "fetch_retries",
            "tags",
            "watch_keywords",
            "watch_regex",
        ]
