from django import forms
from django.core.exceptions import ValidationError

from .models import DarkSource, Feed, Source


_INPUT_CLASS = (
    "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 "
    "placeholder:text-slate-500 focus:border-sky-400 focus:outline-none"
)
_CHECKBOX_CLASS = "h-4 w-4 rounded border-slate-700 bg-slate-950 text-sky-400 focus:ring-sky-400"


class _BaseFeedForm(forms.ModelForm):
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
            "section",
            "enabled",
            "max_age_days",
            "max_items_per_run",
        ]


class FeedEditForm(_BaseFeedForm):
    class Meta:
        model = Feed
        fields = ["url", "enabled", "section", "max_age_days", "max_items_per_run"]


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["tags"].initial = ", ".join(self.instance.tags or [])
            self.fields["watch_keywords"].initial = self.instance.watch_keywords
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = _CHECKBOX_CLASS
            else:
                widget.attrs["class"] = _INPUT_CLASS

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


class DarkSourceCreateForm(_BaseDarkSourceForm):
    class Meta:
        model = DarkSource
        fields = ["name", "slug", "homepage", "url", "tags", "watch_keywords"]


class DarkSourceEditForm(_BaseDarkSourceForm):
    class Meta:
        model = DarkSource
        fields = ["name", "slug", "homepage", "url", "tags", "watch_keywords", "enabled"]
