from django import forms

from .models import Feed


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
