import subprocess
import sys
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.db import transaction
from django.utils import timezone

from .models import OpsJob


OPS_ACTIONS = {
    "ingest": ("ingest_sources", [], {}, "Ingest run"),
    "ingest_dark": ("ingest_dark", [], {}, "Dark ingest run"),
    "prune": ("prune_items", [], {}, "Prune run"),
    "prune_dry_run": ("prune_items", ["--dry-run"], {}, "Prune dry-run"),
    "seed": ("seed_sources", [], {}, "Seed run"),
    "seed_sync": ("seed_sources", ["--sync"], {}, "Seed sync run"),
}


def queue_ops_job(*, action: str, requested_by=None) -> tuple[OpsJob, str]:
    if action not in OPS_ACTIONS:
        raise ValueError("Unknown action.")
    command_name, args, options, label = OPS_ACTIONS[action]
    job = OpsJob.objects.create(
        command_name=command_name,
        command_args=list(args),
        command_options=dict(options),
        requested_by=requested_by,
    )
    return job, label


def launch_ops_job_subprocess(job_id: int):
    manage_py = Path(settings.BASE_DIR) / "manage.py"
    cmd = [sys.executable, str(manage_py), "run_ops_job", str(job_id)]
    return subprocess.Popen(
        cmd,
        cwd=str(settings.BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def run_ops_job(job_id: int):
    with transaction.atomic():
        job = OpsJob.objects.select_for_update().get(id=job_id)
        if job.status == OpsJob.Status.RUNNING:
            return job
        if job.status in {OpsJob.Status.SUCCESS, OpsJob.Status.FAILED}:
            return job
        job.status = OpsJob.Status.RUNNING
        job.started_at = timezone.now()
        job.error_summary = ""
        job.save(update_fields=["status", "started_at", "error_summary", "updated_at"])

    out = StringIO()
    err = StringIO()
    try:
        call_command(
            job.command_name,
            *(job.command_args or []),
            stdout=out,
            stderr=err,
            **(job.command_options or {}),
        )
        status = OpsJob.Status.SUCCESS
        error_summary = ""
    except Exception as exc:
        status = OpsJob.Status.FAILED
        error_summary = str(exc)[:2000]
        if not err.getvalue():
            err.write(str(exc))

    job.status = status
    job.finished_at = timezone.now()
    job.stdout = out.getvalue()[:200000]
    job.stderr = err.getvalue()[:200000]
    job.error_summary = error_summary
    job.save(
        update_fields=[
            "status",
            "finished_at",
            "stdout",
            "stderr",
            "error_summary",
            "updated_at",
        ]
    )
    return job
