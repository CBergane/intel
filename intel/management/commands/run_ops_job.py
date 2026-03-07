from django.core.management.base import BaseCommand, CommandError

from intel.ops_jobs import run_ops_job


class Command(BaseCommand):
    help = "Execute a queued OpsJob by id."

    def add_arguments(self, parser):
        parser.add_argument("job_id", type=int)

    def handle(self, *args, **options):
        job_id = options["job_id"]
        try:
            job = run_ops_job(job_id)
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"OpsJob #{job.id}: status={job.status} command={job.command_name}"
            )
        )
