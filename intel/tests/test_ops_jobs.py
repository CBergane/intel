from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from intel.models import OpsJob


class OpsJobRunnerTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.superuser = user_model.objects.create_superuser(
            username="ops-job-admin",
            password="ops-job-pass-123",
        )

    def test_run_ops_job_stores_success_output(self):
        job = OpsJob.objects.create(command_name="seed_sources", command_args=[])

        def fake_call_command(command_name, *args, **kwargs):
            self.assertEqual(command_name, "seed_sources")
            kwargs["stdout"].write("seed ok")

        with patch("intel.ops_jobs.call_command", side_effect=fake_call_command):
            call_command("run_ops_job", str(job.id))

        job.refresh_from_db()
        self.assertEqual(job.status, OpsJob.Status.SUCCESS)
        self.assertIn("seed ok", job.stdout)
        self.assertEqual(job.error_summary, "")

    def test_run_ops_job_stores_failure_output(self):
        job = OpsJob.objects.create(command_name="ingest_sources", command_args=["--feed", "1"])

        def fake_call_command(command_name, *args, **kwargs):
            kwargs["stderr"].write("network timeout")
            raise RuntimeError("fetch failed")

        with patch("intel.ops_jobs.call_command", side_effect=fake_call_command):
            call_command("run_ops_job", str(job.id))

        job.refresh_from_db()
        self.assertEqual(job.status, OpsJob.Status.FAILED)
        self.assertIn("network timeout", job.stderr)
        self.assertIn("fetch failed", job.error_summary)

    def test_job_output_is_visible_on_ops_page(self):
        job = OpsJob.objects.create(
            command_name="ingest_sources",
            command_args=[],
            status=OpsJob.Status.SUCCESS,
            stdout="ingest completed",
            requested_by=self.superuser,
        )
        self.client.force_login(self.superuser)
        response = self.client.get(f"{reverse('intel_admin:ops')}?job={job.id}")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ingest completed")
