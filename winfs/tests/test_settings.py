"""Ordinary ModelBackend auth; Trusts checks run through KernelConfig."""

from django.apps import apps
from django.conf import settings
from django.core import checks
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from winfs.fixtures import standard_tree


class KernelConfigAndAuthTests(TestCase):
    def test_installed_app_is_kernel_config(self):
        self.assertIn("trusts.apps.KernelConfig", settings.INSTALLED_APPS)
        self.assertNotIn("trusts", settings.INSTALLED_APPS)
        self.assertNotIn("trusts.zero.apps.ZeroConfig", settings.INSTALLED_APPS)
        kernel = apps.get_app_config("trusts_kernel")
        self.assertEqual(kernel.name, "trusts")
        self.assertEqual(kernel.label, "trusts_kernel")
        from trusts.apps import KernelConfig

        self.assertIsInstance(kernel, KernelConfig)

    def test_authentication_backend_is_django_model_backend(self):
        self.assertEqual(
            list(settings.AUTHENTICATION_BACKENDS),
            ["django.contrib.auth.backends.ModelBackend"],
        )

    def test_trusts_system_checks_are_clean(self):
        issues = checks.run_checks()
        trusts_ids = sorted({issue.id for issue in issues if issue.id.startswith("trusts.")})
        self.assertEqual(trusts_ids, [])
        for banned in ("trusts.E001", "trusts.E002", "trusts.E006", "trusts.E007", "trusts.E008"):
            self.assertNotIn(banned, [issue.id for issue in issues])

    def test_manage_py_check_stays_silent(self):
        call_command("check")

    def test_kernel_checks_module_is_loaded_via_appconfig(self):
        from django.core.checks.registry import registry

        import trusts.checks as trusts_checks

        registered = {check.__name__ for check in registry.registered_checks}
        self.assertIn(trusts_checks.check_context_registry.__name__, registered)
        self.assertIn(trusts_checks.check_trustee_registry.__name__, registered)
        self.assertIn(trusts_checks.check_trustee_configuration.__name__, registered)

    def test_password_login_uses_model_backend(self):
        standard_tree()
        response = self.client.post(
            reverse("login"),
            {"username": "alice", "password": "demo"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/winfs/")
