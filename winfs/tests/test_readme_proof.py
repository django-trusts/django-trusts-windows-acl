"""Reusable documentation fixture: copyable README facts (#5).

Locks install/config/registration/package spellings for the later
README/DEV cut. Does not change evaluator semantics or public callables.
"""

from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from winfs.constants import MAX_ACE_SCAN, MAX_PARENT_DEPTH
from winfs.evaluate import access_check, authorized_nodes, authorized_pks
from winfs.models import WinNode
from winfs.policy import INHERITANCE_WALK, NODE_FOLD

ROOT = Path(__file__).resolve().parents[2]


class ReadmeProofSettingsTests(SimpleTestCase):
    def test_winfs_config_and_core_trusts_absent(self):
        self.assertEqual(
            settings.INSTALLED_APPS[-1],
            "winfs.apps.WinfsConfig",
        )
        self.assertNotIn("trusts", settings.INSTALLED_APPS)
        self.assertFalse(
            any(
                entry == "trusts" or str(entry).startswith("trusts.")
                for entry in settings.INSTALLED_APPS
            )
        )

    def test_backends_are_modelbackend_then_winfsbackend(self):
        self.assertEqual(
            list(settings.AUTHENTICATION_BACKENDS),
            [
                "django.contrib.auth.backends.ModelBackend",
                "winfs.backends.WinfsBackend",
            ],
        )


class ReadmeProofRegistrationTests(SimpleTestCase):
    def test_ordered_fold_and_along_are_consumer_owned(self):
        from trusts.core import Along, OrderedFold

        self.assertIsInstance(NODE_FOLD, OrderedFold)
        self.assertIs(NODE_FOLD.content._root, WinNode)
        self.assertEqual(tuple(NODE_FOLD.content._path), ())
        self.assertEqual(
            tuple(NODE_FOLD.descriptor._path),
            ("security_descriptor",),
        )
        self.assertIsInstance(INHERITANCE_WALK, Along)
        self.assertEqual(INHERITANCE_WALK.bound, 64)
        self.assertEqual(INHERITANCE_WALK.bound, MAX_PARENT_DEPTH)
        self.assertIs(INHERITANCE_WALK.ref._root, WinNode)
        self.assertEqual(tuple(INHERITANCE_WALK.ref._path), ("parent",))

    def test_supported_policy_surface_names(self):
        self.assertEqual(access_check.__name__, "access_check")
        self.assertEqual(authorized_pks.__name__, "authorized_pks")
        self.assertEqual(authorized_nodes.__name__, "authorized_nodes")
        self.assertIn("One SQL statement", access_check.__doc__)
        self.assertIn("Filter before ORDER BY / LIMIT", authorized_pks.__doc__)
        self.assertTrue(hasattr(WinNode.objects, "authorized"))
        self.assertEqual(MAX_ACE_SCAN, 4096)


class ReadmeProofPackageTests(SimpleTestCase):
    def test_pyproject_install_facts(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "django-trusts-windows-acl"', text)
        self.assertIn('version = "0.1.0.dev0"', text)
        self.assertIn('requires-python = ">=3.12"', text)
        self.assertIn('"Django>=6.1,<6.2"', text)
        self.assertIn('"django-trusts>=1.0.0.dev3,<2"', text)
        self.assertNotIn("readme", text)
        self.assertNotIn("license", text)
        self.assertNotIn("authors", text)
        self.assertIn('include = ["config*", "winfs*"]', text)

    def test_requirements_pin_and_ci_matrix(self):
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn(
            "django-trusts @ git+https://github.com/django-trusts/"
            "django-trusts.git@1e19b5d464c067186aada58943c3ee67c44b2aa0",
            req,
        )
        self.assertIn("Django>=6.1,<6.2", req)
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('python-version: "3.12"', ci)
        self.assertIn("image: postgres:16", ci)
        self.assertIn("python manage.py test winfs", ci)
        self.assertEqual((ROOT / ".python-version").read_text(encoding="utf-8").strip(), "3.12")

    def test_license_file_is_bsd_2_clause_with_beedesk_2026(self):
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Copyright (c) 2026, BeeDesk, Inc.", text)
        self.assertIn("Redistribution and use in source and binary forms", text)
        self.assertIn("this list of conditions and the following disclaimer", text)
        self.assertNotIn("3. Neither the name", text)
        # Current notice still has the extra clause Chat must drop later.
        self.assertIn("BeeDesk, Inc., and contributors", text)
