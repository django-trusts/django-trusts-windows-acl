"""Configured backend fails loudly on an incompatible django-trusts core."""

import sys
import types
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from winfs.compat import (
    CORE_REQUIREMENT,
    FLOOR_MESSAGE,
    require_final_core,
    require_final_core_backend,
)


class IncompatibleCoreTests(SimpleTestCase):
    def test_missing_implementation_config_raises(self):
        fake_apps = types.ModuleType("trusts.apps")
        with patch.dict(sys.modules, {"trusts.apps": fake_apps}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_final_core()
        self.assertIn(CORE_REQUIREMENT, str(ctx.exception))

    def test_kernel_config_is_refused(self):
        import trusts.apps as apps_mod

        with patch.object(apps_mod, "KernelConfig", object, create=True):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_final_core()
        self.assertIn("KernelConfig", str(ctx.exception))
        self.assertIn(CORE_REQUIREMENT, str(ctx.exception))

    def test_trust_model_backend_is_refused(self):
        import trusts.backends as backends_mod

        with patch.object(
            backends_mod, "TrustModelBackend", object, create=True
        ):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_final_core_backend()
        self.assertIn("TrustModelBackend", str(ctx.exception))

    def test_legacy_context_module_is_refused(self):
        fake_context = types.ModuleType("trusts.context")
        with patch.dict(sys.modules, {"trusts.context": fake_context}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_final_core()
        self.assertIn("trusts.context", str(ctx.exception))

    def test_floor_message_names_final_core(self):
        self.assertIn("TrustsImplementationConfig", FLOOR_MESSAGE)
        self.assertIn("OrderedFold", FLOOR_MESSAGE)
        self.assertIn("1.0.0.dev3", FLOOR_MESSAGE)

    def test_final_core_imports(self):
        names = require_final_core()
        self.assertIn("TrustsImplementationConfig", names)
        self.assertIn("OrderedFold", names)
        self.assertIn("Along", names)

    def test_license_copyright_year_is_2026(self):
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2] / "LICENSE"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Copyright (c) 2026, BeeDesk, Inc.",
            text,
        )
        self.assertNotIn("BeeDesk, Inc., and contributors", text)
        self.assertNotIn("Copyright (c) 2016", text)
