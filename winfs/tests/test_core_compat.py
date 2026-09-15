"""Configured backend fails loudly on an incompatible Trusts stack."""

import sys
import types
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from winfs.compat import (
    CORE_PIN,
    CORE_REQUIREMENT,
    FLOOR_MESSAGE,
    ORDERED_FOLD_PIN,
    ORDERED_FOLD_REQUIREMENT,
    ORDERED_FOLD_REVIEWED_HEAD,
    require_ordered_fold,
    require_ordered_fold_backend,
)


class IncompatibleStackTests(SimpleTestCase):
    def test_missing_implementation_config_raises(self):
        fake_apps = types.ModuleType("trusts.apps")
        with patch.dict(sys.modules, {"trusts.apps": fake_apps}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_ordered_fold()
        self.assertIn(CORE_REQUIREMENT, str(ctx.exception))

    def test_missing_ordered_fold_package_raises(self):
        with patch.dict(sys.modules, {"trusts_ordered_fold": None}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_ordered_fold()
        self.assertIn(ORDERED_FOLD_REQUIREMENT, str(ctx.exception))

    def test_kernel_config_is_refused(self):
        import trusts.apps as apps_mod

        with patch.object(apps_mod, "KernelConfig", object, create=True):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_ordered_fold()
        self.assertIn("KernelConfig", str(ctx.exception))
        self.assertIn(CORE_REQUIREMENT, str(ctx.exception))

    def test_trust_model_backend_is_refused(self):
        import trusts.backends as backends_mod

        with patch.object(
            backends_mod, "TrustModelBackend", object, create=True
        ):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_ordered_fold_backend()
        self.assertIn("TrustModelBackend", str(ctx.exception))

    def test_legacy_context_module_is_refused(self):
        fake_context = types.ModuleType("trusts.context")
        with patch.dict(sys.modules, {"trusts.context": fake_context}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                require_ordered_fold()
        self.assertIn("trusts.context", str(ctx.exception))

    def test_floor_message_names_ordered_fold_package(self):
        self.assertIn("TrustsOrderedFoldModelBackend", FLOOR_MESSAGE)
        self.assertIn("OrderedFoldImplementationConfig", FLOOR_MESSAGE)
        self.assertIn("register_ordered_fold", FLOOR_MESSAGE)
        self.assertIn("1.0.0.dev3", FLOOR_MESSAGE)
        self.assertIn(CORE_PIN, FLOOR_MESSAGE)
        self.assertIn(ORDERED_FOLD_PIN, FLOOR_MESSAGE)
        self.assertIn("Do not rely on Core fold-name shims", FLOOR_MESSAGE)

    def test_w_cutover_pins(self):
        self.assertEqual(
            CORE_PIN,
            "6934894489d4fc0e46de88b55b9a27f5f2eb2b41",
        )
        self.assertEqual(
            ORDERED_FOLD_PIN,
            "c8c649aa5278db2b11fc380fa1646ae73df471ac",
        )
        self.assertEqual(
            ORDERED_FOLD_REVIEWED_HEAD,
            "639d4503f950931fee8bb900942bb1e599ae9b68",
        )
        names = require_ordered_fold()
        self.assertTrue(callable(names["register_ordered_fold"]))
        self.assertIs(
            names["OrderedFold"].__module__,
            "trusts_ordered_fold",
        )

    def test_core_fold_name_is_not_a_floor(self):
        from trusts.core import BackendHandle

        had_method = hasattr(BackendHandle, "register_ordered_fold")
        original = getattr(BackendHandle, "register_ordered_fold", None)
        if had_method:
            delattr(BackendHandle, "register_ordered_fold")
        try:
            names = require_ordered_fold()
            self.assertIn("OrderedFold", names)
            self.assertTrue(callable(names["register_ordered_fold"]))
        finally:
            if had_method:
                BackendHandle.register_ordered_fold = original

    def test_ordered_fold_imports(self):
        names = require_ordered_fold()
        self.assertIn("OrderedFoldImplementationConfig", names)
        self.assertIn("OrderedFold", names)
        self.assertIn("Along", names)
        self.assertIn("OrderedFoldBackendHandle", names)
        self.assertIn("register_ordered_fold", names)
        backend_names = require_ordered_fold_backend()
        self.assertIn("TrustsOrderedFoldModelBackend", backend_names)

    def test_winfs_backend_is_single_inheritance(self):
        from django.contrib.auth.backends import ModelBackend

        from trusts_ordered_fold.backends import TrustsOrderedFoldModelBackend
        from winfs.backends import WinfsBackend

        self.assertTrue(issubclass(WinfsBackend, TrustsOrderedFoldModelBackend))
        self.assertTrue(issubclass(TrustsOrderedFoldModelBackend, ModelBackend))
        self.assertEqual(
            WinfsBackend.__bases__,
            (TrustsOrderedFoldModelBackend,),
        )

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
