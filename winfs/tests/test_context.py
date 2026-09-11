"""Final-core owner registration; no Context / Trustee / kernel AppConfig."""

import inspect

from django.contrib.auth.models import Permission
from django.test import SimpleTestCase

from trusts.apps import TrustsImplementationConfig, implementation_for_path
from trusts.query import AuthorizedManager

from winfs import evaluate
from winfs.apps import CANONICAL_BACKEND, CORE_REQUIREMENT, FLOOR_MESSAGE, WinfsConfig
from winfs.evaluate import access_check
from winfs.fixtures import standard_tree
from winfs.models import WinNode
from winfs.policy import PARENT_REACH_BOUND, parent_along, register_explicit_dacl

from .support import PostgresTestCase


class OwnerRegistrationTests(PostgresTestCase):
    def setUp(self):
        super().setUp()
        self.data = standard_tree()

    def test_winfs_config_is_sole_implementation_owner(self):
        owner = implementation_for_path(CANONICAL_BACKEND)
        self.assertIsInstance(owner, WinfsConfig)
        self.assertIsInstance(owner, TrustsImplementationConfig)
        handle = owner.configured_backend(CANONICAL_BACKEND)
        self.assertEqual(len(handle.registry.strategies), 1)
        self.assertIs(handle.registry.strategies[0].content_model, WinNode)

    def test_winnode_uses_authorized_manager(self):
        self.assertIsInstance(WinNode.objects, AuthorizedManager)

    def test_evaluate_module_has_no_removed_core_surfaces(self):
        source = inspect.getsource(evaluate)
        self.assertNotIn('trusts.context', source)
        self.assertNotIn('trusts.trustee', source)
        self.assertNotIn('kernel_config', source)
        self.assertNotIn('TrustModelBackend', source)
        self.assertNotIn('from trusts.models', source)

    def test_unregistered_model_is_deny(self):
        from winfs.constants import R

        decision = access_check(self.data['users']['alice'], self.data['alice'].sid, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, 'context_not_registered')


class FloorAndAlongDeclarationTests(SimpleTestCase):
    def test_runtime_floor_names_final_core(self):
        self.assertEqual(CORE_REQUIREMENT, 'django-trusts>=1.0.0.dev3,<2')
        self.assertIn(CORE_REQUIREMENT, FLOOR_MESSAGE)
        self.assertNotIn('1.0.0.dev2', FLOOR_MESSAGE)

    def test_parent_along_is_the_approved_depth_bound(self):
        along = parent_along()
        self.assertEqual(along.bound, 64)
        self.assertEqual(along.bound, PARENT_REACH_BOUND)
        self.assertEqual(along.ref._path, ('parent',))

    def test_register_explicit_dacl_is_callable(self):
        self.assertTrue(callable(register_explicit_dacl))
        self.assertTrue(issubclass(Permission, object))
