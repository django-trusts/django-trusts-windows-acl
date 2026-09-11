"""Final-core registration: OrderedFold on WinNode, no Context / Trustee."""

import inspect

from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from trusts.core import Along, OrderedFold

from winfs import evaluate
from winfs.constants import MAX_PARENT_DEPTH, R
from winfs.evaluate import ERR_CONTEXT, access_check
from winfs.fixtures import standard_tree
from winfs.models import WinNode, WinStream
from winfs.policy import INHERITANCE_WALK, MASK_ENTRIES, NODE_FOLD

from .support import PostgresTestCase


class CoreRegistrationTests(PostgresTestCase):
    def setUp(self):
        super().setUp()
        self.data = standard_tree()

    def _registry(self):
        from winfs.apps import winfs_config

        return winfs_config().configured_backend().registry

    def test_trusts_is_absent_from_installed_apps(self):
        self.assertNotIn("trusts", settings.INSTALLED_APPS)
        self.assertNotIn("trusts.apps.KernelConfig", settings.INSTALLED_APPS)

    def test_ordered_fold_is_registered_on_winnode(self):
        registry = self._registry()
        self.assertTrue(registry.frozen)
        self.assertEqual(len(registry.strategies), 1)
        self.assertEqual(registry.records, ())
        compiled = registry.plan_for(WinNode).strategy
        self.assertIsNotNone(compiled)
        self.assertIs(compiled.content_model, WinNode)
        self.assertEqual(len(compiled.mask_rows), len(MASK_ENTRIES))

    def test_along_models_parent_bound_not_anypath_grant_walk(self):
        self.assertIsInstance(INHERITANCE_WALK, Along)
        self.assertEqual(INHERITANCE_WALK.bound, MAX_PARENT_DEPTH)
        self.assertEqual(INHERITANCE_WALK.bound, 64)
        self.assertIsInstance(NODE_FOLD, OrderedFold)
        registry = self._registry()
        self.assertEqual(registry.records, ())

    def test_stream_shares_node_dacl_not_parent(self):
        stream = WinStream.objects.create(
            node=self.data["notes"],
            name="Zone.Identifier",
        )
        from winfs.fixtures import allow

        allow(self.data["notes"], self.data["alice"], R)
        self.assertTrue(
            access_check(self.data["users"]["alice"], stream, R).allowed
        )
        self.assertFalse(
            access_check(
                self.data["users"]["alice"],
                self.data["secret"],
                R,
            ).allowed
        )

    def test_evaluate_module_has_no_trust_or_trustee_grant_path(self):
        source = inspect.getsource(evaluate)
        self.assertNotIn("from trusts.models", source)
        self.assertNotIn("from trusts.trustee", source)
        self.assertNotIn("from trusts.context", source)
        self.assertNotIn("django.contrib.auth.models", source)

    def test_unregistered_model_is_deny(self):
        decision = access_check(
            self.data["users"]["alice"],
            self.data["alice"].sid,
            R,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_CONTEXT)

    def test_domain_permissions_exist_for_winnode(self):
        ct = ContentType.objects.get_for_model(WinNode)
        for entry in MASK_ENTRIES:
            codename = "%s_%s" % (entry.action, WinNode._meta.model_name)
            self.assertTrue(
                Permission.objects.filter(
                    content_type=ct,
                    codename=codename,
                ).exists(),
                codename,
            )
