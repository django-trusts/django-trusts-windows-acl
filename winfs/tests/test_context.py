"""Final-core registration: OrderedFold on WinNode, no Context / Trustee."""

import inspect

from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from django.db import connection
from django.test.utils import CaptureQueriesContext

from trusts.core import Along, Ref, TrustsConfigurationError
from trusts_ordered_fold import (
    FlatToken,
    OrderedFold,
    OrderedFoldBackendHandle,
    OrderedFoldQueryCompiler,
    OrderedFoldRegistry,
    PolarityMap,
    register_ordered_fold,
)

from winfs import evaluate
from winfs.constants import MAX_PARENT_DEPTH, R
from winfs.evaluate import ERR_CONTEXT, access_check
from winfs.fixtures import standard_tree
from winfs.models import (
    WinAce,
    WinNode,
    WinPrincipal,
    WinSecurityDescriptor,
    WinSidMember,
    WinStream,
)
from winfs.policy import (
    INHERITANCE_WALK,
    MASK_ENTRIES,
    NODE_FOLD,
    PERMISSION_DOMAIN,
    register_winfs_policy,
)

from .support import PostgresTestCase


class CoreRegistrationTests(PostgresTestCase):
    def setUp(self):
        super().setUp()
        self.data = standard_tree()

    def _backend(self):
        from winfs.apps import winfs_config

        return winfs_config().configured_backend()

    def _registry(self):
        return self._backend().registry

    def test_trusts_is_absent_from_installed_apps(self):
        self.assertNotIn("trusts", settings.INSTALLED_APPS)
        self.assertNotIn("trusts.apps.KernelConfig", settings.INSTALLED_APPS)

    def test_ordered_fold_is_registered_on_winnode(self):
        backend = self._backend()
        self.assertIsInstance(backend, OrderedFoldBackendHandle)
        registry = backend.registry
        self.assertIsInstance(registry, OrderedFoldRegistry)
        self.assertTrue(registry.frozen)
        self.assertEqual(len(registry.strategies), 1)
        self.assertEqual(registry.records, ())
        compiled = registry.plan_for(WinNode).strategy
        self.assertIsNotNone(compiled)
        self.assertIs(compiled.content_model, WinNode)
        self.assertIs(compiled.source_model, WinAce)
        self.assertEqual(len(compiled.mask_rows), len(MASK_ENTRIES))
        self.assertIs(compiled.policy_set_model, WinSecurityDescriptor)

    def test_single_configured_path_is_winfs_backend(self):
        from django.conf import settings

        from trusts_ordered_fold.backends import TrustsOrderedFoldModelBackend
        from winfs.apps import WinfsConfig
        from winfs.backends import WinfsBackend

        self.assertEqual(
            WinfsConfig.trusts_backend_paths,
            ("winfs.backends.WinfsBackend",),
        )
        self.assertEqual(
            list(settings.AUTHENTICATION_BACKENDS),
            [
                "django.contrib.auth.backends.ModelBackend",
                "winfs.backends.WinfsBackend",
            ],
        )
        self.assertNotIn(
            "trusts_ordered_fold.backends.TrustsOrderedFoldModelBackend",
            settings.AUTHENTICATION_BACKENDS,
        )
        self.assertTrue(issubclass(WinfsBackend, TrustsOrderedFoldModelBackend))
        from trusts_ordered_fold import OrderedFoldImplementationConfig

        self.assertTrue(issubclass(WinfsConfig, OrderedFoldImplementationConfig))

    def test_public_fold_uses_configured_backend_method_not_ref(self):
        self.assertIsInstance(NODE_FOLD, OrderedFold)
        self.assertEqual(NODE_FOLD.__class__.__module__, "trusts_ordered_fold")
        self.assertIs(NODE_FOLD.content, WinNode)
        self.assertEqual(NODE_FOLD.descriptor, "security_descriptor")
        self.assertIsNone(NODE_FOLD.source)
        self.assertEqual(NODE_FOLD.source_descriptor, "descriptor")
        self.assertEqual(NODE_FOLD.order, "ace_order")
        self.assertEqual(NODE_FOLD.mask, "access_mask")
        self.assertEqual(NODE_FOLD.trustee, "trustee_sid")
        self.assertIsInstance(NODE_FOLD.polarity, PolarityMap)
        self.assertEqual(NODE_FOLD.polarity.field, "ace_type")
        self.assertIsInstance(NODE_FOLD.token, FlatToken)
        self.assertIs(NODE_FOLD.token.principal, WinPrincipal)
        self.assertEqual(NODE_FOLD.token.principal_user, "user")
        self.assertEqual(NODE_FOLD.token.principal_identity, "sid")
        self.assertIs(NODE_FOLD.token.member, WinSidMember)
        self.assertEqual(NODE_FOLD.token.member_identity, "member_sid")
        self.assertEqual(NODE_FOLD.token.member_group, "group_sid__sid")
        source = inspect.getsource(register_winfs_policy)
        self.assertIn("register_ordered_fold(backend, WinAce, NODE_FOLD)", source)
        self.assertNotIn("backend.register_ordered_fold", source)
        self.assertNotIn("register_strategy", source)
        self.assertNotIn("backend.registry", source)
        from winfs import policy as policy_mod
        from winfs.apps import WinfsConfig

        self.assertNotIn("from trusts.core import MaskEntry", inspect.getsource(policy_mod))
        self.assertNotIn("from trusts.core import OrderedFold", inspect.getsource(policy_mod))
        apps_source = inspect.getsource(WinfsConfig.ready)
        self.assertIn("configured_backend", apps_source)
        self.assertIn("register_winfs_policy(backend)", apps_source)
        self.assertNotIn(".registry", apps_source)
        self.assertNotIn("register_strategy", apps_source)

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
        from winfs.policy import ensure_domain_permissions

        ensure_domain_permissions()
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

    def test_startup_redonation_is_idempotent_and_zero_sql(self):
        backend = self._backend()
        before = backend.registry.strategies
        with CaptureQueriesContext(connection) as captured:
            register_winfs_policy(backend)
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertEqual(backend.registry.strategies, before)

    def test_register_winfs_policy_rejects_bare_registry(self):
        with self.assertRaises(TypeError):
            register_winfs_policy(self._registry())


def _isolated_backend():
    return OrderedFoldBackendHandle(
        path="winfs.tests.isolated",
        registry=OrderedFoldRegistry(),
        compiler=OrderedFoldQueryCompiler(),
    )


def _public_fold(**overrides):
    fields = {
        "content": WinNode,
        "descriptor": "security_descriptor",
        "source_descriptor": "descriptor",
        "order": "ace_order",
        "polarity": PolarityMap(
            "ace_type",
            allow_value="allow",
            deny_value="deny",
        ),
        "mask": "access_mask",
        "trustee": "trustee_sid",
        "token": FlatToken(
            principal=WinPrincipal,
            principal_user="user",
            principal_identity="sid",
            member=WinSidMember,
            member_identity="member_sid",
            member_group="group_sid__sid",
        ),
        "domain": PERMISSION_DOMAIN,
    }
    fields.update(overrides)
    return OrderedFold(**fields)


class OrderedFoldDonationTests(PostgresTestCase):
    def test_isolated_donation_is_zero_sql_and_convergent(self):
        backend = _isolated_backend()
        with CaptureQueriesContext(connection) as captured:
            compiled = register_ordered_fold(backend, WinAce, NODE_FOLD)
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertIs(compiled.content_model, WinNode)
        self.assertIs(compiled.source_model, WinAce)
        self.assertIs(compiled.policy_set_model, WinSecurityDescriptor)
        self.assertEqual(compiled.content_desc_attname, "security_descriptor_id")
        self.assertEqual(compiled.source_desc_attname, "descriptor_id")
        self.assertEqual(len(backend.registry.strategies), 1)

    def test_duplicate_isolated_donation_is_zero_sql_and_unmutated(self):
        backend = _isolated_backend()
        first = register_ordered_fold(backend, WinAce, NODE_FOLD)
        before = backend.registry.strategies
        with CaptureQueriesContext(connection) as captured:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                register_ordered_fold(backend, WinAce, _public_fold())
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertIn("Conflicting OrderedFold", str(ctx.exception))
        self.assertEqual(backend.registry.strategies, before)
        self.assertIs(backend.registry.strategies[0], first)

    def test_ref_declaration_is_zero_sql_and_unmutated(self):
        backend = _isolated_backend()
        with CaptureQueriesContext(connection) as captured:
            with self.assertRaises(TypeError):
                register_ordered_fold(
                    backend,
                    WinAce,
                    _public_fold(source_descriptor=Ref(WinAce).descriptor),
                )
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertEqual(backend.registry.strategies, ())

    def test_derived_source_field_is_zero_sql_and_unmutated(self):
        backend = _isolated_backend()
        with CaptureQueriesContext(connection) as captured:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                register_ordered_fold(
                    backend,
                    WinAce,
                    _public_fold(source=WinAce),
                )
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertIn("source is derived", str(ctx.exception))
        self.assertEqual(backend.registry.strategies, ())

    def test_missing_source_descriptor_is_zero_sql_and_unmutated(self):
        backend = _isolated_backend()
        with CaptureQueriesContext(connection) as captured:
            with self.assertRaises((TypeError, TrustsConfigurationError)):
                register_ordered_fold(
                    backend,
                    WinAce,
                    _public_fold(source_descriptor=None),
                )
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertEqual(backend.registry.strategies, ())

    def test_frozen_backend_rejects_before_mutation(self):
        backend = self._live_backend()
        before = backend.registry.strategies
        with CaptureQueriesContext(connection) as captured:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                register_ordered_fold(backend, WinAce, NODE_FOLD)
        self.assertEqual(len(captured.captured_queries), 0)
        self.assertIn("frozen", str(ctx.exception).lower())
        self.assertEqual(backend.registry.strategies, before)

    def _live_backend(self):
        from winfs.apps import winfs_config

        return winfs_config().configured_backend()

