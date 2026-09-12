"""Reusable documentation fixture for the Windows ACL README proof packet.

Copyable spellings below are the live settings / registration / AccessCheck
surface. Chat owns README prose; this module only freezes the verified
names so later user-facing examples can be copied, not invented.

``WinNode.objects.authorized`` is installed (AuthorizedManager) but is
not the AccessCheck listing surface: inheritance and owner pre-grant
live in the consumer SQL used by ``access_check`` / ``authorized_pks`` /
``authorized_nodes``.
"""

from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext

from trusts.core import Along, FlatToken, OrderedFold

from winfs.constants import MAX_PARENT_DEPTH, R, RC, WD
from winfs.evaluate import access_check, authorized_nodes, authorized_pks
from winfs.fixtures import allow
from winfs.models import WinNode
from winfs.policy import INHERITANCE_WALK, NODE_FOLD, register_winfs_policy

from .support import FixtureMixin, PostgresTestCase

# --- Copyable settings (live ``config.settings``) ---
#
# Required implementation entries. Demo extras (admin, sessions, static,
# messages) are present in this repository's project settings but are not
# the authorization contract.
COPYABLE_INSTALLED_APP = "winfs.apps.WinfsConfig"
COPYABLE_AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "winfs.backends.WinfsBackend",
]

# --- Copyable registration (live ``winfs.policy``) ---
#
# registry.register_strategy(NODE_FOLD)
# INHERITANCE_WALK = Along(Ref(WinNode).parent, bound=64)
# Along is not register(along=) and is not AnyPath grant-reachability.

# --- Copyable authorization surface ---
#
# user.has_perm("winfs.read_winnode", node)
# access_check(user, node, R)
# authorized_pks(user, R, parent_id=parent.pk, limit=25, offset=0)
# authorized_nodes(user, R, parent_id=parent.pk)
#
# Domain codes: winfs.{read,write,execute,readwrite,list,readcontrol,writedac}_winnode


class ReadmeProofTests(FixtureMixin, PostgresTestCase):
    def setUp(self):
        super().setUp()
        from winfs.policy import ensure_domain_permissions

        ensure_domain_permissions()

    def _read_perm(self):
        ct = ContentType.objects.get_for_model(WinNode)
        return Permission.objects.get(content_type=ct, codename="read_winnode")

    def _registry(self):
        from winfs.apps import winfs_config

        return winfs_config().configured_backend().registry

    def _assert_one_statement(self, fn):
        with CaptureQueriesContext(connection) as captured:
            result = fn()
        self.assertEqual(
            len(captured.captured_queries),
            1,
            "expected one SQL statement, got %s:\n%s"
            % (
                len(captured.captured_queries),
                "\n---\n".join(q["sql"] for q in captured.captured_queries),
            ),
        )
        return result

    def test_copyable_settings_match_live_project(self):
        self.assertIn(COPYABLE_INSTALLED_APP, settings.INSTALLED_APPS)
        self.assertNotIn("trusts", settings.INSTALLED_APPS)
        self.assertNotIn("trusts.apps.KernelConfig", settings.INSTALLED_APPS)
        self.assertEqual(
            list(settings.AUTHENTICATION_BACKENDS),
            COPYABLE_AUTHENTICATION_BACKENDS,
        )

    def test_copyable_ordered_fold_and_consumer_along(self):
        self.assertIsInstance(NODE_FOLD, OrderedFold)
        self.assertEqual(repr(NODE_FOLD.content), "Ref(WinNode)")
        self.assertEqual(repr(NODE_FOLD.source), "Ref(WinAce)")
        self.assertIsInstance(NODE_FOLD.token, FlatToken)
        self.assertEqual(repr(NODE_FOLD.token.principal), "Ref(WinPrincipal)")
        self.assertEqual(repr(NODE_FOLD.token.member), "Ref(WinSidMember)")
        self.assertIsInstance(INHERITANCE_WALK, Along)
        self.assertEqual(INHERITANCE_WALK.bound, MAX_PARENT_DEPTH)
        self.assertEqual(INHERITANCE_WALK.bound, 64)
        self.assertEqual(repr(INHERITANCE_WALK), "Along(Ref(WinNode).parent, bound=64)")
        registry = self._registry()
        self.assertEqual(registry.records, ())
        self.assertEqual(len(registry.strategies), 1)
        self.assertIs(registry.plan_for(WinNode).strategy.content_model, WinNode)
        before = registry.strategies
        again = register_winfs_policy(registry)
        self.assertEqual(again, before)

    def test_object_and_listing_share_accesscheck_surface(self):
        allow(self.notes, self.data["alice"], R)
        self.assertTrue(access_check(self.alice, self.notes, R).allowed)
        self.assertTrue(self.alice.has_perm("winfs.read_winnode", self.notes))
        self.assertEqual(
            authorized_pks(
                self.alice,
                R,
                parent_id=self.secret.pk,
                limit=25,
                offset=0,
            ),
            [self.notes.pk],
        )
        listed = authorized_nodes(
            self.alice,
            R,
            parent_id=self.secret.pk,
            limit=25,
            offset=0,
        )
        self.assertEqual([node.pk for node in listed], [self.notes.pk])

    def test_object_decision_and_authorized_listing_are_one_query(self):
        allow(self.notes, self.data["alice"], R)
        decision = self._assert_one_statement(
            lambda: access_check(self.alice, self.notes, R)
        )
        self.assertTrue(decision.allowed)
        allowed = self._assert_one_statement(
            lambda: self.alice.has_perm("winfs.read_winnode", self.notes)
        )
        self.assertTrue(allowed)
        pks = self._assert_one_statement(
            lambda: authorized_pks(
                self.alice,
                R,
                parent_id=self.secret.pk,
                limit=25,
                offset=0,
            )
        )
        self.assertEqual(pks, [self.notes.pk])
        nodes = self._assert_one_statement(
            lambda: authorized_nodes(
                self.alice,
                R,
                parent_id=self.secret.pk,
                limit=25,
                offset=0,
            )
        )
        self.assertEqual([node.pk for node in nodes], [self.notes.pk])

    def test_inherited_allow_is_accesscheck_not_authorized_manager(self):
        allow(self.proj, self.eng, R, oi=True, ci=True)
        self.assertTrue(access_check(self.alice, self.readme, R).allowed)
        self.assertTrue(self.alice.has_perm("winfs.read_winnode", self.readme))
        self.assertIn(
            self.readme.pk,
            authorized_pks(self.alice, R, parent_id=self.proj.pk),
        )
        fold_allowed = self._registry().has_permission(
            self.alice,
            self.readme,
            self._read_perm(),
        )
        self.assertFalse(fold_allowed)
        self.assertNotIn(
            self.readme,
            list(WinNode.objects.authorized(self.alice, self._read_perm())),
        )

    def test_owner_pregrant_is_rc_wd_not_full_control(self):
        self.assertTrue(access_check(self.alice, self.notes, RC).allowed)
        self.assertTrue(access_check(self.alice, self.notes, WD).allowed)
        self.assertTrue(self.alice.has_perm("winfs.writedac_winnode", self.notes))
        self.assertFalse(access_check(self.alice, self.notes, R).allowed)
        self.assertFalse(self.alice.has_perm("winfs.read_winnode", self.notes))

    def test_empty_dacl_and_missing_policy_fail_closed(self):
        self.assertFalse(access_check(self.alice, self.notes, R).allowed)
        self.assertIsNone(access_check(self.alice, self.notes, R).error)
        self.assertEqual(
            authorized_pks(self.alice, R, parent_id=self.secret.pk),
            [],
        )
        self.notes.security_descriptor = None
        self.notes.save()
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, "missing_descriptor")
