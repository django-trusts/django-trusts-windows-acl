"""OrderedFold explicit-DACL remaining-bits agrees with AccessCheck."""

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext

from winfs.constants import R, W
from winfs.evaluate import access_check
from winfs.fixtures import allow, deny
from winfs.models import WinNode

from .support import FixtureMixin, PostgresTestCase


class OrderedFoldParityTests(FixtureMixin, PostgresTestCase):
    def setUp(self):
        super().setUp()
        from winfs.policy import ensure_domain_permissions

        ensure_domain_permissions()

    def _read_perm(self):
        ct = ContentType.objects.get_for_model(WinNode)
        return Permission.objects.get(content_type=ct, codename="read_winnode")

    def _write_perm(self):
        ct = ContentType.objects.get_for_model(WinNode)
        return Permission.objects.get(content_type=ct, codename="write_winnode")

    def _readwrite_perm(self):
        ct = ContentType.objects.get_for_model(WinNode)
        return Permission.objects.get(
            content_type=ct,
            codename="readwrite_winnode",
        )

    def _fold(self, user, node, permission):
        from winfs.apps import winfs_config

        registry = winfs_config().configured_backend().registry
        return registry.has_permission(user, node, permission)

    def test_explicit_allow_matches_v3(self):
        allow(self.notes, self.data["alice"], R)
        self.assertTrue(access_check(self.alice, self.notes, R).allowed)
        self.assertTrue(self._fold(self.alice, self.notes, self._read_perm()))

    def test_canonical_deny_then_allow_matches_v4(self):
        deny(self.notes, self.data["alice"], R)
        allow(self.notes, self.data["alice"], R)
        self.assertFalse(access_check(self.alice, self.notes, R).allowed)
        self.assertFalse(self._fold(self.alice, self.notes, self._read_perm()))

    def test_noncanonical_allow_then_deny_matches_v5(self):
        allow(self.notes, self.data["alice"], R)
        deny(self.notes, self.data["alice"], R)
        self.assertTrue(access_check(self.alice, self.notes, R).allowed)
        self.assertTrue(self._fold(self.alice, self.notes, self._read_perm()))

    def test_partial_bits_and_accumulate_match_v9_v10(self):
        allow(self.notes, self.data["alice"], R)
        self.assertFalse(access_check(self.alice, self.notes, R | W).allowed)
        self.assertFalse(
            self._fold(self.alice, self.notes, self._readwrite_perm())
        )
        allow(self.notes, self.data["alice"], W)
        self.assertTrue(access_check(self.alice, self.notes, R | W).allowed)
        self.assertTrue(
            self._fold(self.alice, self.notes, self._readwrite_perm())
        )

    def test_has_perm_uses_full_accesscheck_for_owner_wd(self):
        from winfs.constants import WD

        self.assertTrue(access_check(self.alice, self.notes, WD).allowed)
        self.assertTrue(
            self.alice.has_perm("winfs.writedac_winnode", self.notes)
        )

    def test_has_perm_object_decision_is_one_query(self):
        allow(self.notes, self.data["alice"], R)
        with CaptureQueriesContext(connection) as captured:
            allowed = self.alice.has_perm("winfs.read_winnode", self.notes)
        self.assertTrue(allowed)
        self.assertEqual(
            len(captured.captured_queries),
            1,
            "expected one SQL statement, got %s:\n%s"
            % (
                len(captured.captured_queries),
                "\n---\n".join(q["sql"] for q in captured.captured_queries),
            ),
        )
