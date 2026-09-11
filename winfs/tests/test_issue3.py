"""#3: final-core owner + OrderedFold registration beside the preserved matrix."""

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext

from trusts.apps import implementation_for_path
from trusts.core import Along

from winfs.apps import CANONICAL_BACKEND, FLOOR_MESSAGE, _load_implementation_config
from winfs.constants import FILE_READ_DATA, R
from winfs.evaluate import access_check, authorized_pks
from winfs.fixtures import allow, file, folder, principal
from winfs.models import WinAce, WinNode, WinVolume
from winfs.policy import MASKS, parent_along, register_explicit_dacl

from .support import PostgresTestCase


def _read_perm():
    ct = ContentType.objects.get_for_model(WinNode)
    perm, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='read_winnode',
        defaults={'name': 'WinFS read'},
    )
    return perm


class ExplicitDaclCoreProofs(PostgresTestCase):
    def setUp(self):
        super().setUp()
        self.alice = principal('core-alice', 'S-1-5-21-3000-1-1-1')
        self.stranger = principal('core-stranger', 'S-1-5-21-3000-1-1-2')
        self.vol = WinVolume.objects.create(name='core-vol')
        root = folder(self.vol, 'root', self.alice)
        self.notes = file(self.vol, 'notes.txt', self.alice, parent=root)
        allow(self.notes, self.alice, FILE_READ_DATA)
        self.read = _read_perm()
        self.registry = implementation_for_path(CANONICAL_BACKEND).configured_backend(
            CANONICAL_BACKEND,
        ).registry

    def test_ordered_fold_registers_explicit_dacl_shape(self):
        compiled = self.registry.strategies[0]
        self.assertIs(compiled.content_model, WinNode)
        self.assertIs(compiled.source_model, WinAce)
        self.assertEqual(compiled.order_attname, 'ace_order')
        self.assertEqual(compiled.mask_attname, 'access_mask')
        self.assertEqual(compiled.allow_value, 'allow')
        self.assertEqual(compiled.deny_value, 'deny')
        # WinAce.trustee uses db_column trustee_sid_id; OrderedFold SQL
        # currently emits attname trustee_id. Production remaining-bits
        # therefore stays on the preserved CTE until that seam is closed
        # in core. Registration itself is zero-SQL and live.
        self.assertEqual(compiled.trustee_attname, 'trustee_id')
        self.assertEqual(WinAce._meta.get_field('trustee').column, 'trustee_sid_id')
        self.assertTrue(callable(register_explicit_dacl))

    def test_access_check_object_decision_is_one_statement(self):
        with CaptureQueriesContext(connection) as captured:
            decision = access_check(self.alice.user, self.notes, R)
        self.assertTrue(decision.allowed)
        self.assertFalse(access_check(self.stranger.user, self.notes, R).allowed)
        statements = [
            q['sql'] for q in captured.captured_queries
            if not q['sql'].startswith('SAVEPOINT')
            and not q['sql'].startswith('RELEASE')
        ]
        self.assertEqual(len(statements), 1)

    def test_authorized_listing_is_one_statement(self):
        with CaptureQueriesContext(connection) as captured:
            listed = authorized_pks(
                self.alice.user, R, candidate_ids=[self.notes.pk],
            )
        self.assertEqual(listed, [self.notes.pk])
        statements = [
            q['sql'] for q in captured.captured_queries
            if not q['sql'].startswith('SAVEPOINT')
            and not q['sql'].startswith('RELEASE')
        ]
        self.assertEqual(len(statements), 1)

    def test_listing_applies_authorization_before_pagination(self):
        with CaptureQueriesContext(connection) as captured:
            page = authorized_pks(
                self.alice.user, R, candidate_ids=[self.notes.pk],
                limit=10, offset=0,
            )
        self.assertEqual(page, [self.notes.pk])
        sql = captured.captured_queries[-1]['sql'].lower()
        self.assertIn('limit', sql)
        self.assertLess(sql.find('limit'), sql.find('offset') + 1)

    def test_along_declaration_is_closed_and_not_on_the_fold_terminal(self):
        along = parent_along()
        self.assertIsInstance(along, Along)
        self.assertEqual(along.bound, 64)
        self.assertEqual(len(self.registry.strategies), 1)
        self.assertEqual(self.registry.records, ())

    def test_incompatible_core_fails_loud(self):
        import sys
        import types
        from unittest.mock import patch

        from django.core.exceptions import ImproperlyConfigured

        fake = types.ModuleType('trusts.apps')
        with patch.dict(sys.modules, {'trusts.apps': fake}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                _load_implementation_config()
        self.assertEqual(str(ctx.exception), FLOOR_MESSAGE)

    def test_mask_domain_covers_requested_bits(self):
        actions = [entry.action for entry in MASKS]
        self.assertEqual(actions, ['read', 'write', 'rc', 'wd'])
        self.assertEqual(self.read.codename, 'read_winnode')
