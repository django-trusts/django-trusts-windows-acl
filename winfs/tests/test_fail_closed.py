"""Invalid / unknown / NULL / negative source rows fail closed. Zero is legal."""

from django.db import connection

from winfs.constants import MASK_32, R, W
from winfs.evaluate import ERR_INVALID_SOURCE, access_check
from winfs.fixtures import allow
from winfs.models import WinAce

from .support import FixtureMixin, PostgresTransactionTestCase


class FailClosedSourceTests(FixtureMixin, PostgresTransactionTestCase):
    def _ace(self):
        allow(self.notes, self.data["alice"], R)
        return WinAce.objects.filter(
            descriptor=self.notes.security_descriptor,
        ).earliest("ace_order")

    def _restore_mask_constraint(self):
        WinAce.objects.filter(access_mask__lt=0).update(access_mask=0)
        WinAce.objects.filter(access_mask__gt=MASK_32).update(access_mask=0)
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace ADD CONSTRAINT win_ace_mask_32bit "
                "CHECK (access_mask >= 0 AND access_mask <= 4294967295)"
            )

    def _restore_type_constraint(self):
        WinAce.objects.exclude(ace_type__in=("allow", "deny")).update(
            ace_type="allow"
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace ADD CONSTRAINT win_ace_type "
                "CHECK (ace_type IN ('allow', 'deny'))"
            )

    def _restore_order_null(self):
        WinAce.objects.filter(ace_order__isnull=True).update(ace_order=0)
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace ALTER COLUMN ace_order SET NOT NULL"
            )

    def test_zero_mask_is_legal_and_grants_nothing(self):
        ace = allow(self.notes, self.data["alice"], 0)
        self.assertEqual(ace.access_mask, 0)
        self.assert_deny(self.alice, self.notes, R)
        allow(self.notes, self.data["alice"], R)
        self.assert_allow(self.alice, self.notes, R)

    def test_negative_mask_fails_closed_before_applicability(self):
        ace = self._ace()
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace DROP CONSTRAINT win_ace_mask_32bit"
            )
            cursor.execute(
                "UPDATE win_ace SET access_mask = %s WHERE id = %s",
                [-1, ace.pk],
            )
        self.addCleanup(self._restore_mask_constraint)
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_mask_above_32_bit_fails_closed(self):
        ace = self._ace()
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace DROP CONSTRAINT win_ace_mask_32bit"
            )
            cursor.execute(
                "UPDATE win_ace SET access_mask = %s WHERE id = %s",
                [1 << 32, ace.pk],
            )
        self.addCleanup(self._restore_mask_constraint)
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_unknown_ace_type_fails_closed_before_allow(self):
        ace = self._ace()
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE win_ace DROP CONSTRAINT win_ace_type")
            cursor.execute(
                "UPDATE win_ace SET ace_type = %s WHERE id = %s",
                ["audit", ace.pk],
            )
        self.addCleanup(self._restore_type_constraint)
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_null_order_fails_closed(self):
        ace = self._ace()
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE win_ace ALTER COLUMN ace_order DROP NOT NULL"
            )
            cursor.execute(
                "UPDATE win_ace SET ace_order = NULL WHERE id = %s",
                [ace.pk],
            )
        self.addCleanup(self._restore_order_null)
        decision = access_check(self.alice, self.notes, W)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)
