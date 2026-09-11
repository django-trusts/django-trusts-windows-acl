"""Invalid / unknown / NULL / negative source rows fail closed. Zero is legal."""

from django.db import connection

from winfs.constants import R, W
from winfs.evaluate import ERR_INVALID_SOURCE, access_check
from winfs.fixtures import allow
from winfs.models import WinAce

from .support import FixtureMixin, PostgresTestCase


class FailClosedSourceTests(FixtureMixin, PostgresTestCase):
    def _bypass(self, sql, params):
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL session_replication_role = replica")
            cursor.execute(sql, params)
            cursor.execute("SET LOCAL session_replication_role = origin")

    def test_zero_mask_is_legal_and_grants_nothing(self):
        ace = allow(self.notes, self.data["alice"], 0)
        self.assertEqual(ace.access_mask, 0)
        self.assert_deny(self.alice, self.notes, R)
        allow(self.notes, self.data["alice"], R)
        self.assert_allow(self.alice, self.notes, R)

    def test_negative_mask_fails_closed_before_applicability(self):
        allow(self.notes, self.data["alice"], R)
        ace = WinAce.objects.filter(
            descriptor=self.notes.security_descriptor,
        ).earliest("ace_order")
        self._bypass(
            "UPDATE win_ace SET access_mask = %s WHERE id = %s",
            [-1, ace.pk],
        )
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_mask_above_32_bit_fails_closed(self):
        allow(self.notes, self.data["alice"], R)
        ace = WinAce.objects.filter(
            descriptor=self.notes.security_descriptor,
        ).earliest("ace_order")
        self._bypass(
            "UPDATE win_ace SET access_mask = %s WHERE id = %s",
            [1 << 32, ace.pk],
        )
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_unknown_ace_type_fails_closed_before_allow(self):
        allow(self.notes, self.data["alice"], R)
        ace = WinAce.objects.filter(
            descriptor=self.notes.security_descriptor,
        ).earliest("ace_order")
        self._bypass(
            "UPDATE win_ace SET ace_type = %s WHERE id = %s",
            ["audit", ace.pk],
        )
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)

    def test_null_order_fails_closed(self):
        allow(self.notes, self.data["alice"], R)
        ace = WinAce.objects.filter(
            descriptor=self.notes.security_descriptor,
        ).earliest("ace_order")
        self._bypass(
            "UPDATE win_ace SET ace_order = NULL WHERE id = %s",
            [ace.pk],
        )
        decision = access_check(self.alice, self.notes, W)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_INVALID_SOURCE)
