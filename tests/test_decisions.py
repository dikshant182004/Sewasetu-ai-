"""Officer decisions and case checks (no database)."""
import os
import sys
import unittest
from datetime import date, datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "app"))
os.environ.setdefault("SECRET_KEY", "test")
import _stubs  # noqa: E402,F401
import app as portal  # noqa: E402


class RecordingCursor:
    def __init__(self, updated_row=("SSP26000001",)):
        self.calls, self._row = [], updated_row

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self._row


class DecisionTests(unittest.TestCase):
    def test_a_reason_is_required_for_approve_and_reject(self):
        for status in ("APPROVED", "REJECTED"):
            for reason in ("", "   ", None, "ok"):
                cur = RecordingCursor()
                app_no, err = portal.decide_application(cur, 1, status, reason, "meera")
                self.assertIsNone(app_no)
                self.assertIn("reason", err)
                self.assertEqual(cur.calls, [], "nothing may be written without a reason")

    def test_decision_is_recorded_against_the_named_officer_with_the_reason(self):
        cur = RecordingCursor()
        app_no, err = portal.decide_application(cur, 7, "REJECTED",
                                                "Age proof does not match date of birth", "meera.das")
        self.assertEqual((app_no, err), ("SSP26000001", None))
        update, audit = cur.calls
        self.assertEqual(update[1][0], "REJECTED")
        self.assertEqual(update[1][2], "meera.das")                       # decided_by
        self.assertIn("status = 'PENDING'", update[0])                    # cannot re-decide
        self.assertEqual(audit[1][1:4], ("REJECTED", "admin:meera.das",
                                         "Age proof does not match date of birth"))

    def test_other_channels_are_noted_in_the_audit_trail(self):
        cur = RecordingCursor()
        portal.decide_application(cur, 7, "APPROVED", "Documents verified", "meera",
                                  channel="AI assistant")
        self.assertEqual(cur.calls[1][1][3], "Documents verified [via AI assistant]")

    def test_officer_mcp_decisions_are_attributed_to_officer_not_admin(self):
        cur = RecordingCursor()
        portal.decide_application(cur, 7, "APPROVED", "Documents verified", "meera.das",
                                  channel="officer-mcp")
        self.assertEqual(cur.calls[1][1][2], "officer:meera.das")
        self.assertIn("[via officer-mcp]", cur.calls[1][1][3])

    def test_long_input_fits_the_audit_columns(self):
        cur = RecordingCursor()
        portal.decide_application(cur, 7, "APPROVED", "r" * 900, "o" * 80, channel="AI assistant")
        actor, note = cur.calls[1][1][2], cur.calls[1][1][3]
        self.assertLessEqual(len(actor), 50)
        self.assertLessEqual(len(note), 500)

    def test_an_already_decided_case_is_refused_and_not_audited(self):
        cur = RecordingCursor(updated_row=None)
        app_no, err = portal.decide_application(cur, 7, "APPROVED", "Documents verified", "meera")
        self.assertIsNone(app_no)
        self.assertEqual(err, "Only a pending application can be decided.")
        self.assertEqual(len(cur.calls), 1)                               # just the guarded UPDATE

    def test_only_approve_or_reject_are_possible(self):
        with self.assertRaises(ValueError):
            portal.decide_application(RecordingCursor(), 1, "DEEMED_APPROVED", "reason here", "o")


class CaseCheckTests(unittest.TestCase):
    def test_turned_60_after_applying_is_still_below_age_for_that_application(self):
        # born 17 Oct 1966, applied 28 Sep 2026: 59 then, whatever today's date is
        c = portal.case_checks(date(1966, 10, 17), datetime(2026, 9, 28, 15, 30), "", "PENDING")
        self.assertEqual(c["age_at_submission"], 59)
        self.assertFalse(c["age_ok"])
        self.assertTrue(c["overdue"])
        self.assertEqual(c["deemed_due"], datetime(2026, 10, 13, 15, 30))

    def test_eligible_recent_application(self):
        now = portal.now_ist().replace(microsecond=0)
        c = portal.case_checks(date(1950, 1, 1), now, "", "PENDING")
        self.assertTrue(c["age_ok"])
        self.assertFalse(c["overdue"])
        self.assertEqual(c["deemed_due"], now + timedelta(days=portal.SLA_DAYS))

    def test_decided_cases_have_no_deadline(self):
        c = portal.case_checks(date(1950, 1, 1), datetime(2026, 1, 1), "", "APPROVED")
        self.assertIsNone(c["deemed_due"])
        self.assertFalse(c["overdue"])


if __name__ == "__main__":
    unittest.main()
