"""OTP limits (no database: a tiny in-memory cursor stands in for the otps table)."""
import os
import sys
import unittest
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "app"))
os.environ.setdefault("SECRET_KEY", "test")
import _stubs  # noqa: E402,F401
import app as portal  # noqa: E402


class FakeOtpCursor:
    def __init__(self):
        self.rows, self._result = [], None

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        if sql.startswith("SELECT count(*) FROM otps"):
            mobile, since = params
            self._result = (sum(1 for r in self.rows
                                if r["mobile"] == mobile and r["created_at"] > since),)
        elif sql.startswith("INSERT INTO otps"):
            mobile, code, created_at = params
            self.rows.append(dict(id=len(self.rows) + 1, mobile=mobile, code=code,
                                  created_at=created_at, attempts=0))
        elif sql.startswith("SELECT id, code, created_at, attempts FROM otps"):
            mine = [r for r in self.rows if r["mobile"] == params[0]]
            r = mine[-1] if mine else None
            self._result = (r["id"], r["code"], r["created_at"], r["attempts"]) if r else None
        elif sql.startswith("UPDATE otps SET attempts = attempts + 1"):
            next(r for r in self.rows if r["id"] == params[0])["attempts"] += 1
        else:
            raise AssertionError("unexpected SQL: " + sql)

    def fetchone(self):
        return self._result


class OtpTests(unittest.TestCase):
    M = "9000000001"

    def test_codes_are_six_digits_and_can_be_used(self):
        cur = FakeOtpCursor()
        code, err = portal.issue_otp(cur, self.M)
        self.assertIsNone(err)
        self.assertRegex(code, r"^\d{6}$")
        self.assertEqual(portal.check_otp(cur, self.M, code), "ok")

    def test_sending_is_limited_per_mobile_per_hour(self):
        cur = FakeOtpCursor()
        for _ in range(portal.OTP_MAX_SENDS_PER_HOUR):
            self.assertIsNone(portal.issue_otp(cur, self.M)[1])
        code, err = portal.issue_otp(cur, self.M)
        self.assertIsNone(code)
        self.assertIn("Too many OTP requests", err)
        self.assertIsNone(portal.issue_otp(cur, "9000000002")[1])       # other numbers unaffected

    def test_old_sends_stop_counting_after_an_hour(self):
        cur = FakeOtpCursor()
        for _ in range(portal.OTP_MAX_SENDS_PER_HOUR):
            portal.issue_otp(cur, self.M)
        for r in cur.rows:
            r["created_at"] -= timedelta(hours=2)
        self.assertIsNone(portal.issue_otp(cur, self.M)[1])

    def test_five_wrong_guesses_lock_the_code_even_for_the_right_answer(self):
        cur = FakeOtpCursor()
        code, _ = portal.issue_otp(cur, self.M)
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(portal.OTP_MAX_WRONG_GUESSES):
            self.assertEqual(portal.check_otp(cur, self.M, wrong), "invalid")
        self.assertEqual(portal.check_otp(cur, self.M, code), "locked")

    def test_a_fresh_code_starts_clean_after_a_lock(self):
        cur = FakeOtpCursor()
        code, _ = portal.issue_otp(cur, self.M)
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(portal.OTP_MAX_WRONG_GUESSES):
            portal.check_otp(cur, self.M, wrong)
        new_code, _ = portal.issue_otp(cur, self.M)
        self.assertEqual(portal.check_otp(cur, self.M, new_code), "ok")

    def test_expired_and_unknown(self):
        cur = FakeOtpCursor()
        code, _ = portal.issue_otp(cur, self.M)
        cur.rows[-1]["created_at"] -= timedelta(seconds=portal.OTP_VALIDITY_SECONDS + 5)
        self.assertEqual(portal.check_otp(cur, self.M, code), "expired")
        self.assertEqual(portal.check_otp(cur, "9999999999", "123456"), "invalid")


if __name__ == "__main__":
    unittest.main()
