"""Walks the edited web routes end to end with Flask's test client.

The database is replaced by do-nothing stand-ins, so this checks the wiring of the
routes (redirects, messages, what gets stored in the session), not the SQL.
"""
import io
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "app"))
os.environ.setdefault("SECRET_KEY", "test")
import _stubs  # noqa: E402,F401
import app as portal  # noqa: E402

MOBILE = "9000000001"


class DummyCursor:
    row = None

    def execute(self, *a, **k):
        pass

    def fetchone(self):
        return self.row

    def fetchall(self):
        return []

    def close(self):
        pass


class DummyConn:
    def __init__(self):
        self.cur = DummyCursor()
        self.committed = self.rolled_back = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.saved = {k: getattr(portal, k) for k in
                      ("UPLOAD_DIR", "SCHEME_DEADLINE", "ADMIN_PASSWORD", "get_db", "send_sms",
                       "check_otp", "issue_otp", "active_application", "create_application")}
        portal.UPLOAD_DIR = self.tmp
        portal.SCHEME_DEADLINE = datetime(2999, 1, 1)
        portal.ADMIN_PASSWORD = "pw"
        self.conn = DummyConn()
        portal.get_db = lambda: self.conn
        portal.send_sms = lambda *a, **k: None
        portal.issue_otp = lambda cur, mobile: ("123456", None)
        portal.check_otp = lambda cur, mobile, code: "ok" if code == "123456" else "invalid"
        portal.active_application = lambda cur, mobile: None
        portal.create_application = lambda cur, mobile, cleaned: (1, "SSP26000001")
        portal.app.config["TESTING"] = True
        self.client = portal.app.test_client()

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(portal, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers -----------------------------------------------------------
    def start_apply(self):
        self.client.get("/apply")
        with self.client.session_transaction() as s:
            answer = s["captcha_answer"]
        return self.client.post("/apply", data={"mobile": MOBILE, "captcha": str(answer)})

    def verified(self):
        self.start_apply()
        return self.client.post("/verify", data={"otp": "123456"})

    def fill_form(self):
        self.client.post("/form/1", data={"applicant_name": "Sewali Devi", "dob": "01/01/1950",
                                           "gender": "Female", "marital_status": "Widowed"})
        self.client.post("/form/2", data={"village": "Sonari Gaon", "block": "Sonari"})
        self.client.post("/form/3", data={"bank_account": "123456789012", "ifsc": "SBIN0003077"})

    def upload(self, name="proof.pdf", content=b"%PDF-1.4 x"):
        return self.client.post("/upload", data={"document": (io.BytesIO(content), name)},
                                content_type="multipart/form-data")

    def messages(self):
        with self.client.session_transaction() as s:
            return [m for _, m in s.get("_flashes", [])]

    # tests -------------------------------------------------------------
    def test_happy_path_from_otp_to_confirmation(self):
        r = self.start_apply()
        self.assertEqual((r.status_code, r.headers["Location"]), (302, "/verify"))
        r = self.client.post("/verify", data={"otp": "123456"})
        self.assertEqual(r.headers["Location"], "/form/1")
        self.fill_form()
        r = self.upload("Birth Certificate \u2014 final.PDF")
        self.assertEqual(r.headers["Location"], "/declaration")
        stored = os.listdir(self.tmp)
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0].startswith(MOBILE + "_") and stored[0].endswith(".pdf"))
        page = self.client.get("/declaration")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"cannot be submitted yet", page.data)
        self.assertIn("Birth Certificate".encode(), page.data)        # original name shown
        done = self.client.post("/declaration", data={})
        self.assertEqual(done.status_code, 200)
        self.assertIn(b"SSP26000001", done.data)
        self.assertTrue(self.conn.committed)

    def test_wrong_otp_stays_on_the_page(self):
        self.start_apply()
        r = self.client.post("/verify", data={"otp": "000000"})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Invalid OTP.", r.data)          # shown on the page, not redirected away

    def test_locked_otp_sends_the_person_back_to_ask_for_a_new_one(self):
        portal.check_otp = lambda cur, mobile, code: "locked"
        self.start_apply()
        r = self.client.post("/verify", data={"otp": "123456"})
        self.assertEqual(r.headers["Location"], "/apply")
        self.assertIn("Too many wrong attempts", self.messages()[-1])

    def test_otp_send_limit_is_shown(self):
        portal.issue_otp = lambda cur, mobile: (None, "Too many OTP requests for this mobile number.")
        self.client.get("/apply")
        with self.client.session_transaction() as s:
            answer = s["captcha_answer"]
        r = self.client.post("/apply", data={"mobile": MOBILE, "captcha": str(answer)})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.conn.rolled_back)

    def test_existing_application_is_reported_right_after_otp_not_after_the_form(self):
        portal.active_application = lambda cur, mobile: (5, "SSP26111111", "PENDING")
        self.start_apply()
        r = self.client.post("/verify", data={"otp": "123456"})
        self.assertEqual(r.headers["Location"], "/")
        self.assertIn("SSP26111111", self.messages()[-1])
        with self.client.session_transaction() as s:
            self.assertNotIn("verified_mobile", s)

    def test_bad_uploads_are_refused_without_storing_anything(self):
        self.verified()
        for name, content in (("virus.exe", b"x"), ("empty.pdf", b""),
                              ("big.pdf", b"x" * (portal.MAX_DOC_BYTES + 1))):
            r = self.upload(name, content)
            self.assertEqual(r.status_code, 200, name)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_preview_lists_every_problem_including_missing_ifsc(self):
        self.verified()
        self.client.post("/form/1", data={"applicant_name": "A", "dob": "01/01/1950",
                                           "gender": "Female", "marital_status": "Widowed"})
        self.client.post("/form/2", data={"village": "V", "block": "Sonari"})
        self.client.post("/form/3", data={"bank_account": "12345", "ifsc": ""})
        self.upload()
        page = self.client.get("/declaration").data
        self.assertIn(b"IFSC code is required", page)
        self.assertIn(b"9 to 18 digits", page)

    def test_preview_shows_an_existing_application(self):
        self.verified()
        self.fill_form()
        self.upload()
        portal.active_application = lambda cur, mobile: (5, "SSP26111111", "PENDING")
        page = self.client.get("/declaration").data
        self.assertIn(b"SSP26111111", page)
        self.assertNotIn(b"I agree to the above declaration", page)

    def test_officer_must_give_a_reason_and_it_is_recorded(self):
        self.client.post("/admin", data={"username": portal.ADMIN_USERNAME, "password": "pw"})
        r = self.client.post("/admin/approve/7", data={"note": "ok"})        # too short
        self.assertEqual(r.headers["Location"], "/admin/application/7")
        self.assertIn("reason", self.messages()[-1])
        self.assertFalse(self.conn.committed)
        self.conn.cur.row = ("SSP26000007",)
        self.client.post("/admin/reject/7", data={"note": "Age proof does not match date of birth"})
        self.assertTrue(self.conn.committed)
        self.assertIn("Application SSP26000007 rejected.", self.messages())

    def test_decisions_need_an_officer_login(self):
        self.assertEqual(self.client.post("/admin/approve/7", data={"note": "long enough"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
