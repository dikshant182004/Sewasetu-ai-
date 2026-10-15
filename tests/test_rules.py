"""Unit tests for the shared scheme rules (no database needed).

Run:  python3 -m unittest discover -s tests -v          (from the repo root)
Docker: docker compose run --rm --no-deps -v ./tests:/tests app \
            sh -c "cd /tests && PYTHONPATH=/app python -m unittest discover -s /tests -v"
"""
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "app"))
os.environ.setdefault("SECRET_KEY", "test")
import _stubs  # noqa: E402,F401
import app as portal  # noqa: E402

GOOD = dict(applicant_name="Sewali Devi", village="Sonari Gaon", block="Sonari",
            gender="Female", marital_status="Widowed", bank_account="123456789012",
            ifsc="SBIN0003077", dob="01/01/1950")


def dob_for(days_from_60th_birthday=0):
    t = portal.now_ist().date()
    d = t.replace(year=t.year - portal.MIN_AGE) + timedelta(days=days_from_60th_birthday)
    return d.strftime("%d/%m/%Y")


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.upload_dir = tempfile.mkdtemp()
        self._saved = (portal.UPLOAD_DIR, portal.SCHEME_DEADLINE)
        portal.UPLOAD_DIR = self.upload_dir
        portal.SCHEME_DEADLINE = datetime(2999, 1, 1)   # keep tests independent of today's date

    def tearDown(self):
        portal.UPLOAD_DIR, portal.SCHEME_DEADLINE = self._saved
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    def errs(self, doc="/x/9000000001_a.pdf", mobile=None, **over):
        return portal.validate_application({**GOOD, **over}, doc, mobile)[0]

    # --- age -------------------------------------------------------------
    def test_valid_application_passes(self):
        self.assertEqual(self.errs(), [])

    def test_exactly_60_today_is_accepted(self):
        self.assertEqual(self.errs(dob=dob_for(0)), [])

    def test_turning_60_tomorrow_is_rejected(self):
        self.assertTrue(any("60 years" in e for e in self.errs(dob=dob_for(1))))

    def test_implausible_age_is_rejected(self):
        self.assertTrue(any("does not look right" in e for e in self.errs(dob="01/01/1850")))

    def test_dob_must_be_dd_mm_yyyy(self):
        self.assertTrue(any("DD/MM/YYYY" in e for e in self.errs(dob="1950-01-01")))

    # --- required fields / lists ----------------------------------------
    def test_ifsc_is_required(self):
        self.assertIn("IFSC code is required", self.errs(ifsc=""))

    def test_ifsc_format_checked_after_cleaning(self):
        self.assertEqual(self.errs(ifsc="sbin 0003077"), [])
        self.assertTrue(any("IFSC must be" in e for e in self.errs(ifsc="dw_jnAWfnekfn12")))

    def test_gender_and_marital_status_are_required_and_from_the_list(self):
        self.assertIn("gender is required", self.errs(gender=""))
        self.assertIn("marital status is required", self.errs(marital_status=""))
        self.assertTrue(any("gender must be" in e for e in self.errs(gender="banana")))
        self.assertTrue(any("marital status must be" in e for e in self.errs(marital_status="x")))

    def test_bank_account_digits(self):
        self.assertTrue(any("9 to 18 digits" in e for e in self.errs(bank_account="12345")))

    def test_long_text_is_clamped_to_column_width(self):
        _, cleaned = portal.validate_application({**GOOD, "village": "v" * 500}, "/x", None)
        self.assertEqual(len(cleaned["village"]), 100)

    def test_closed_window_is_reported(self):
        portal.SCHEME_DEADLINE = datetime(2000, 1, 1)
        self.assertIn("the application window has closed", self.errs())

    # --- age-proof document ---------------------------------------------
    def test_missing_document_is_rejected(self):
        self.assertIn("age proof document is required", self.errs(doc=""))

    def test_document_must_be_a_file_the_server_stored_for_this_mobile(self):
        mobile = "9000000001"
        own = os.path.join(self.upload_dir, mobile + "_abc.pdf")
        other = os.path.join(self.upload_dir, "9111111111_abc.pdf")
        for p in (own, other):
            with open(p, "wb") as fh:
                fh.write(b"x")
        self.assertEqual(self.errs(doc=own, mobile=mobile), [])
        for bad in (other, "/etc/passwd", own + "/../9111111111_abc.pdf",
                    os.path.join(self.upload_dir, mobile + "_missing.pdf")):
            self.assertTrue(any("could not be found" in e for e in self.errs(doc=bad, mobile=mobile)),
                            bad)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.upload_dir = tempfile.mkdtemp()
        self._saved = (portal.UPLOAD_DIR, portal.STRICT_DOC_CHECK)
        portal.UPLOAD_DIR = self.upload_dir

    def tearDown(self):
        portal.UPLOAD_DIR, portal.STRICT_DOC_CHECK = self._saved
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    def test_stores_under_a_generated_name_and_is_accepted_by_the_rules(self):
        path, err = portal.store_age_proof("9000000001", "My Birth Certificate \u2014 final.PDF", b"%PDF-1.4")
        self.assertIsNone(err)
        self.assertTrue(os.path.basename(path).startswith("9000000001_"))
        self.assertTrue(path.endswith(".pdf"))
        self.assertNotIn("Birth", path)
        self.assertTrue(portal.doc_on_file("9000000001", path))

    def test_hostile_filename_cannot_choose_the_location(self):
        path, err = portal.store_age_proof("9000000001", "../../etc/cron.d/x.pdf", b"data")
        self.assertIsNone(err)
        self.assertEqual(os.path.dirname(path), self.upload_dir)

    def test_rejects_wrong_type_empty_and_oversized(self):
        self.assertIn("JPG, PNG or PDF", portal.store_age_proof("9000000001", "a.exe", b"x")[1])
        self.assertIn("JPG, PNG or PDF", portal.store_age_proof("9000000001", "noextension", b"x")[1])
        self.assertIn("empty", portal.store_age_proof("9000000001", "a.pdf", b"")[1])
        big = b"x" * (portal.MAX_DOC_BYTES + 1)
        self.assertIn("5 MB", portal.store_age_proof("9000000001", "a.pdf", big)[1])
        self.assertEqual(os.listdir(self.upload_dir), [])       # nothing left behind

    def test_strict_mode_checks_the_file_signature(self):
        portal.STRICT_DOC_CHECK = True
        self.assertIsNotNone(portal.store_age_proof("9000000001", "a.pdf", b"not a pdf")[1])
        self.assertIsNone(portal.store_age_proof("9000000001", "a.png", b"\x89PNG\r\n\x1a\nrest")[1])


class AcknowledgmentFontTests(unittest.TestCase):
    def test_latin_text_uses_the_builtin_font_and_other_scripts_do_not(self):
        self.assertFalse(portal._needs_indic_font("Sewali Gogoi"))
        self.assertFalse(portal._needs_indic_font("Caf\u00e9 Devi"))          # Latin-1 is fine
        self.assertTrue(portal._needs_indic_font("\u0985\u09ad\u09bf\u099c\u09bf\u09ce"))  # Bengali
        self.assertTrue(portal._needs_indic_font("\u09ae\u09be\u09a7\u09c1\u09f0\u09c0"))  # Assamese (ৰ)
        self.assertTrue(portal._needs_indic_font("Ram \u2014 Devi"))          # em dash is not Latin-1

    def test_font_lookup_returns_a_real_file_or_nothing(self):
        path = portal._indic_font_path()
        self.assertTrue(path is None or os.path.isfile(path))


if __name__ == "__main__":
    unittest.main()
