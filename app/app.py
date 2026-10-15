# -*- coding: utf-8 -*-
"""
Sewa Setu - Old Age Pension Portal
Government of Purvanchal, Department of Social Welfare

Developed by: Netlink Infosolutions Pvt Ltd (2023)
Maintained in-house since 02/2026.
"""

import os
import io
import re
import glob
import random
import secrets
import hashlib
import configparser
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    """The portal's clock is Indian Standard Time regardless of where the server runs."""
    return datetime.now(IST).replace(tzinfo=None)

import requests
import psycopg2
import psycopg2.errors
from flask import (Flask, request, session, redirect, url_for, render_template,
                   flash, send_file, abort)
from fpdf import FPDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, "config", "app.ini"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or config.get("app", "secret_key")
# Two hours: elderly applicants fill the form slowly; the draft lives in the session.
app.config["PERMANENT_SESSION_LIFETIME"] = 7200
# Reject oversized request bodies before reading them (documents are capped at 5 MB).
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# An applicant may hold at most one application in these states at a time.
# WITHDRAWN and REJECTED applications do not block a fresh application.
ACTIVE_STATUSES = ("PENDING", "APPROVED", "DEEMED_APPROVED")

SMS_GATEWAY_URL = config.get("app", "sms_gateway_url")
OTP_VALIDITY_SECONDS = config.getint("app", "otp_validity_seconds")
UPLOAD_DIR = config.get("app", "upload_dir")
SCHEME_DEADLINE = datetime.strptime(config.get("pension", "scheme_deadline"),
                                    "%Y-%m-%d %H:%M")
MIN_AGE = config.getint("pension", "min_age")
SLA_DAYS = config.getint("pension", "sla_days")

BLOCKS = ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"]
GENDERS = ["Male", "Female", "Other"]
MARITAL_STATUSES = ["Married", "Unmarried", "Widowed"]
MAX_AGE = 110   # beyond this a date of birth is a typing error, not a person

import logging
_logdir = "/var/log/sewasetu"
try:
    os.makedirs(_logdir, exist_ok=True)
    _fh = logging.FileHandler(os.path.join(_logdir, "sewasetu-app.log"))
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s in app: %(message)s"))
    app.logger.addHandler(_fh)
    app.logger.setLevel(logging.INFO)
except Exception:
    pass


def get_db():
    return psycopg2.connect(
        host=config.get("database", "host"),
        port=config.get("database", "port"),
        dbname=config.get("database", "name"),
        user=config.get("database", "user"),
        password=config.get("database", "password"),
    )


def sanitize(value, maxlen=100):
    # Trim whitespace and cap at the column width, counting characters (not
    # bytes) so Assamese/Bangla names are stored intact.
    if value is None:
        return ""
    return value.strip()[:maxlen]


def hash_password(p):
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def send_sms(mobile, text):
    try:
        requests.post(SMS_GATEWAY_URL + "/api/send",
                      json={"to": mobile, "text": text}, timeout=5)
    except Exception as e:
        app.logger.error("sms gateway error: %s" % e)


def deadline_remaining():
    delta = SCHEME_DEADLINE - now_ist()
    if delta.total_seconds() <= 0:
        return None
    return int(delta.total_seconds() // 3600)


def new_application_no():
    return "SSP" + now_ist().strftime("%y") + str(random.randint(100000, 999999))


def write_audit(cur, app_id, action, actor, note=""):
    cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (app_id, action, actor, note, now_ist()))


# ---------------------------------------------------------------------------
# One-time passwords: shared by the web form and the OAuth sign-in.
# Limits are deliberately generous for real users but stop two abuses: flooding
# someone's phone with codes, and guessing a 6-digit code.
# ---------------------------------------------------------------------------
OTP_MAX_SENDS_PER_HOUR = 10     # per mobile number
OTP_MAX_WRONG_GUESSES = 5       # per code; asking for a fresh code starts again
OTP_MESSAGES = {
    "invalid": "Invalid OTP.",
    "expired": "OTP expired. Please request a new OTP.",
    "locked": "Too many wrong attempts. Please request a new OTP.",
}


def issue_otp(cur, mobile):
    """Create an OTP for `mobile`. Returns (code, error); the caller sends the SMS and commits."""
    cur.execute("SELECT count(*) FROM otps WHERE mobile = %s AND created_at > %s",
                (mobile, now_ist() - timedelta(hours=1)))
    if cur.fetchone()[0] >= OTP_MAX_SENDS_PER_HOUR:
        return None, "Too many OTP requests for this mobile number. Please try again in an hour."
    code = "%06d" % secrets.randbelow(1000000)
    cur.execute("INSERT INTO otps (mobile, code, created_at, attempts) VALUES (%s, %s, %s, 0)",
                (mobile, code, now_ist()))
    return code, None


def check_otp(cur, mobile, code):
    """Check `code` against the latest OTP for `mobile`.

    Returns "ok", "invalid", "expired" or "locked". The caller commits (a wrong
    guess is counted in the database).
    """
    cur.execute("SELECT id, code, created_at, attempts FROM otps WHERE mobile = %s "
                "ORDER BY id DESC LIMIT 1", (mobile,))
    row = cur.fetchone()
    if not row:
        return "invalid"
    otp_id, real_code, created_at, attempts = row
    if attempts >= OTP_MAX_WRONG_GUESSES:
        return "locked"
    if (now_ist() - created_at).total_seconds() > OTP_VALIDITY_SECONDS:
        return "expired"
    if secrets.compare_digest(real_code or "", code or ""):
        return "ok"
    cur.execute("UPDATE otps SET attempts = attempts + 1 WHERE id = %s", (otp_id,))
    return "invalid"


# ---------------------------------------------------------------------------
# Scheme rules: the single source of truth for what an application must satisfy.
# Every channel that creates an application (the web form, any API, any batch
# import) MUST go through validate_application() and create_application() so
# that no channel admits an application another channel would refuse.
# ---------------------------------------------------------------------------

def parse_dob(raw):
    try:
        return datetime.strptime((raw or "").strip(), "%d/%m/%Y").date()
    except ValueError:
        return None


def age_on(dob, on):
    return on.year - dob.year - ((on.month, on.day) < (dob.month, dob.day))


def doc_on_file(mobile, doc_path):
    """True only for a real file inside the upload directory that belongs to this mobile.

    The document path is never taken on trust from a client: it must be one this
    server stored for this applicant (see store_age_proof).
    """
    if not doc_path or not mobile:
        return False
    real = os.path.realpath(doc_path)
    root = os.path.realpath(UPLOAD_DIR)
    return (real.startswith(root + os.sep)
            and os.path.basename(real).startswith(mobile + "_")
            and os.path.isfile(real))


def validate_application(data, doc_path, mobile=None):
    """Validate a complete application. Returns (errors, cleaned).

    `errors` is a list of plain-language problems (empty when valid);
    `cleaned` holds the normalised values ready for create_application().
    When `mobile` is given the age-proof document must also be a file this server
    stored for that mobile (every real channel passes it).
    """
    errors = []
    cleaned = {
        "applicant_name": sanitize(data.get("applicant_name")),
        "village": sanitize(data.get("village")),
        "block": (data.get("block") or "").strip(),
        "gender": (data.get("gender") or "").strip(),
        "marital_status": (data.get("marital_status") or "").strip(),
        "husband_name": sanitize(data.get("husband_name")),
        "husband_employer": "",  # no longer collected (not a scheme requirement)
        "bank_account": re.sub(r"[\s-]", "", data.get("bank_account") or ""),
        "ifsc": re.sub(r"[\s-]", "", (data.get("ifsc") or "")).upper(),
        "doc_path": doc_path or "",
        "dob": None,
    }
    for label, key in (("full name", "applicant_name"), ("village", "village"),
                       ("block", "block"), ("gender", "gender"),
                       ("marital status", "marital_status"),
                       ("bank account", "bank_account"), ("IFSC code", "ifsc")):
        if not cleaned[key]:
            errors.append("%s is required" % label)
    if cleaned["block"] and cleaned["block"] not in BLOCKS:
        errors.append("block must be one of: " + ", ".join(BLOCKS))
    if cleaned["gender"] and cleaned["gender"] not in GENDERS:
        errors.append("gender must be one of: " + ", ".join(GENDERS))
    if cleaned["marital_status"] and cleaned["marital_status"] not in MARITAL_STATUSES:
        errors.append("marital status must be one of: " + ", ".join(MARITAL_STATUSES))
    if cleaned["bank_account"] and not re.fullmatch(r"\d{9,18}", cleaned["bank_account"]):
        errors.append("bank account number must be 9 to 18 digits")
    if cleaned["ifsc"] and not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned["ifsc"]):
        errors.append("IFSC must be 11 characters, e.g. SBIN0003077")
    dob = parse_dob(data.get("dob"))
    if dob is None:
        errors.append("date of birth must be given as DD/MM/YYYY")
    else:
        cleaned["dob"] = dob
        years = age_on(dob, now_ist().date())
        if years < MIN_AGE:
            errors.append("applicant must be %d years of age or above" % MIN_AGE)
        elif years > MAX_AGE:
            errors.append("date of birth does not look right (age over %d)" % MAX_AGE)
    if not cleaned["doc_path"]:
        errors.append("age proof document is required")
    elif mobile is not None and not doc_on_file(mobile, cleaned["doc_path"]):
        errors.append("age proof document could not be found; please upload it again")
    if now_ist() > SCHEME_DEADLINE:
        errors.append("the application window has closed")
    return errors, cleaned


ALLOWED_DOC_TYPES = {"pdf": b"%PDF-", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
                     "png": b"\x89PNG\r\n\x1a\n"}
MAX_DOC_BYTES = 5 * 1024 * 1024
# Off by default: also require the file's first bytes to match its extension.
STRICT_DOC_CHECK = os.environ.get("STRICT_DOC_CHECK", "0") == "1"


def store_age_proof(mobile, filename, content):
    """Validate and store an age-proof document. Returns (path, error).

    The one place documents are accepted, so every channel applies the same rules.
    The stored name is generated here (never derived from the uploaded name), so a
    hostile filename cannot influence where the file goes.
    """
    ext = os.path.splitext(filename or "")[1].lstrip(".").lower()
    if ext not in ALLOWED_DOC_TYPES:
        return None, "Please upload a JPG, PNG or PDF file."
    if not content:
        return None, "The file is empty. Please choose the document again."
    if len(content) > MAX_DOC_BYTES:
        return None, "File is larger than 5 MB. Please upload a smaller file."
    if STRICT_DOC_CHECK and not content.startswith(ALLOWED_DOC_TYPES[ext]):
        return None, "The file does not look like a real %s file." % ext.upper()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, "%s_%s.%s" % (mobile, secrets.token_hex(6), ext))
    with open(path, "wb") as out:
        out.write(content)
    return path, None


def active_application(cur, mobile):
    """The applicant's current live application, if any."""
    cur.execute("SELECT id, application_no, status FROM applications "
                "WHERE mobile = %s AND status IN %s "
                "ORDER BY submitted_at DESC LIMIT 1", (mobile, ACTIVE_STATUSES))
    return cur.fetchone()


class DuplicateApplication(Exception):
    """The mobile number already holds a live application (database-level guarantee)."""


def duplicate_message(existing):
    return ("Application %s (%s) already exists for this mobile number. A pending "
            "application can be withdrawn from the status portal if you need to "
            "apply afresh." % (existing[1], existing[2]))


def create_application(cur, mobile, cleaned):
    """Insert a validated application; ensure the status-portal account exists.

    The caller commits. Returns (id, application_no). Raises DuplicateApplication if
    the mobile already holds a live application, even when two submissions race.
    Application numbers are random, so a (rare) collision with an existing number is
    retried with a fresh one instead of creating two applications with the same number.
    """
    new_id = app_no = None
    for _ in range(8):
        app_no = new_application_no()
        cur.execute("SAVEPOINT create_application")
        try:
            cur.execute(
                """INSERT INTO applications
                   (application_no, applicant_name, mobile, dob, gender, marital_status,
                    husband_name, husband_employer, village, block, bank_account, ifsc,
                    doc_path, status, submitted_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s)
                   RETURNING id""",
                (app_no, cleaned["applicant_name"], mobile, cleaned["dob"], cleaned["gender"],
                 cleaned["marital_status"], cleaned["husband_name"], cleaned["husband_employer"],
                 cleaned["village"], cleaned["block"], cleaned["bank_account"], cleaned["ifsc"],
                 cleaned["doc_path"], now_ist()))
            new_id = cur.fetchone()[0]
            cur.execute("RELEASE SAVEPOINT create_application")
            break
        except psycopg2.errors.UniqueViolation as exc:
            cur.execute("ROLLBACK TO SAVEPOINT create_application")
            if "one_active_per_mobile" in (getattr(exc.diag, "constraint_name", "") or ""):
                raise DuplicateApplication()
            # otherwise the application number collided: loop and draw another
    if new_id is None:
        raise RuntimeError("could not allocate a unique application number")

    # status portal account; password is DOB as DDMMYYYY per dept. circular
    portal_pass = cleaned["dob"].strftime("%d%m%Y")
    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO portal_users (mobile, password_hash) VALUES (%s,%s)",
                    (mobile, hash_password(portal_pass)))
    write_audit(cur, new_id, "SUBMIT", "applicant:%s" % mobile)
    return new_id, app_no


MIN_REASON_CHARS = 5


def case_checks(dob, submitted_at, doc_path, status):
    """What an officer needs to judge a case, computed from the stored record."""
    if dob is None or submitted_at is None:
        return {"age_at_submission": None, "age_today": None, "age_ok": False,
                "pending": status == "PENDING", "deemed_due": None, "overdue": False}
    age_then = age_on(dob, submitted_at.date())
    return {
        "age_at_submission": age_then,
        "age_today": age_on(dob, now_ist().date()),
        "age_ok": age_then >= MIN_AGE,       # eligibility is judged at application, not today
        "pending": status == "PENDING",
        "deemed_due": (submitted_at + timedelta(days=SLA_DAYS)) if status == "PENDING" else None,
        "overdue": status == "PENDING" and now_ist() > submitted_at + timedelta(days=SLA_DAYS),
    }


def decide_application(cur, app_id, new_status, reason, officer, channel="portal"):
    """Approve or reject a PENDING application on behalf of a named officer.

    The one place a decision is made, so every channel records the same things: who
    decided, when, and why. Returns (application_no, error); the caller commits.
    `channel` is noted in the audit trail for anything other than the web portal.
    """
    if new_status not in ("APPROVED", "REJECTED"):
        raise ValueError("new_status must be APPROVED or REJECTED")
    reason = sanitize(reason, 400)             # audit note column is 500 characters
    if len(reason) < MIN_REASON_CHARS:
        return None, ("Please give a reason (at least %d characters); it is recorded "
                      "against your name." % MIN_REASON_CHARS)
    officer = sanitize(officer, 40)            # audit actor column is 50 characters
    note = reason if channel == "portal" else "%s [via %s]" % (reason, channel)
    cur.execute("UPDATE applications SET status = %s, decided_at = %s, decided_by = %s "
                "WHERE id = %s AND status = 'PENDING' RETURNING application_no",
                (new_status, now_ist(), officer, app_id))
    row = cur.fetchone()
    if not row:
        return None, "Only a pending application can be decided."
    write_audit(cur, app_id, new_status, "admin:%s" % officer, note)
    return row[0], None


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", hours_left=deadline_remaining())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/__gateway/", defaults={"subpath": ""})
@app.route("/__gateway/<path:subpath>")
def gateway_proxy(subpath):
    # Convenience proxy to the internal SMS gateway, so the OTP inbox is reachable
    # on the main site without opening a second port on the host. The gateway
    # itself runs only on the internal network.
    try:
        r = requests.get(SMS_GATEWAY_URL + "/" + subpath,
                         params=request.args, timeout=5)
        return (r.content, r.status_code,
                {"Content-Type": r.headers.get("Content-Type", "text/html")})
    except Exception as e:
        return ("SMS gateway unreachable: %s" % e, 502)


# ---------------------------------------------------------------------------
# Application flow: mobile -> OTP -> form steps -> upload -> declaration
# ---------------------------------------------------------------------------

@app.route("/apply", methods=["GET", "POST"])
def apply():
    if deadline_remaining() is None:
        flash("The application window for this scheme has closed.")
        return redirect(url_for("index"))
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        captcha = request.form.get("captcha", "")
        try:
            captcha_ok = int(captcha) == session.get("captcha_answer")
        except (ValueError, TypeError):
            captcha_ok = False
        if not captcha_ok:
            flash("Security check answer is incorrect. Please try again.")
            return render_template("apply.html", captcha_q=make_captcha())
        if len(mobile) != 10 or not mobile.isdigit():
            flash("Please enter a valid 10-digit mobile number.")
            return render_template("apply.html", captcha_q=make_captcha())
        conn = get_db()
        cur = conn.cursor()
        code, error = issue_otp(cur, mobile)
        if error:
            conn.rollback()
            cur.close(); conn.close()
            flash(error)
            return render_template("apply.html", captcha_q=make_captcha())
        conn.commit()
        cur.close(); conn.close()
        send_sms(mobile, "Your Sewa Setu OTP is %s. Valid for 5 minutes." % code)
        session.permanent = True
        session["apply_mobile"] = mobile
        return redirect(url_for("verify"))
    return render_template("apply.html", captcha_q=make_captcha())


def make_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    session["captcha_answer"] = a + b
    return "%d + %d" % (a, b)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    mobile = session.get("apply_mobile")
    if not mobile:
        return redirect(url_for("apply"))
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        conn = get_db()
        cur = conn.cursor()
        result = check_otp(cur, mobile, code)
        conn.commit()               # a wrong guess is counted
        cur.close(); conn.close()
        if result != "ok":
            app.logger.warning("otp %s mobile=%s" % (result, mobile))
            flash(OTP_MESSAGES[result])
            if result in ("expired", "locked"):
                return redirect(url_for("apply"))
        else:
            session["verified_mobile"] = mobile
            conn = get_db()
            cur = conn.cursor()
            existing = active_application(cur, mobile)
            cur.close(); conn.close()
            if existing:
                # no point filling in a form that cannot be submitted
                session.pop("verified_mobile", None)
                flash(duplicate_message(existing))
                return redirect(url_for("index"))
            return redirect(url_for("form_step", step=1))
    return render_template("verify.html", mobile=mobile)


@app.route("/form/<int:step>", methods=["GET", "POST"])
def form_step(step):
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if step not in (1, 2, 3):
        abort(404)
    if request.method == "POST":
        data = session.get("form_data", {})
        for k, v in request.form.items():
            data[k] = v
        session["form_data"] = data
        if step < 3:
            return redirect(url_for("form_step", step=step + 1))
        return redirect(url_for("upload"))
    return render_template("form_step%d.html" % step,
                           data=session.get("form_data", {}), blocks=BLOCKS)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        f = request.files.get("document")
        if f is None or f.filename == "":
            flash("Please choose a file to upload (JPG, PNG or PDF, up to 5 MB).")
            return render_template("upload.html")
        mobile = session["verified_mobile"]
        path, error = store_age_proof(mobile, f.filename, f.read())
        if error:
            flash(error)
            return render_template("upload.html")
        old = session.get("doc_path")
        if old and old != path and doc_on_file(mobile, old):
            try:
                os.remove(old)          # replaced by the new upload
            except OSError:
                pass
        session["doc_path"] = path
        session["doc_name"] = os.path.basename(f.filename.replace("\\", "/"))[:80]   # display only
        return redirect(url_for("declaration"))
    return render_template("upload.html")


@app.errorhandler(413)
def request_too_large(_error):
    flash("File is larger than 5 MB. Please upload a smaller file.")
    return redirect(url_for("upload"))


@app.route("/declaration", methods=["GET", "POST"])
def declaration():
    if not session.get("verified_mobile"):
        flash("Session expired. Please verify your mobile number again.")
        return redirect(url_for("apply"))
    if request.method == "POST":
        return handle_submission()
    # Preview everything before the applicant commits.
    data = session.get("form_data", {})
    mobile = session["verified_mobile"]
    errors, _ = validate_application(data, session.get("doc_path", ""), mobile)
    conn = get_db()
    cur = conn.cursor()
    existing = active_application(cur, mobile)
    cur.close(); conn.close()
    if existing:
        errors.append(duplicate_message(existing))
    return render_template("declaration.html", data=data, errors=errors,
                           doc_name=session.get("doc_name")
                           or os.path.basename(session.get("doc_path", "") or ""))


def handle_submission():
    mobile = session.get("verified_mobile")
    data = session.get("form_data", {})
    errors, cleaned = validate_application(data, session.get("doc_path", ""), mobile)
    if errors:
        flash("Please correct the following before submitting: " + "; ".join(errors) + ".")
        return redirect(url_for("form_step", step=1))

    conn = get_db()
    cur = conn.cursor()
    existing = active_application(cur, mobile)
    if existing:
        cur.close(); conn.close()
        flash(duplicate_message(existing))
        return redirect(url_for("index"))

    try:
        new_id, app_no = create_application(cur, mobile, cleaned)
    except DuplicateApplication:
        # lost a race with a simultaneous submission for the same mobile
        conn.rollback()
        existing = active_application(cur, mobile)
        cur.close(); conn.close()
        flash(duplicate_message(existing) if existing else
              "An application already exists for this mobile number.")
        return redirect(url_for("index"))
    conn.commit()
    cur.close(); conn.close()

    session.pop("form_data", None)
    session.pop("doc_path", None)
    session.pop("doc_name", None)
    session.pop("verified_mobile", None)
    # The applicant just proved ownership of this mobile by OTP, so let them
    # see their application and download the acknowledgment without a second login.
    session["logged_in"] = True
    session["portal_mobile"] = mobile
    send_sms(mobile, "Sewa Setu: application %s received. Track at the status portal "
                     "with mobile no. and password (DOB as DDMMYYYY)." % app_no)
    return render_template("confirmation.html", app_no=app_no, app_id=new_id)


def _needs_indic_font(text):
    """True when the built-in PDF font (Latin-1 only) cannot draw this text."""
    try:
        text.encode("latin-1")
        return False
    except UnicodeEncodeError:
        return True


def _indic_font_path():
    """A TrueType font that covers Bengali/Assamese script, or None.

    Looks in app/fonts/ first (drop a .ttf there to override), then for the Noto
    font the Docker image installs (fonts-noto-core).
    """
    patterns = [os.path.join(BASE_DIR, "fonts", "*.ttf"),
                "/usr/share/fonts/**/NotoSansBengali-Regular.ttf",
                "/usr/share/fonts/**/NotoSansBengali*.ttf",
                "/usr/share/fonts/**/*Bengali*.ttf",
                "/usr/share/fonts/**/*Assamese*.ttf"]
    for pattern in patterns:
        found = sorted(glob.glob(pattern, recursive=True))
        if found:
            return found[0]
    return None


def generate_acknowledgment(cur, app_id):
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, submitted_at, status FROM applications WHERE id = %s",
                (app_id,))
    row = cur.fetchone()
    pdf = FPDF()
    pdf.add_page()
    indic = _indic_font_path()
    if indic:
        try:
            pdf.add_font("Indic", "", indic)
        except Exception as exc:
            app.logger.error("acknowledgment: cannot load font %s: %s" % (indic, exc))
            indic = None
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "GOVERNMENT OF PURVANCHAL", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, "Department of Social Welfare", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 8, "Old Age Pension Scheme - Acknowledgment", new_x="LMARGIN", new_y="NEXT",
             align="C")
    pdf.ln(4)
    # letterhead rules
    pdf.line(10, 12, 200, 12)
    pdf.line(10, 282, 200, 282)
    labels = ["Application No", "Applicant Name", "Mobile", "Date of Birth",
              "Village", "Block", "Bank Account", "IFSC", "Submitted At", "Status"]
    pdf.set_font("Helvetica", "", 10)
    for label, val in zip(labels, row):
        text = "" if val is None else str(val)
        pdf.cell(60, 8, label, border=1)
        if not _needs_indic_font(text):
            pdf.cell(0, 8, text, border=1, new_x="LMARGIN", new_y="NEXT")
            continue
        # Bengali / Assamese (or any non-Latin-1) text: draw it in a font that has the
        # glyphs, with text shaping so vowel signs and conjuncts are placed correctly.
        try:
            if not indic:
                raise RuntimeError("no font installed for non-Latin text")
            pdf.set_font("Indic", "", 10)
            try:
                pdf.set_text_shaping(True)
            except Exception as exc:        # shaping library missing: still readable
                app.logger.warning("acknowledgment: text shaping unavailable: %s" % exc)
            pdf.cell(0, 8, text, border=1, new_x="LMARGIN", new_y="NEXT")
        except Exception as exc:
            app.logger.warning("acknowledgment: could not draw %r: %s" % (label, exc))
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 8, text.encode("latin-1", "replace").decode("latin-1"), border=1,
                     new_x="LMARGIN", new_y="NEXT")
        finally:
            try:
                pdf.set_text_shaping(False)
            except Exception:
                pass
            pdf.set_font("Helvetica", "", 10)
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(0, 5, "This is a computer generated acknowledgment. Processing SLA "
                         "as per the Purvanchal Right to Public Services Act applies.")
    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# Status portal (citizen login)
# ---------------------------------------------------------------------------

@app.route("/status", methods=["GET", "POST"])
def status_login():
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM portal_users WHERE mobile = %s", (mobile,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if row and row[0] == hash_password(password):
            session["logged_in"] = True
            session["portal_mobile"] = mobile
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM applications WHERE mobile = %s "
                        "ORDER BY submitted_at DESC LIMIT 1", (mobile,))
            r = cur.fetchone()
            cur.close(); conn.close()
            if r:
                return redirect(url_for("view_application", app_id=r[0]))
            flash("No application found for this mobile number.")
            return redirect(url_for("status_login"))
        flash("Mobile number or password is incorrect. The password is your date of "
              "birth as DDMMYYYY.")
    return render_template("status_login.html")


@app.route("/application/<int:app_id>")
def view_application(app_id):
    if not session.get("logged_in"):
        flash("Please login to view application status.")
        return redirect(url_for("status_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, village, block, "
                "bank_account, ifsc, status, submitted_at, decided_at "
                "FROM applications WHERE id = %s AND mobile = %s",
                (app_id, session.get("portal_mobile")))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        abort(404)
    reason = None
    if row[8] == "REJECTED":
        cur.execute("SELECT note FROM audit_log WHERE application_id = %s AND action = 'REJECTED' "
                    "ORDER BY at DESC LIMIT 1", (app_id,))
        r = cur.fetchone()
        reason = r[0] if r else None
    cur.close(); conn.close()
    checks = case_checks(row[3], row[9], "", row[8])
    # the automatic-approval date only applies to a case the age rule lets through
    due = checks["deemed_due"] if checks["age_ok"] else None
    return render_template("application.html", a=row, app_id=app_id, due=due,
                           reason=reason, sla=SLA_DAYS)


@app.route("/application/<int:app_id>/withdraw", methods=["POST"])
def withdraw_application(app_id):
    """Applicant withdraws their own PENDING application so they can apply afresh."""
    if not session.get("logged_in") or not session.get("portal_mobile"):
        flash("Please login to manage your application.")
        return redirect(url_for("status_login"))
    mobile = session["portal_mobile"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = 'WITHDRAWN', decided_at = %s, "
                "decided_by = 'APPLICANT' WHERE id = %s AND mobile = %s "
                "AND status = 'PENDING' RETURNING application_no",
                (now_ist(), app_id, mobile))
    row = cur.fetchone()
    if row:
        write_audit(cur, app_id, "WITHDRAW", "applicant:%s" % mobile)
        conn.commit()
        flash("Application %s has been withdrawn. You may submit a new application; "
              "a new application starts a fresh %d-day processing period." % (row[0], SLA_DAYS))
    else:
        flash("Only a pending application can be withdrawn.")
    cur.close(); conn.close()
    return redirect(url_for("view_application", app_id=app_id))


@app.route("/ack/<int:app_id>.pdf")
def ack_pdf(app_id):
    if not session.get("admin"):
        conn0 = get_db(); c0 = conn0.cursor()
        c0.execute("SELECT 1 FROM applications WHERE id = %s AND mobile = %s",
                   (app_id, session.get("portal_mobile")))
        owned = c0.fetchone()
        c0.close(); conn0.close()
        if not owned:
            abort(403)
    path = os.path.join(UPLOAD_DIR, "ack", "%d.pdf" % app_id)
    if not os.path.exists(path):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM applications WHERE id = %s", (app_id,))
        if not cur.fetchone():
            cur.close(); conn.close()
            abort(404)
        data = generate_acknowledgment(cur, app_id)
        cur.close(); conn.close()
        return send_file(io.BytesIO(data), mimetype="application/pdf")
    return send_file(path, mimetype="application/pdf")


@app.route("/status/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        mobile = request.form.get("mobile", "")
        conn = get_db()
        cur = conn.cursor()
        # fetch account for reset
        cur.execute("SELECT mobile FROM portal_users WHERE mobile = %s", (mobile,))
        row = cur.fetchone()
        if row:
            cur.execute("SELECT dob FROM applications WHERE mobile = %s LIMIT 1", (mobile,))
            r2 = cur.fetchone()
            if r2:
                newpass = r2[0].strftime("%d%m%Y")
                cur.execute("UPDATE portal_users SET password_hash = %s WHERE mobile = %s",
                            (hash_password(newpass), row[0]))
                conn.commit()
                send_sms(row[0], "Sewa Setu: your password has been reset to your "
                                 "date of birth (DDMMYYYY).")
        cur.close(); conn.close()
        flash("If the mobile number exists, the password has been reset and sent by SMS.")
    return render_template("reset.html")


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (ADMIN_PASSWORD and request.form.get("username") == ADMIN_USERNAME and
                request.form.get("password") == ADMIN_PASSWORD):
            session["logged_in"] = True
            session["admin"] = True
            session["admin_user"] = ADMIN_USERNAME
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials.")
    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, count(*) FROM applications GROUP BY status")
    by_status = cur.fetchall()
    cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING' "
                "AND submitted_at < %s", (now_ist() - timedelta(days=SLA_DAYS),))
    overdue = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING' "
                "AND submitted_at < %s AND "
                "COALESCE(date_part('year', age(submitted_at::date, dob)), 0) < %s",
                (now_ist() - timedelta(days=SLA_DAYS), MIN_AGE))
    held = cur.fetchone()[0]
    cur.execute("SELECT block, count(*) FROM applications WHERE status = 'PENDING' "
                "GROUP BY block ORDER BY count(*) DESC")
    by_block = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_dashboard.html", by_status=by_status,
                           overdue=overdue, held=held, by_block=by_block, sla=SLA_DAYS,
                           min_age=MIN_AGE)


@app.route("/admin/applications")
def admin_list():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    status = request.args.get("status", "PENDING")
    mobile = request.args.get("mobile", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    conn = get_db()
    cur = conn.cursor()
    # last column: was the applicant below the minimum age on the day they applied?
    under_age = ("COALESCE(date_part('year', age(submitted_at::date, dob)), 0) < %d" % MIN_AGE)
    if mobile:
        cur.execute("SELECT id, application_no, applicant_name, mobile, block, status, "
                    "submitted_at, " + under_age + " FROM applications WHERE mobile = %s "
                    "ORDER BY submitted_at ASC", (mobile,))
        status = "mobile %s" % mobile
    else:
        cur.execute("SELECT id, application_no, applicant_name, mobile, block, status, "
                    "submitted_at, " + under_age + " FROM applications WHERE status = %s "
                    "ORDER BY submitted_at ASC LIMIT 50 OFFSET %s",
                    (status, (page - 1) * 50))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_list.html", rows=rows, status=status, page=page, mobile=mobile)


@app.route("/admin/application/<int:app_id>")
def admin_view(app_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, dob, gender, "
                "marital_status, village, block, bank_account, ifsc, doc_path, "
                "status, submitted_at, decided_at, decided_by "
                "FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        abort(404)
    cur.execute("SELECT at, action, actor, note FROM audit_log "
                "WHERE application_id = %s ORDER BY at ASC", (app_id,))
    audit = cur.fetchall()
    cur.close(); conn.close()
    checks = case_checks(row[3], row[12], row[10], row[11])
    return render_template("admin_view.html", a=row, app_id=app_id, audit=audit,
                           checks=checks, min_age=MIN_AGE, sla=SLA_DAYS,
                           doc_available=doc_on_file(row[2], row[10]))


@app.route("/admin/document/<int:app_id>")
def admin_document(app_id):
    """Let the deciding officer see the age proof the applicant uploaded."""
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT mobile, doc_path FROM applications WHERE id = %s", (app_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row or not doc_on_file(row[0], row[1]):
        abort(404)
    resp = send_file(row[1])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _admin_decide(app_id, new_status, reason):
    """Approve/reject a PENDING application from the web portal."""
    if not session.get("admin"):
        abort(403)
    officer = session.get("admin_user", ADMIN_USERNAME)
    conn = get_db()
    cur = conn.cursor()
    app_no, error = decide_application(cur, app_id, new_status, reason, officer)
    if error:
        conn.rollback()
        flash(error)
    else:
        conn.commit()
        flash("Application %s %s." % (app_no, new_status.lower()))
    cur.close(); conn.close()
    return redirect(url_for("admin_view", app_id=app_id))


@app.route("/admin/approve/<int:app_id>", methods=["POST"])
def admin_approve(app_id):
    return _admin_decide(app_id, "APPROVED", request.form.get("note", ""))


@app.route("/admin/reject/<int:app_id>", methods=["POST"])
def admin_reject(app_id):
    return _admin_decide(app_id, "REJECTED", request.form.get("note", ""))


from oauth import oauth as _oauth_blueprint   # noqa: E402  (needs the definitions above)
app.register_blueprint(_oauth_blueprint)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
