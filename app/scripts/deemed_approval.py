# -*- coding: utf-8 -*-
"""
Nightly deemed-approval job.

Under the Purvanchal Right to Public Services Act, an application not processed
within the statutory SLA stands approved. This job marks such applications
DEEMED_APPROVED and notifies the applicant by SMS.

The Act covers applications that went unprocessed through delay. An applicant who
did not meet the minimum age on the day they applied is not a delayed case but one
that needs a decision, and the counter would not have accepted the application at
all. Those are left PENDING for an officer (and noted once in the audit trail as
HELD_FOR_REVIEW) instead of being approved by the clock.

Scheduled via cron, 02:00 daily. See deploy/crontab.
"""

import os
import sys
import configparser
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import psycopg2
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

config = configparser.ConfigParser()
CONFIG_PATH = os.path.join(BASE_DIR, "config", "app.ini")
with open(CONFIG_PATH) as fh:
    config.read_file(fh)

IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    """Same clock as the portal: all stored timestamps are Indian Standard Time."""
    return datetime.now(IST).replace(tzinfo=None)


SLA_DAYS = config.getint("pension", "sla_days")
MIN_AGE = config.getint("pension", "min_age")
SMS_GATEWAY_URL = config.get("app", "sms_gateway_url")


def main():
    conn = psycopg2.connect(
        host=config.get("database", "host"),
        port=config.get("database", "port"),
        dbname=config.get("database", "name"),
        user=config.get("database", "user"),
        password=config.get("database", "password"),
    )
    cur = conn.cursor()
    now = now_ist()
    cutoff = now - timedelta(days=SLA_DAYS)
    # age on the day they applied, in whole years (same rule as the portal's age_on)
    age_at_application = "COALESCE(date_part('year', age(submitted_at::date, dob)), 0)"

    # 1. overdue and eligible: stands approved
    cur.execute(
        """UPDATE applications
           SET status = 'DEEMED_APPROVED', decided_at = %s, decided_by = 'RTPS-AUTO'
           WHERE status = 'PENDING' AND submitted_at < %s AND """ + age_at_application + """ >= %s
           RETURNING id, application_no, mobile""",
        (now, cutoff, MIN_AGE))
    approved = cur.fetchall()
    for app_id, _app_no, _mobile in approved:
        cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                    "VALUES (%s, 'DEEMED_APPROVED', 'system:rtps-cron', "
                    "'not processed within SLA', %s)", (app_id, now))
    rows = [(app_no, mobile) for _id, app_no, mobile in approved]

    # 2. overdue but under age on the day they applied: leave for an officer, note it once
    cur.execute(
        """INSERT INTO audit_log (application_id, action, actor, note, at)
           SELECT a.id, 'HELD_FOR_REVIEW', 'system:rtps-cron',
                  'past SLA but applicant was under minimum age when applying; needs officer decision', %s
           FROM applications a
           WHERE a.status = 'PENDING' AND a.submitted_at < %s
             AND COALESCE(date_part('year', age(a.submitted_at::date, a.dob)), 0) < %s
             AND NOT EXISTS (SELECT 1 FROM audit_log l
                             WHERE l.application_id = a.id AND l.action = 'HELD_FOR_REVIEW')
           RETURNING application_id""",
        (now, cutoff, MIN_AGE))
    held = cur.fetchall()
    conn.commit()
    for app_no, mobile in rows:
        try:
            requests.post(SMS_GATEWAY_URL + "/api/send", json={
                "to": mobile,
                "text": "Sewa Setu: your pension application %s stands approved "
                        "under the RTPS Act." % app_no}, timeout=5)
        except Exception:
            pass
    print("%s deemed approval: %d applications approved, %d newly held for officer review"
          % (now_ist().strftime("%Y-%m-%d %H:%M:%S"), len(rows), len(held)))
    cur.close()
    conn.close()


if __name__ == "__main__":
    sys.exit(main())
