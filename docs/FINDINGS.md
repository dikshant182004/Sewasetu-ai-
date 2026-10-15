# Seva Setu portal: findings and fixes

How each item was found: **observed** = seen by running the portal and querying the database;
**code** = read in the source. "Verified" means covered by the unit tests in `tests/` (run with
`python3 -m unittest discover -s tests -v`); items marked *needs Docker* involve SQL, the PDF
library or the container image and must be checked on a running stack (`tests/verify_db.sql`).

## Fixed on branch `fix/portal-hardening`

| # | Problem | Found | Fix | Checked by |
|---|---|---|---|---|
| 1 | Nightly job approved every pending case past 15 days with no eligibility check. On first start it approved 8 applicants who were 59 on the day they applied. | observed | Eligible cases are approved; applicants under the minimum age on the day they applied stay pending and get one `HELD_FOR_REVIEW` audit entry. Audit rows now come from the UPDATE's `RETURNING` list. | *needs Docker* (`verify_db.sql` 3, 4) |
| 2 | Server in UTC; seed data and scheme deadline in IST. New rows were stamped 5.5 h behind. | observed | One clock: `now_ist()` everywhere; containers run in Asia/Kolkata. | code review, compile |
| 3 | Uploaded filename used in the stored path (spaces, dashes, case kept; no size limit on the request). | observed + code | `store_age_proof()`: extension allow-list, 5 MB cap, empty-file check, server-generated file name; oversized requests refused before reading. | unit tests |
| 4 | "Already has an application" only reported after the whole form was filled; not on the preview page. | observed | Checked right after OTP verification and listed on the preview page. | code review |
| 5 | Audit trail did not record how/by whom beyond `admin:admin`; decisions needed no reason. | observed | `decide_application()`: reason required (approve and reject), named officer, refuses an already-decided case, fits the column widths. | unit tests |
| 6 | Overdue cases show PENDING until the nightly run. | observed | Citizen page shows the decision-due date; officer page shows the deemed-approval date and whether it has passed. | render check |
| 7 | No limit on OTP requests or guesses (web form and OAuth sign-in). | observed | 10 codes per number per hour; 5 wrong guesses lock a code. One shared implementation. | unit tests |
| 8 | IFSC optional although the about page says it is required; gender and marital status accepted any text; long text caused a database error. | code | Required, fixed lists, plausible-age check, text clamped to column width. | unit tests |
| 9 | The document check only tested that a path string was non-empty. | code | The document must be a file this server stored for this mobile. | unit tests |
| 10 | Application numbers random with no uniqueness (~11% collision chance per new application). | code | Unique index + retry. | *needs Docker* |
| 11 | Two simultaneous submissions could both create a live application. | code | Partial unique index; a lost race gives the normal "already exists" message. | *needs Docker* |
| 12 | Bengali/Assamese names printed as `?` in the acknowledgment PDF. | observed | Noto font in the image, per-cell font choice, text shaping. | *needs Docker*: submit the name অভিজিৎ and open the PDF |
| 13 | Admin had no way to see the uploaded document; case page showed no age checks; list had no flag. | observed | Officer-only document view; checks block; "under age" flag; dashboard count of held cases. | render check |
| 14 | `?page=abc` on the admin list crashed. | code | Safe parse. | code review |
| 15 | Default admin password and secret key were built in. | observed | `ADMIN_PASSWORD` and `SECRET_KEY` must be set (`.env`, see `.env.example`). | compose config |

## Considered and deliberately not changed

* **Public SMS console at `/__gateway/`.** It shows every OTP to anyone. It is a simulation of a
  telecom gateway and the brief relies on it to sign in; on a real deployment OTPs go by SMS only.
  This is the largest production risk.
* **Status password = date of birth, reset to date of birth.** Weak, but changing it changes how
  citizens (and anyone reviewing the portal) sign in. Flagged for the department.
* **One shared officer login.** No per-block officers exist in the data; the officer queue covers all blocks.
* **Withdraw then reapply restarts the 15-day clock.** Allowed by the portal's rules; now stated to the applicant.
* **Magic-byte check on uploads** exists (`STRICT_DOC_CHECK=1`) but is off by default: it cannot tell a
  genuine document from a forged one, and would reject any placeholder file used in testing.
* **Mobile number prefix (6-9).** All seed numbers fit, but a stricter rule risks rejecting test numbers.

## Data-quality observation (not fixable in code)

Using the portal's own rule (age on the day of application), the historic data contains
2,585 APPROVED and 264 DEEMED_APPROVED applications whose applicant was under 60 when they
applied (about 3% of decisions), plus 9 pending ones. The pattern is spread across the whole
data set, so it looks like an artefact of how the data was generated, not 9 special cases.
Historic decisions were not altered; the department may want a review.

## Policy decision to confirm

Eligibility is judged **on the day of application**, as the portal's form does. A pending applicant who has
since turned 60 is therefore held for an officer instead of being approved by the clock. The officer page shows
age at application and age today so the officer can decide either way.

## Verified on a running stack (15 Oct 2026)
Schema indexes and OTP column present; nightly job holds under-age cases (8 held,
re-run adds no duplicates, 0 under-age approved); officer page shows checks and
records the reason against the officer; Bengali name renders in the acknowledgment
PDF; OTP wrong-guess lock confirmed; 44 tests pass in the container.