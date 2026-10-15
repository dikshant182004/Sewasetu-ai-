-- Checks to run against the live database after the fixes are deployed:
--   docker compose exec -T db psql -U sewasetu sewasetu < tests/verify_db.sql
\echo '--- 1. both unique indexes exist (expect 2 rows)'
SELECT indexname FROM pg_indexes
WHERE tablename = 'applications'
  AND indexname IN ('ux_app_application_no', 'ux_app_one_active_per_mobile');

\echo '--- 2. otps has the attempts column (expect 1 row)'
SELECT column_name FROM information_schema.columns WHERE table_name = 'otps' AND column_name = 'attempts';

\echo '--- 3. nothing was deemed-approved TODAY for an applicant who was under 60 when applying (expect 0)'
SELECT count(*) AS should_be_zero FROM applications
WHERE decided_by = 'RTPS-AUTO' AND decided_at::date = current_date
  AND date_part('year', age(submitted_at::date, dob)) < 60;

\echo '--- 4. cases held for an officer, and their audit note (the nightly job writes this once per case)'
SELECT a.id, a.application_no, a.dob, a.submitted_at, l.action, l.at
FROM applications a JOIN audit_log l ON l.application_id = a.id AND l.action = 'HELD_FOR_REVIEW'
WHERE a.status = 'PENDING' ORDER BY a.submitted_at;

\echo '--- 5. no application number is shared (expect 0 rows)'
SELECT application_no, count(*) FROM applications GROUP BY 1 HAVING count(*) > 1;

\echo '--- 6. decisions made since the fix all carry a reason (expect 0 rows)'
SELECT application_id, action, actor, at FROM audit_log
WHERE action IN ('APPROVED', 'REJECTED') AND at::date >= current_date
  AND (note IS NULL OR length(trim(note)) < 5);
