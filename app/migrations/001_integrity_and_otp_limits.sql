-- Apply to an EXISTING database (fresh databases get this from schema.sql):
--   docker compose exec -T db psql -U sewasetu sewasetu < app/migrations/001_integrity_and_otp_limits.sql
-- Safe to run more than once. Fails loudly (and changes nothing) if the data already
-- contains duplicates, which is what you want to know about.
BEGIN;
ALTER TABLE otps ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_application_no ON applications(application_no);
CREATE UNIQUE INDEX IF NOT EXISTS ux_app_one_active_per_mobile ON applications(mobile)
    WHERE status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED');
COMMIT;
