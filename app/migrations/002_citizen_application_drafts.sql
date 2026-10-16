-- Apply once to an existing database before starting citizen-mcp.
-- Drafts are not applications and never enter the officer queue.
CREATE TABLE IF NOT EXISTS application_drafts (
    mobile      VARCHAR(15) PRIMARY KEY,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMP NOT NULL
);
