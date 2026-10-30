-- Hub settings an admin changes in the UI (internal/store/settings.go):
-- one row per setting, absent until it's changed from its default. The
-- first is "stepup", whether actions need a fresh code (docs/mobile.md).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
    value      TEXT NOT NULL CHECK (length(value) <= 1024),
    updated_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

-- When the session's user last proved it's them: a TOTP code at sign-in or
-- for a step-up, or a Microsoft sign-in with prompt=login. NULL: never.
ALTER TABLE sessions ADD COLUMN stepped_up_at TEXT;

-- Branding: the dark theme's accent, when an admin picks one; '' derives
-- it from the light theme's (internal/web/brandimg.go).
ALTER TABLE branding ADD COLUMN accent_dark TEXT NOT NULL DEFAULT ''
    CHECK (accent_dark = '' OR accent_dark GLOB '#[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]');
