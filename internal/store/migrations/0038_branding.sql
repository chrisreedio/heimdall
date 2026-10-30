-- Branding, from the admin settings page: the hub's display name, its
-- accent color, a logo and the app icon at the sizes browsers ask for.
-- One row, absent until an admin changes something; '' and NULL mean
-- Heimdall's own. The images are PNGs the hub decoded and re-encoded
-- itself (internal/web/brandimg.go). version goes up with every change and
-- is in the images' URLs, so browsers can cache them for good.
CREATE TABLE branding (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    name       TEXT    NOT NULL DEFAULT '' CHECK (length(name) <= 30),
    accent     TEXT    NOT NULL DEFAULT '' CHECK (accent = '' OR accent GLOB '#[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
    logo       BLOB,
    icon_512   BLOB,
    icon_192   BLOB,
    icon_180   BLOB,
    icon_32    BLOB,
    version    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL
) STRICT;
