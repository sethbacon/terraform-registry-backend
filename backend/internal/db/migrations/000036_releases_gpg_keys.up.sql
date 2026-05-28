-- Cache of release-signing GPG keys auto-refreshed from each tool's
-- .well-known/pgp-key.txt. Mirror sync prefers the cached row over the
-- embedded snapshot. Refresh is fingerprint-pinned in code; a row with an
-- unexpected primary_fpr can never be inserted by the job, so this table is
-- safe to consult without additional in-DB validation.

CREATE TABLE releases_gpg_keys (
    tool           TEXT PRIMARY KEY,
    armored_key    TEXT NOT NULL,
    primary_fpr    TEXT NOT NULL,
    key_expires_at TIMESTAMP WITH TIME ZONE,
    source_url     TEXT NOT NULL,
    fetched_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
