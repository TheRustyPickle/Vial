CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    expires_at TIMESTAMPTZ,
    remaining_views INTEGER,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT expiry_required CHECK (
        expires_at IS NOT NULL
        OR remaining_views IS NOT NULL
    ),
    CONSTRAINT remaining_views_positive CHECK (
        remaining_views IS NULL
        OR remaining_views > 0
    )
);

CREATE INDEX secrets_expires_at_idx ON secrets (expires_at)
WHERE
    expires_at IS NOT NULL;
