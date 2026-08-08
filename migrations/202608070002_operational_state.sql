CREATE TABLE IF NOT EXISTS operational_targets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target JSONB NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operational_targets_enabled
    ON operational_targets(enabled);

CREATE TABLE IF NOT EXISTS operational_findings (
    id UUID PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    target JSONB NOT NULL,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN (
            'new', 'confirmed', 'accepted', 'remediation_planned',
            'remediated', 'resolved', 'false_positive'
        )),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count BIGINT NOT NULL DEFAULT 1,
    evidence_event_id UUID,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_operational_findings_status
    ON operational_findings(status);
CREATE INDEX IF NOT EXISTS idx_operational_findings_scope
    ON operational_findings(scope);
CREATE INDEX IF NOT EXISTS idx_operational_findings_last_seen
    ON operational_findings(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_operational_findings_target
    ON operational_findings USING GIN(target);
