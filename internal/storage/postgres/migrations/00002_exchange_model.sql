-- +goose Up
-- Exchange between organizations: distribution label, confidence, history of
-- changes and consistency of hashes.
ALTER TABLE threats
    ADD COLUMN tlp text NOT NULL DEFAULT 'amber'
        CONSTRAINT threats_tlp_values CHECK (tlp IN ('clear','green','amber','amber+strict','red')),
    ADD COLUMN confidence smallint
        CONSTRAINT threats_confidence_range CHECK (confidence BETWEEN 0 AND 100),
    ADD CONSTRAINT threats_first_seen_min CHECK (first_seen_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00'),
    ADD CONSTRAINT threats_last_seen_min CHECK (last_seen_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00'),
    -- One file has one MD5, so one SHA-256 cannot belong to two records. The same
    -- does not hold for SHA-1: different files with equal SHA-1 are known.
    ADD CONSTRAINT threats_sha256_key UNIQUE (sha256);

-- Every version of every record, kept to find out who changed what. A shared
-- record can be replaced by any writer, so its previous data must not be lost.
CREATE TABLE threat_history (
    md5        text        NOT NULL REFERENCES threats (md5),
    version    bigint      NOT NULL,
    changed_by text        NOT NULL,
    changed_at timestamptz NOT NULL,
    snapshot   jsonb       NOT NULL,
    PRIMARY KEY (md5, version)
);

COMMENT ON TABLE threat_history IS 'Immutable log of all versions of threats, filled by a trigger';

-- A trigger keeps the history complete even for changes that bypass the service.
-- SECURITY DEFINER lets the application role write history without having write
-- access to the table.
-- +goose StatementBegin
CREATE FUNCTION threats_record_history() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO threat_history (md5, version, changed_by, changed_at, snapshot)
    VALUES (NEW.md5, NEW.version, NEW.updated_by, NEW.updated_at, to_jsonb(NEW));
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER threats_history AFTER INSERT OR UPDATE ON threats
    FOR EACH ROW EXECUTE FUNCTION threats_record_history();

INSERT INTO threat_history (md5, version, changed_by, changed_at, snapshot)
SELECT t.md5, t.version, t.updated_by, t.updated_at, to_jsonb(t) FROM threats t;

-- Least privilege for the application role, when the deployment defines it
-- (see deploy/postgres): it cannot change the schema or rewrite the history.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'threats_app') THEN
        GRANT SELECT, INSERT, UPDATE ON threats TO threats_app;
        GRANT SELECT ON threat_history TO threats_app;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER threats_history ON threats;
DROP FUNCTION threats_record_history();
DROP TABLE threat_history;
ALTER TABLE threats
    DROP CONSTRAINT threats_sha256_key,
    DROP CONSTRAINT threats_last_seen_min,
    DROP CONSTRAINT threats_first_seen_min,
    DROP COLUMN confidence,
    DROP COLUMN tlp;
