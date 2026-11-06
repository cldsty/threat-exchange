-- +goose Up
-- Threat records. Constraints duplicate the main API and domain rules on purpose
-- (defence in depth). They cover formats, enumerations and rules between fields;
-- rules that depend on the current time or on Unicode classes stay in the domain.
CREATE TABLE threats (
    md5           text        PRIMARY KEY
                              CONSTRAINT threats_md5_format CHECK (md5 ~ '^[0-9a-f]{32}$'),
    sha1          text        CONSTRAINT threats_sha1_format CHECK (sha1 ~ '^[0-9a-f]{40}$'),
    sha256        text        CONSTRAINT threats_sha256_format CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    name          text        NOT NULL
                              CONSTRAINT threats_name_length CHECK (char_length(name) BETWEEN 1 AND 255),
    description   text        CONSTRAINT threats_description_length CHECK (char_length(description) BETWEEN 1 AND 2000),
    types         text[]      NOT NULL DEFAULT '{}'
                              CONSTRAINT threats_types_count CHECK (cardinality(types) <= 12)
                              CONSTRAINT threats_types_vocabulary CHECK (types <@ ARRAY[
                                  'virus','worm','trojan','backdoor','rootkit','exploit','ransomware',
                                  'banker','downloader','dropper','spyware','stealer','miner','adware',
                                  'riskware','hacktool','other']::text[]),
    zone          text        NOT NULL DEFAULT 'grey'
                              CONSTRAINT threats_zone_values CHECK (zone IN ('red','orange','yellow','green','grey')),
    severity      text        NOT NULL DEFAULT 'unknown'
                              CONSTRAINT threats_severity_values CHECK (severity IN ('unknown','low','medium','high','critical')),
    file_size     bigint      CONSTRAINT threats_file_size_non_negative CHECK (file_size >= 0),
    first_seen_at timestamptz,
    last_seen_at  timestamptz,
    revoked       boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text        NOT NULL,
    updated_by    text        NOT NULL,
    version       bigint      NOT NULL DEFAULT 1
                              CONSTRAINT threats_version_positive CHECK (version >= 1),

    CONSTRAINT threats_seen_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT threats_severity_matches_zone
        CHECK (zone NOT IN ('green','grey') OR severity = 'unknown')
);

COMMENT ON TABLE threats IS 'Information about threats identified by file MD5';
COMMENT ON COLUMN threats.version IS 'Optimistic concurrency version, exposed as ETag';

-- +goose Down
DROP TABLE threats;
