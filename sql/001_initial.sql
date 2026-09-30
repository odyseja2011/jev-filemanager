-- File Migration Planner: initial schema.
-- The database is the authoritative operational record.

CREATE OR REPLACE FUNCTION migrator_forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% on % is forbidden: table is append-only/immutable', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
CREATE TABLE migration_run (
    run_id              UUID PRIMARY KEY,
    name                TEXT NOT NULL,
    state               TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    config_json         JSONB NOT NULL,
    config_sha256       CHAR(64) NOT NULL,
    requested_jev_model TEXT NOT NULL,
    workspace_path      TEXT NOT NULL,
    run_trace_id        UUID NOT NULL,
    CONSTRAINT migration_run_state_chk CHECK (state IN (
        'CREATED','DISCOVERING','DISCOVERY_COMPLETE','HASHING','INVENTORY_COMPLETE',
        'CLASSIFYING','CLASSIFIED','REVIEW_REQUIRED','PLANNING','PLAN_READY',
        'BATCHES_GENERATED','EXTERNAL_EXECUTION_OBSERVED','RECONCILING','RECONCILED'))
);

-- A run is immutable with respect to its configuration snapshot.
CREATE OR REPLACE FUNCTION migrator_run_config_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.config_json IS DISTINCT FROM OLD.config_json
       OR NEW.config_sha256 IS DISTINCT FROM OLD.config_sha256
       OR NEW.requested_jev_model IS DISTINCT FROM OLD.requested_jev_model
       OR NEW.workspace_path IS DISTINCT FROM OLD.workspace_path THEN
        RAISE EXCEPTION 'migration_run configuration snapshot is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER migration_run_config_immutable BEFORE UPDATE ON migration_run
    FOR EACH ROW EXECUTE FUNCTION migrator_run_config_immutable();

CREATE TABLE run_state_history (
    id          BIGSERIAL PRIMARY KEY,
    run_id      UUID NOT NULL REFERENCES migration_run(run_id),
    from_state  TEXT,
    to_state    TEXT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    note        TEXT
);
CREATE INDEX run_state_history_run ON run_state_history(run_id, id);

-- ---------------------------------------------------------------------------
CREATE TABLE scan_root (
    scan_root_id            UUID PRIMARY KEY,
    run_id                  UUID NOT NULL REFERENCES migration_run(run_id),
    root_type               TEXT NOT NULL CHECK (root_type IN ('SOURCE','TARGET')),
    config_id               TEXT NOT NULL,
    absolute_path           TEXT NOT NULL,
    cross_mounts            BOOLEAN NOT NULL,
    discovery_started_at    TIMESTAMPTZ,
    discovery_completed_at  TIMESTAMPTZ,
    regular_file_count      BIGINT NOT NULL DEFAULT 0,
    directory_count         BIGINT NOT NULL DEFAULT 0,
    symlink_skipped_count   BIGINT NOT NULL DEFAULT 0,
    other_skipped_count     BIGINT NOT NULL DEFAULT 0,
    undecodable_skipped_count BIGINT NOT NULL DEFAULT 0,
    hash_success_count      BIGINT NOT NULL DEFAULT 0,
    hash_failure_count      BIGINT NOT NULL DEFAULT 0,
    UNIQUE (run_id, root_type, config_id)
);

CREATE TABLE directory_inventory (
    directory_id        UUID PRIMARY KEY,
    run_id              UUID NOT NULL REFERENCES migration_run(run_id),
    scan_root_id        UUID NOT NULL REFERENCES scan_root(scan_root_id),
    parent_directory_id UUID NULL REFERENCES directory_inventory(directory_id),
    absolute_path       TEXT NOT NULL,
    relative_path       TEXT NOT NULL,
    basename            TEXT NOT NULL,
    depth               INTEGER NOT NULL,
    st_dev              BIGINT,
    st_ino              BIGINT,
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, absolute_path)
);
CREATE INDEX directory_inventory_parent ON directory_inventory(parent_directory_id);
CREATE INDEX directory_inventory_root ON directory_inventory(scan_root_id);

CREATE TABLE file_inventory (
    file_id             UUID PRIMARY KEY,
    trace_id            UUID UNIQUE NOT NULL,
    run_id              UUID NOT NULL REFERENCES migration_run(run_id),
    scan_root_id        UUID NOT NULL REFERENCES scan_root(scan_root_id),
    parent_directory_id UUID NOT NULL REFERENCES directory_inventory(directory_id),
    root_type           TEXT NOT NULL CHECK (root_type IN ('SOURCE','TARGET')),
    absolute_path       TEXT NOT NULL,   -- original discovered path: never overwritten
    relative_path       TEXT NOT NULL,
    basename            TEXT NOT NULL,
    size_bytes          BIGINT NOT NULL,
    mtime_ns            BIGINT NOT NULL,
    ctime_ns            BIGINT NOT NULL,
    st_dev              BIGINT NOT NULL,
    st_ino              BIGINT NOT NULL,
    st_nlink            BIGINT NOT NULL,
    sha256              CHAR(64) NULL,
    hash_status         TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (hash_status IN ('PENDING','HASHING','HASHED','FAILED','UNSTABLE','BLOCKED_HARDLINK')),
    hash_error          TEXT NULL,
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    hashed_at           TIMESTAMPTZ NULL,
    UNIQUE (run_id, absolute_path)
);
CREATE INDEX file_inventory_run_type_status ON file_inventory(run_id, root_type, hash_status);
CREATE INDEX file_inventory_parent ON file_inventory(parent_directory_id);

-- ---------------------------------------------------------------------------
CREATE TABLE route_decision (
    decision_id             UUID PRIMARY KEY,
    run_id                  UUID NOT NULL REFERENCES migration_run(run_id),
    subject_type            TEXT NOT NULL CHECK (subject_type IN ('DIRECTORY','FILE')),
    subject_id              UUID NOT NULL,
    decision_source         TEXT NOT NULL CHECK (decision_source IN ('JEV','HUMAN')),
    decision_status         TEXT NOT NULL DEFAULT 'OK' CHECK (decision_status IN ('OK','API_FAILED')),
    supersedes_decision_id  UUID NULL REFERENCES route_decision(decision_id),
    cached_from_decision_id UUID NULL REFERENCES route_decision(decision_id),
    cache_key               CHAR(64) NULL,
    routing_policy_version  TEXT NULL,
    applies_to_subtree      BOOLEAN NULL,     -- HUMAN directory decisions
    state_json              JSONB NOT NULL,
    state_sha256            CHAR(64) NOT NULL,
    question_json           JSONB NOT NULL,
    criteria_sha256         CHAR(64) NOT NULL,
    selected_choice         TEXT NULL,
    confidence              DOUBLE PRECISION NULL,
    probabilities           JSONB NULL,
    response_json           JSONB NULL,       -- full Jev response
    error_text              TEXT NULL,
    requested_model         TEXT NULL,
    returned_model          TEXT NULL,
    api_request_id          TEXT NULL,
    api_usage               JSONB NULL,
    decided_by              TEXT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX route_decision_subject ON route_decision(run_id, subject_type, subject_id, created_at);
CREATE INDEX route_decision_cache ON route_decision(cache_key)
    WHERE cache_key IS NOT NULL AND cached_from_decision_id IS NULL AND decision_status = 'OK';
CREATE TRIGGER route_decision_append_only BEFORE UPDATE OR DELETE ON route_decision
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

CREATE TABLE file_route (
    file_route_id       UUID PRIMARY KEY,
    run_id              UUID NOT NULL REFERENCES migration_run(run_id),
    file_id             UUID NOT NULL REFERENCES file_inventory(file_id),
    decision_id         UUID NULL REFERENCES route_decision(decision_id),
    route_origin_type   TEXT NULL CHECK (route_origin_type IN ('DIRECT','INHERITED_DIRECTORY')),
    route_directory_id  UUID NULL REFERENCES directory_inventory(directory_id),
    target_id           TEXT NULL,
    confidence          DOUBLE PRECISION NULL,
    route_status        TEXT NOT NULL CHECK (route_status IN ('READY','REVIEW','BLOCKED')),
    reason_code         TEXT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, file_id)
);
CREATE INDEX file_route_status ON file_route(run_id, route_status);

-- ---------------------------------------------------------------------------
CREATE TABLE plan_revision (
    plan_id         UUID PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES migration_run(run_id),
    revision        INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    plan_sha256     CHAR(64) NOT NULL,
    operation_count BIGINT NOT NULL,
    ready_count     BIGINT NOT NULL,
    review_count    BIGINT NOT NULL,
    blocked_count   BIGINT NOT NULL,
    noop_count      BIGINT NOT NULL DEFAULT 0,
    UNIQUE (run_id, revision)
);
CREATE TRIGGER plan_revision_immutable BEFORE UPDATE OR DELETE ON plan_revision
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

CREATE TABLE plan_operation (
    operation_id         UUID PRIMARY KEY,
    plan_id              UUID NOT NULL REFERENCES plan_revision(plan_id),
    run_id               UUID NOT NULL REFERENCES migration_run(run_id),
    file_id              UUID NOT NULL REFERENCES file_inventory(file_id),
    trace_id             UUID NOT NULL,
    decision_id          UUID NULL REFERENCES route_decision(decision_id),
    operation_type       TEXT NOT NULL DEFAULT 'SAFE_MOVE',
    source_absolute_path TEXT NOT NULL,
    target_absolute_path TEXT NULL,
    expected_sha256      CHAR(64) NULL,
    expected_size_bytes  BIGINT NOT NULL,
    target_id            TEXT NULL,
    plan_status          TEXT NOT NULL CHECK (plan_status IN ('READY','REVIEW','BLOCKED','NOOP')),
    blocker_code         TEXT NULL,
    blocker_details      JSONB NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plan_id, file_id),
    CONSTRAINT plan_operation_ready_complete CHECK (
        plan_status <> 'READY' OR
        (target_absolute_path IS NOT NULL AND expected_sha256 IS NOT NULL AND target_id IS NOT NULL))
);
CREATE INDEX plan_operation_plan_status ON plan_operation(plan_id, plan_status);
CREATE TRIGGER plan_operation_immutable BEFORE UPDATE OR DELETE ON plan_operation
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

CREATE TABLE batch (
    batch_id        UUID PRIMARY KEY,
    plan_id         UUID NOT NULL REFERENCES plan_revision(plan_id),
    run_id          UUID NOT NULL REFERENCES migration_run(run_id),
    batch_number    INTEGER NOT NULL,
    operation_count INTEGER NOT NULL,
    script_path     TEXT NOT NULL,
    script_sha256   CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plan_id, batch_number)
);
CREATE TRIGGER batch_immutable BEFORE UPDATE OR DELETE ON batch
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

CREATE TABLE batch_operation (
    batch_id            UUID NOT NULL REFERENCES batch(batch_id),
    operation_id        UUID NOT NULL REFERENCES plan_operation(operation_id),
    position            INTEGER NOT NULL,
    trace_head_sequence BIGINT NOT NULL,   -- audit chain head when the batch was generated
    trace_head_hash     CHAR(64) NOT NULL,
    temp_absolute_path  TEXT NOT NULL,
    PRIMARY KEY (batch_id, operation_id)
);
CREATE UNIQUE INDEX batch_operation_operation ON batch_operation(operation_id);
CREATE TRIGGER batch_operation_immutable BEFORE UPDATE OR DELETE ON batch_operation
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

-- ---------------------------------------------------------------------------
CREATE TABLE audit_event (
    event_id            UUID PRIMARY KEY,
    run_id              UUID NOT NULL REFERENCES migration_run(run_id),
    trace_id            UUID NOT NULL,
    file_id             UUID NULL,
    operation_id        UUID NULL,
    batch_id            UUID NULL,
    sequence_no         BIGINT NOT NULL,
    event_type          TEXT NOT NULL,
    actor               TEXT NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL,
    payload             JSONB NOT NULL,
    previous_event_hash CHAR(64) NOT NULL,
    event_hash          CHAR(64) NOT NULL,
    source              TEXT NOT NULL,
    UNIQUE (trace_id, sequence_no)
);
CREATE INDEX audit_event_run ON audit_event(run_id);
CREATE INDEX audit_event_operation ON audit_event(operation_id) WHERE operation_id IS NOT NULL;
CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();

CREATE TABLE trace_head (
    trace_id    UUID PRIMARY KEY,
    sequence_no BIGINT NOT NULL,
    event_hash  CHAR(64) NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
CREATE TABLE reconciliation_pass (
    pass_id      UUID PRIMARY KEY,
    run_id       UUID NOT NULL REFERENCES migration_run(run_id),
    plan_id      UUID NOT NULL REFERENCES plan_revision(plan_id),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NULL
);

CREATE TABLE reconciliation_result (
    pass_id        UUID NOT NULL REFERENCES reconciliation_pass(pass_id),
    operation_id   UUID NOT NULL REFERENCES plan_operation(operation_id),
    outcome        TEXT NOT NULL,
    source_state   TEXT,
    target_state   TEXT,
    source_sha256  CHAR(64),
    target_sha256  CHAR(64),
    details        JSONB,
    checked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pass_id, operation_id)
);
CREATE TRIGGER reconciliation_result_append_only BEFORE UPDATE OR DELETE ON reconciliation_result
    FOR EACH ROW EXECUTE FUNCTION migrator_forbid_mutation();
