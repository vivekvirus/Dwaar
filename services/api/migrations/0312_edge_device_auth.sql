-- 0312 device authentication lookup: a global, function-only directory of enrolled devices.
-- REQ: EDGE-09 (per-device identity; revocation effective at once), SOC-05, INV-01, ADR-0011 (the identity module's pattern: a global projection
--      kept in step by SECURITY DEFINER triggers, readable only through a reviewed SECURITY DEFINER function).
--
-- An edge request names only a device id: the society is not known yet, and every society table is FORCE row level security, so "device id ->
-- society + public key + state" cannot be asked of `devices` itself. `edge.device_directory` mirrors the columns authentication needs (never a
-- secret: the public key, state and ids), is maintained by triggers on `devices` in the SAME transaction as every change (so a revocation is
-- visible to the very next request), carries NO table privilege for any runtime role, and is reachable only through `edge.device_for_auth`.
-- `society_ref` (not `society_id`) marks it as a global index exactly like iam.person_access_index.
CREATE SCHEMA edge;
REVOKE ALL ON SCHEMA edge FROM PUBLIC;
GRANT USAGE ON SCHEMA edge TO dwaar_app;

CREATE TABLE edge.device_directory (
    device_id uuid PRIMARY KEY,
    society_ref uuid NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    gate_id uuid,
    state text NOT NULL,
    public_key text NOT NULL,
    key_id text NOT NULL,
    simulation boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE edge.device_directory FROM PUBLIC, dwaar_app, dwaar_worker;

CREATE FUNCTION edge.index_device() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, edge, public AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- a purged device can never authenticate again; the directory row stays as a tombstone (RUN-01: nothing is deleted here)
        UPDATE edge.device_directory SET state = 'deleted', updated_at = clock_timestamp() WHERE device_id = OLD.id;
        RETURN OLD;
    END IF;
    INSERT INTO edge.device_directory AS d (device_id, society_ref, kind, name, gate_id, state, public_key, key_id, simulation, updated_at)
    VALUES (NEW.id, NEW.society_id, NEW.kind, NEW.name, NEW.gate_id, NEW.state, NEW.public_key, NEW.key_id, NEW.simulation, clock_timestamp())
    ON CONFLICT (device_id) DO UPDATE SET society_ref = EXCLUDED.society_ref, kind = EXCLUDED.kind, name = EXCLUDED.name,
        gate_id = EXCLUDED.gate_id, state = EXCLUDED.state, public_key = EXCLUDED.public_key, key_id = EXCLUDED.key_id,
        simulation = EXCLUDED.simulation, updated_at = EXCLUDED.updated_at;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION edge.index_device() FROM PUBLIC;

CREATE TRIGGER devices_edge_directory AFTER INSERT OR UPDATE OR DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION edge.index_device();

-- backfill devices that exist already (slice 2 data): the owner is subject to FORCE row level security, so lift it for this one statement
-- inside the migration's own transaction
ALTER TABLE devices NO FORCE ROW LEVEL SECURITY;
INSERT INTO edge.device_directory (device_id, society_ref, kind, name, gate_id, state, public_key, key_id, simulation)
SELECT id, society_id, kind, name, gate_id, state, public_key, key_id, simulation FROM devices
ON CONFLICT (device_id) DO NOTHING;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;

CREATE FUNCTION edge.device_for_auth(p_device uuid)
RETURNS TABLE (society_id uuid, kind text, name text, gate_id uuid, state text, public_key text, key_id text, simulation boolean)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, edge AS $$
    SELECT d.society_ref, d.kind, d.name, d.gate_id, d.state, d.public_key, d.key_id, d.simulation
    FROM edge.device_directory d WHERE d.device_id = p_device
$$;
REVOKE ALL ON FUNCTION edge.device_for_auth(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION edge.device_for_auth(uuid) TO dwaar_app;
