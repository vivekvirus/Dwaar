-- 0312 device authentication lookup.
-- REQ: EDGE-09 (per-device identity; revocation effective at once), SOC-05, INV-01.
--
-- An edge request names only a device id: the society is not known yet, and every society table is FORCE row level security. This
-- reviewed SECURITY DEFINER function is the ONLY way to resolve "device id -> society + public key + state" before the society context
-- exists. It returns that one device row (public key, never a secret), is not executable by PUBLIC, and enables a SELECT policy that
-- exists solely for the function owner while the function runs.
CREATE POLICY devices_edge_auth_select ON devices FOR SELECT TO dwaar_owner
    USING (current_setting('dwaar.edge_auth', true) = '1');

CREATE FUNCTION edge_device_for_auth(p_device uuid)
RETURNS TABLE (society_id uuid, kind text, name text, gate_id uuid, state text, public_key text, key_id text,
               simulation boolean, last_seen_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM set_config('dwaar.edge_auth', '1', true);
    RETURN QUERY
    SELECT d.society_id, d.kind, d.name, d.gate_id, d.state, d.public_key, d.key_id, d.simulation, d.last_seen_at
    FROM public.devices d WHERE d.id = p_device;
    PERFORM set_config('dwaar.edge_auth', '', true);
END $$;
REVOKE ALL ON FUNCTION edge_device_for_auth(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION edge_device_for_auth(uuid) TO dwaar_app;
