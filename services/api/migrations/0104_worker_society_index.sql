-- 0104 organisation: how a background job finds the societies it must visit, without a cross-society read.
-- REQ: INV-01 (every society table is FORCE RLS: with no society context the worker sees ZERO rows, so it cannot list the tenants it has to
--      sweep), PRD 13 (workers run per society, each in the context of that society).
--
-- `dwaar_active_society_ids()` is a reviewed SECURITY DEFINER function (owner dwaar_owner) that returns the ids of the active societies and
-- nothing else. EXECUTE belongs to dwaar_worker only (not PUBLIC, not dwaar_app). FORCE RLS binds the owner too, so the function raises a
-- transaction-local flag that ONE extra SELECT policy, scoped TO dwaar_owner, requires: no runtime role can read societies through it, and the
-- worker still reads, writes and audits each society only inside that society's own context.
CREATE POLICY societies_active_index ON societies FOR SELECT TO dwaar_owner
    USING (current_setting('dwaar.society_index', true) = 'on' AND status = 'active');

CREATE FUNCTION dwaar_active_society_ids() RETURNS SETOF uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM set_config('dwaar.society_index', 'on', true);
    RETURN QUERY SELECT s.id FROM public.societies s WHERE s.status = 'active' ORDER BY s.id;
    PERFORM set_config('dwaar.society_index', 'off', true);
    RETURN;
END
$$;
REVOKE ALL ON FUNCTION dwaar_active_society_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dwaar_active_society_ids() TO dwaar_worker;
COMMENT ON FUNCTION dwaar_active_society_ids() IS 'Ids of active societies for the worker role (no other column). SECURITY DEFINER; worker-only EXECUTE.';
