-- 0314 edge: what the worker's policy publisher needs and nothing more (the publisher is dwaar_api.modules.edge.snapshot.publish_policy).
-- REQ: EDGE-04 (publisher: on change and a periodic refresh, revocations first), EDGE-10, PRD 13 (workers), PRD 12.4, INV-01.
--
-- Until now publish-on-poll ran as dwaar_app inside the device's request; the worker publisher is the same code in a job. The worker gets the
-- same narrow, column-scoped rights the API role has on exactly these tables, each still behind the society RLS policy (no context, no row):
--   * policy_snapshots      INSERT (append-only; the sequence trigger still forces seq = previous + 1, UPDATE/DELETE stay impossible)
--   * edge_credential_refs  INSERT, and UPDATE of the revocation columns (a membership that ended gets its reference revoked)
--   * gate_policies         INSERT and UPDATE of the monotonic revocation counter only (the same counter invitations use)
GRANT INSERT ON TABLE policy_snapshots TO dwaar_worker;
GRANT INSERT ON TABLE edge_credential_refs TO dwaar_worker;
GRANT UPDATE (state, revocation_version, revoked_at) ON TABLE edge_credential_refs TO dwaar_worker;
GRANT INSERT (id, society_id, revocation_version, updated_by) ON TABLE gate_policies TO dwaar_worker;
GRANT UPDATE (revocation_version) ON TABLE gate_policies TO dwaar_worker;
