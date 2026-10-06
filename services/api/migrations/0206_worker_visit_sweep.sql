-- 0206 visits: what the worker's expiry sweep needs and nothing more (the sweep itself is dwaar_api.modules.visits.visits.sweep).
-- REQ: GATE-02 (a pending request expires), GATE-05 / GATE-08 (a pass past its last window expires), GATE-11 (overstay), PRD 12.4, INV-01, INV-03.
--
-- The sweep already updates visits, visit_stops and approval_requests and inserts exceptions as dwaar_worker (0202, 0203, 0205). What it still
-- lacked is the one transition of a pass: active -> expired. Column-scoped to exactly that: the worker cannot change uses, revocation, the
-- windows or any other column of an invitation, and RLS (society context) still decides WHICH society's passes it may touch.
GRANT UPDATE (state, version) ON TABLE invitations TO dwaar_worker;
