-- 0563 community: what the worker's poll closer needs and nothing more (dwaar_api.modules.community.polls.close_due, run by dwaar_worker).
-- REQ: COM-06 (an open opinion poll closes at its closing time), PRD 12.4 (the close commits with its audit and outbox row: the worker may insert both
--      since 0004/0010), PRD 13 (job logic in plain functions run by the worker), INV-01, INV-06 (the system closes a poll; it decides nothing else).
--
-- Column-scoped to exactly the close transition: state, closes_at (stamped with the closing moment), version and updated_at. The worker cannot change a
-- question, an option, eligibility, result visibility, the neutrality review or an answer (poll_options and poll_responses stay SELECT-only for it), and
-- RLS (the society context of the job) still decides WHICH society's polls it may touch. Notices and tickets already had worker UPDATE grants (0531, 0560).
GRANT UPDATE (state, closes_at, version, updated_at) ON TABLE polls TO dwaar_worker;
