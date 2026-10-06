-- 0311 two additional exception kinds for the edge sync (additive; the slice 2 kinds are unchanged).
-- REQ: EDGE-05 (an implausible device clock is flagged for review, never "fixed"), EDGE-07 (an invalid transition or a quarantined event
--      is visible to a supervisor), GATE-07 (nothing is an invisible bypass).
ALTER TABLE exceptions DROP CONSTRAINT exceptions_kind_check;
ALTER TABLE exceptions ADD CONSTRAINT exceptions_kind_check CHECK (kind IN
    ('overstay', 'unauthorised_entry', 'exit_unknown', 'exit_without_entry', 'emergency_entry', 'manual_entry', 'other',
     'clock_implausible', 'edge_quarantine'));
