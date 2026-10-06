-- 0313 index for matching an exit to an earlier entry of the same edge-local movement (docs/contracts/edge-sync.md 4.1).
-- REQ: EDGE-07 (the exit of a movement the gateway minted is matched to its observed entry), GATE-05.
CREATE INDEX edge_events_entity_idx ON edge_events (society_id, entity_id, event_type);
