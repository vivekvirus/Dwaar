-- 0710 PRD 8.2 common columns (retention_class, legal_hold_id) on the slice 4 tables that were built without them.
-- REQ: PRD 8.2 (every table carries retention_class and legal_hold_id), PRIV-06 / Appendix B (class codes; durations stay in the retention pack, INV-10),
--      PRIV-15, DB-02 (nothing here touches an append-only guarantee: ADD COLUMN fires no row trigger and rewrites no row).
--
-- EXPAND-ONLY: two nullable-or-defaulted columns per table. A constant DEFAULT is a catalog change in PostgreSQL 16 (no rewrite, no lock beyond
-- the instant ACCESS EXCLUSIVE of ALTER TABLE), existing rows read the default, no data is changed, nothing is dropped or renamed.
-- legal_hold_id is set by privacy tooling (the retention slice), never by a request handler: no handler in this repository writes it, and the
-- retention slice must also narrow the runtime INSERT grant of that one column (open issue, slice 4 report).
--
-- Class codes follow the PARENT record's class so that one record expires as a unit (tickets OPS, notices and polls COM, documents DOC, staff STAFF,
-- logs LOG, resident preferences RES, device tokens CRED). OPEN ISSUE (slice 4 report): CONSENT, STAFF, OPS, COM and DOC are used by the slice 4
-- parents but are not codes of packages/legal-packs/retention (VIS VISPH DEL ANPR CRED RES STF FIN LOG BKP HOLD); the retention slice must map or add
-- them. tests/integration/core/test_retention_codes.py pins the set so that no further unmapped code appears unnoticed.

ALTER TABLE attendance_corrections
    ADD COLUMN retention_class text NOT NULL DEFAULT 'STAFF' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE attendance_events
    ADD COLUMN retention_class text NOT NULL DEFAULT 'STAFF' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE courier_observations
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE custody_transfers
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE parcel_custody_reports
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE parcel_pickup_attempts
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE parcel_reminders
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE device_push_tokens
    ADD COLUMN retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_budgets
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_cascades
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_counters
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_preferences
    ADD COLUMN retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_processed_events
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notification_templates
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE unit_notification_settings
    ADD COLUMN retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE document_versions
    ADD COLUMN retention_class text NOT NULL DEFAULT 'DOC' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE emergency_procedures
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE helpdesk_settings
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE ticket_events
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE ticket_links
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE ticket_priority_history
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE ticket_sla_breaches
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE ticket_sla_log
    ADD COLUMN retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE guard_profiles
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE guard_training_completions
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE shift_checklists
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE shift_overrides
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notice_deliveries
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notice_receipts
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notice_translations
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE notice_versions
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE poll_options
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE poll_responses
    ADD COLUMN retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
