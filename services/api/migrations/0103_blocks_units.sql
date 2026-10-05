-- 0103 organisation: blocks and units (PRD 8.2, SOC-02).
-- REQ: SOC-02 (carpet area, built-up area, undivided interest %, architect-certified construction cost for fund
--      formulas), ARCH-01 (composite FKs make cross-society references impossible), INV-01 (RLS), PRD 8.1
--      (unit unique within block).
--
-- Units are unique per (society_id, block_id, label): the same label in two blocks is fine. A second, case-insensitive
-- unique index stops "A-101" vs "a-101" from becoming two units of one block (stricter than the PRD constraint,
-- which is kept verbatim). Areas are fixed decimals (numeric), the cost is integer paise (INV-02); there are no floats.

CREATE TABLE blocks (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
    floors integer NOT NULL CHECK (floors BETWEEN 0 AND 300),
    has_lift boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT blocks_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT blocks_society_name_uq UNIQUE (society_id, name)
);
CREATE UNIQUE INDEX blocks_society_name_ci_uq ON blocks (society_id, lower(btrim(name)));

CREATE TABLE units (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    block_id uuid NOT NULL,
    label text NOT NULL CHECK (char_length(btrim(label)) BETWEEN 1 AND 40),
    floor integer NOT NULL CHECK (floor BETWEEN -10 AND 300),
    carpet_area_sqft numeric(12, 2) CHECK (carpet_area_sqft IS NULL OR carpet_area_sqft > 0),
    builtup_area_sqft numeric(12, 2) CHECK (builtup_area_sqft IS NULL OR builtup_area_sqft > 0),
    undivided_interest_pct numeric(9, 6)
        CHECK (undivided_interest_pct IS NULL OR (undivided_interest_pct >= 0 AND undivided_interest_pct <= 100)),
    construction_cost_paise bigint CHECK (construction_cost_paise IS NULL OR construction_cost_paise >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT units_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT units_block_label_uq UNIQUE (society_id, block_id, label),
    CONSTRAINT units_block_fk FOREIGN KEY (society_id, block_id) REFERENCES blocks (society_id, id),
    CONSTRAINT units_builtup_ge_carpet CHECK (
        carpet_area_sqft IS NULL OR builtup_area_sqft IS NULL OR builtup_area_sqft >= carpet_area_sqft)
);
CREATE UNIQUE INDEX units_block_label_ci_uq ON units (society_id, block_id, lower(btrim(label)));
CREATE INDEX units_block_idx ON units (society_id, block_id, id);

SELECT dwaar_enable_society_rls('blocks', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_enable_society_rls('units', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (name, floors, has_lift, version, status) ON TABLE blocks TO dwaar_app;
GRANT UPDATE (label, floor, carpet_area_sqft, builtup_area_sqft, undivided_interest_pct,
              construction_cost_paise, version, status)
    ON TABLE units TO dwaar_app;
