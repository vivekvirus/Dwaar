-- 0190 identity: foreign keys from the identity tables to the organisation module (0100-0129).
-- REQ: ARCH-01 (composite foreign keys prevent cross-society references), IAM-01.
-- Kept apart from 0133/0134 so the identity chain never depends on the organisation tables being applied first;
-- numbered after the organisation range so a database built from scratch has societies and units by now.
-- Referential-integrity checks bypass row security by design, so a membership can never point at another
-- society's unit and the constraint holds for every role.
ALTER TABLE memberships
    ADD CONSTRAINT memberships_society_fk FOREIGN KEY (society_id) REFERENCES societies (id),
    ADD CONSTRAINT memberships_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id);
ALTER TABLE role_grants
    ADD CONSTRAINT role_grants_society_fk FOREIGN KEY (society_id) REFERENCES societies (id);
