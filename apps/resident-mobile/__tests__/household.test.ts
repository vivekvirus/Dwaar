// REQ: INV-01 / PRD 6: the selector never silently changes context; stale ids fail closed.
import { belongsToContext, deriveContexts, resolveContext, sameContext } from "../src/domain/household";
import { makeMe, OTHER_UNIT_ID, SOCIETY_ID, UNIT_ID } from "./helpers";

describe("household contexts", () => {
  test("only active, valid, unit-scoped household roles are offered (not owner_nr, not staff, not expired)", () => {
    const me = makeMe({}, [
      { role: "owner_occ", unit_id: UNIT_ID, active: true, valid_now: true },
      { role: "owner_nr", unit_id: OTHER_UNIT_ID, active: true, valid_now: true },
      { role: "secretary", unit_id: null, active: true, valid_now: true },
      { role: "tenant", unit_id: "u3", active: true, valid_now: false },
      { role: "family", unit_id: "u4", active: false, valid_now: true },
      { role: "owner_occ", unit_id: UNIT_ID, active: true, valid_now: true },
    ]);
    expect(deriveContexts(me)).toEqual([{ societyId: SOCIETY_ID, unitId: UNIT_ID, role: "owner_occ" }]);
  });

  const a = { societyId: "s1", unitId: "u1", role: "owner_occ" as const };
  const b = { societyId: "s2", unitId: "u2", role: "tenant" as const };

  test("nothing offered -> none", () => expect(resolveContext([], a)).toEqual({ kind: "none" }));
  test("a stored choice that is still offered is kept", () => expect(resolveContext([a, b], b)).toEqual({ kind: "active", context: b, chosenByUser: true }));
  test("a stored choice that is gone is NOT replaced by another home: the person must choose", () => {
    expect(resolveContext([a, b], { societyId: "s9", unitId: "u9", role: "tenant" })).toEqual({ kind: "choose", stale: true });
    expect(resolveContext([a], { societyId: "s9", unitId: "u9", role: "tenant" })).toEqual({ kind: "choose", stale: true });
  });
  test("several homes and no stored choice -> choose; exactly one -> that one (visible in the header)", () => {
    expect(resolveContext([a, b], null)).toEqual({ kind: "choose", stale: false });
    expect(resolveContext([a], null)).toEqual({ kind: "active", context: a, chosenByUser: false });
  });
  test("an object of another unit does not belong to the active context", () => {
    expect(belongsToContext(a, { unit_id: "u1" })).toBe(true);
    expect(belongsToContext(a, { unit_id: "u2" })).toBe(false);
    expect(sameContext(a, { ...a })).toBe(true);
    expect(sameContext(a, b)).toBe(false);
  });
});
