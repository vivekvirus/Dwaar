import { screen } from "@testing-library/react-native";
import { flattenStyle } from "./helpers";

const INTERACTIVE = new Set(["button", "tab", "radio", "link", "switch"]);

/** Every interactive host element: has a role, a non-empty accessible name and a >= 48 dp target (PRD 6 acceptance). */
export function assertAccessibleControls() {
  const root = screen.toJSON();
  const found: Array<{ role: string; label: string | undefined; minHeight: number }> = [];
  const walk = (n: any) => {
    if (!n || typeof n === "string") return;
    const p = n.props ?? {};
    const role = p.accessibilityRole ?? p.role;
    if (role && INTERACTIVE.has(role) && p.accessible !== false) {
      const st = flattenStyle(p.style);
      found.push({ role, label: p.accessibilityLabel ?? p["aria-label"], minHeight: Number(st.minHeight ?? st.height ?? 0) });
    }
    (n.children ?? []).forEach(walk);
  };
  (Array.isArray(root) ? root : [root]).forEach(walk);
  expect(found.length).toBeGreaterThan(0);
  for (const c of found) {
    expect({ role: c.role, named: !!c.label && c.label.length > 0 }).toEqual({ role: c.role, named: true });
    expect(c.minHeight).toBeGreaterThanOrEqual(48);
  }
  return found;
}
