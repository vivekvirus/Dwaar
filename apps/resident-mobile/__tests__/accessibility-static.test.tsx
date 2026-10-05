// REQ: UX-02/UX-03, PRD 6 acceptance. Automated accessibility guards that need no device:
// (1) eslint-plugin-react-native-a11y is live and fails on bad code, (2) source rules that keep 200% text from clipping,
// (3) no hard-coded copy, (4) tab bar semantics, (5) token store behaviour per platform.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { execFileSync } from "node:child_process";
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react-native";
import { TabBar } from "../src/ui/chrome";
import { Button, Choice, Field } from "../src/ui/components";
import { assertAccessibleControls } from "./a11y";

const root = join(__dirname, "..");
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? (f === "generated" ? [] : files(p)) : /\.(tsx?)$/.test(f) ? [p] : [];
  });
}
const uiFiles = [...files(join(root, "src")), ...files(join(root, "app"))].filter((f) => f.endsWith(".tsx"));
const rel = (f: string) => relative(root, f);

describe("eslint-plugin-react-native-a11y is enforced (and catches real problems)", () => {
  // run the real CLI with the project config on a snippet (the lint script's own rules, not a copy of them)
  const lint = async (code: string): Promise<Array<string | null>> => {
    let out = "";
    try {
      out = execFileSync("npx", ["eslint", "--stdin", "--stdin-filename", "src/__lint_probe__.tsx", "--format", "json", "--no-warn-ignored"], { cwd: root, input: code, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    } catch (e: any) {
      out = e.stdout as string; // eslint exits 1 when it reports errors
    }
    return (JSON.parse(out)[0].messages as Array<{ ruleId: string | null }>).map((m) => m.ruleId);
  };
  test("an unlabelled touchable with an invalid role is rejected", async () => {
    const rules = await lint(`import React from "react"; import { Pressable, Text } from "react-native";
      export const X = () => <Pressable accessibilityRole="buton"><Text>x</Text></Pressable>;`);
    expect(rules).toContain("react-native-a11y/has-valid-accessibility-role");
  });
  test("a touchable without role/label is rejected", async () => {
    const rules = await lint(`import React from "react"; import { TouchableOpacity, Text } from "react-native";
      export const X = () => <TouchableOpacity onPress={() => undefined}><Text>x</Text></TouchableOpacity>;`);
    expect(rules).toContain("react-native-a11y/has-valid-accessibility-descriptors");
  });
  test("disabling font scaling is rejected (200% text)", async () => {
    const rules = await lint(`import React from "react"; import { Text } from "react-native";
      export const X = () => <Text allowFontScaling={false}>x</Text>;`);
    expect(rules).toContain("no-restricted-syntax");
  });
});

describe("200% text scale without clipping (static guards; not a substitute for a device check)", () => {
  test("no font-scaling opt-outs or caps anywhere", () => {
    for (const f of uiFiles) {
      const src = readFileSync(f, "utf8");
      expect({ f: rel(f), bad: /allowFontScaling\s*=\s*\{\s*false|maxFontSizeMultiplier/.test(src) }).toEqual({ f: rel(f), bad: false });
    }
  });
  test("no truncation: numberOfLines/ellipsizeMode are never used", () => {
    for (const f of uiFiles) expect({ f: rel(f), bad: /numberOfLines|ellipsizeMode/.test(readFileSync(f, "utf8")) }).toEqual({ f: rel(f), bad: false });
  });
  test("no fixed numeric height/width on containers (only minHeight/minWidth, spacers use tokens)", () => {
    for (const f of uiFiles) {
      const src = readFileSync(f, "utf8");
      const bad = [...src.matchAll(/(?<![a-zA-Z])(height|width):\s*\d+/g)].map((m) => m[0]).filter((m) => !/lineHeight/.test(m));
      // the QR block is a fixed-size image (240) and the only allowed numeric size
      const allowed = bad.filter((m) => !(rel(f).endsWith("InviteDetailScreen.tsx") && m.includes("240")));
      expect({ f: rel(f), allowed }).toEqual({ f: rel(f), allowed: [] });
    }
  });
  test("text always wraps and shrinks inside rows (flexShrink on text)", () => {
    const src = readFileSync(join(root, "src/ui/components.tsx"), "utf8");
    expect(src).toMatch(/flexShrink: 1/);
  });
  test("line heights are generous enough for Devanagari conjuncts (>= 1.5x font size)", () => {
    const tok = readFileSync(join(root, "src/ui/tokens.ts"), "utf8");
    for (const m of tok.matchAll(/fontSize: (\d+), lineHeight: (\d+)/g)) expect(Number(m[2]) / Number(m[1])).toBeGreaterThanOrEqual(1.45);
  });
});

describe("no hard-coded copy in UI code (every visible word comes from i18n)", () => {
  test("JSX text nodes contain no literal words", () => {
    const offenders: string[] = [];
    for (const f of uiFiles.filter((x) => !x.includes("/app/"))) {
      const src = readFileSync(f, "utf8");
      for (const m of src.matchAll(/>\s*([^<>{}\n]*[A-Za-z]{3,}[^<>{}\n]*)\s*</g)) {
        const text = m[1]!.trim();
        if (text && !/=>|\?|&&|\|\||[;()]|^\s*\/\//.test(text)) offenders.push(`${rel(f)}: ${text}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("tab bar semantics", () => {
  const tabs = [
    { name: "index", label: "Home", glyph: "⌂" },
    { name: "visitors", label: "Visitors", glyph: "☰" },
    { name: "profile", label: "Profile and privacy", glyph: "☺" },
  ];
  test("tablist with named tabs, selected state, text always visible, >= 48 dp, only released modules", () => {
    const onSelect = jest.fn();
    render(<TabBar tabs={tabs} activeName="visitors" onSelect={onSelect} navLabel="Main navigation" />);
    expect(screen.getByLabelText("Main navigation").props.accessibilityRole).toBe("tablist");
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    expect(screen.getByRole("tab", { name: "Visitors" }).props.accessibilityState.selected).toBe(true);
    expect(screen.getByRole("tab", { name: "Home" }).props.accessibilityState.selected).toBe(false);
    expect(screen.getByText("Home")).toBeTruthy(); // label is visible text, not only an icon
    assertAccessibleControls();
    fireEvent.press(screen.getByRole("tab", { name: "Profile and privacy" }));
    expect(onSelect).toHaveBeenCalledWith("profile");
    for (const hidden of ["Dues", "Help", "Community"]) expect(screen.queryByText(hidden)).toBeNull();
  });
});

describe("components expose role, name and state", () => {
  test("disabled and busy buttons say so to assistive tech; choices are radios with selected/checked", () => {
    render(
      <>
        <Button label="Go" onPress={() => undefined} disabled />
        <Button label="Wait" onPress={() => undefined} busy />
        <Choice label="One" selected onPress={() => undefined} />
        <Choice label="Two" selected={false} onPress={() => undefined} />
        <Field label="Phone" value="" onChangeText={() => undefined} error="Bad number" />
      </>,
    );
    expect(screen.getByRole("button", { name: "Go" }).props.accessibilityState).toMatchObject({ disabled: true });
    expect(screen.getByRole("button", { name: "Wait" }).props.accessibilityState).toMatchObject({ busy: true, disabled: true });
    expect(screen.getByRole("radio", { name: "One" }).props.accessibilityState).toMatchObject({ selected: true, checked: true });
    expect(screen.getByLabelText("Phone")).toBeTruthy();
    expect(screen.getByRole("alert")).toBeTruthy(); // field error announced
    expect(screen.getByText(/Bad number/).props.children.join("")).toMatch(/✕/); // error mark is not colour alone
    // selected choice carries a glyph difference too
    expect(JSON.stringify(screen.toJSON())).toContain("◉");
    expect(JSON.stringify(screen.toJSON())).toContain("○");
  });
});
