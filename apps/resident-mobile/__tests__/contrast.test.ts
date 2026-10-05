// REQ: UX-02/UX-03: contrast >= 4.5:1 for every foreground/background pair the UI uses.
import { colors } from "../src/ui/tokens";

function lum(hex: string): number {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0]! + 0.7152 * c[1]! + 0.0722 * c[2]!;
}
export function ratio(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

const pairs: Array<[string, string, string]> = [
  ["text on bg", colors.text, colors.bg],
  ["text on surface", colors.text, colors.surface],
  ["muted on bg", colors.textMuted, colors.bg],
  ["muted on surface", colors.textMuted, colors.surface],
  ["onNavy on navy", colors.onNavy, colors.navy],
  ["navy on surface (secondary button)", colors.navy, colors.surface],
  ["navy on tealSoft (selected choice, tab)", colors.navy, colors.tealSoft],
  ["text on tealSoft", colors.text, colors.tealSoft],
  ["teal on surface", colors.teal, colors.surface],
  ["info on infoBg", colors.info, colors.infoBg],
  ["success on successBg", colors.success, colors.successBg],
  ["warning on warningBg", colors.warning, colors.warningBg],
  ["danger on dangerBg", colors.danger, colors.dangerBg],
  ["danger on surface (deny button)", colors.danger, colors.surface],
  ["text on infoBg", colors.text, colors.infoBg],
  ["text on warningBg", colors.text, colors.warningBg],
  ["text on dangerBg", colors.text, colors.dangerBg],
  ["text on successBg", colors.text, colors.successBg],
  ["simulator text on simulator bg", colors.simulatorText, colors.simulatorBg],
  ["success on surface", colors.success, colors.surface],
  ["info on surface", colors.info, colors.surface],
  ["warning on surface", colors.warning, colors.surface],
];

describe("design tokens contrast (>= 4.5:1)", () => {
  test.each(pairs)("%s", (_name, fg, bg) => {
    expect(ratio(fg, bg)).toBeGreaterThanOrEqual(4.5);
  });
  test("the border colour of inputs/cards reaches 3:1 against surface (non-text UI contrast)", () => {
    expect(ratio(colors.border, colors.surface)).toBeGreaterThanOrEqual(3);
  });
});
