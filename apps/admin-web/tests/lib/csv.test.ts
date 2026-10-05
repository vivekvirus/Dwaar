import { describe, expect, it } from "vitest";
import { csvCell, toCsv } from "@/lib/csv";
import { formatPaise } from "@/lib/utils";

describe("CSV export (RPT-01 partial)", () => {
  it("neutralises spreadsheet formulas and quotes special characters", () => {
    expect(csvCell("=HYPERLINK(\"x\")")).toBe("\"'=HYPERLINK(\"\"x\"\")\"");
    expect(csvCell("+91 99999")).toBe("'+91 99999");
    expect(csvCell("-1")).toBe("'-1");
    expect(csvCell("@sum")).toBe("'@sum");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell("line\nbreak")).toBe('"line\nbreak"');
    expect(csvCell(null)).toBe("");
    expect(csvCell(0)).toBe("0");
  });

  it("writes a header and CRLF rows", () => {
    expect(toCsv(["a", "b"], [[1, "x"], [2, "y"]])).toBe("a,b\r\n1,x\r\n2,y\r\n");
  });

  it("formats integer paise without floating point (INV-02)", () => {
    expect(formatPaise(405000000)).toBe("40,50,000.00");
    expect(formatPaise(5)).toBe("0.05");
    expect(formatPaise(null)).toBe("");
  });
});
