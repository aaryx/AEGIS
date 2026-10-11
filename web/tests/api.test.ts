import { describe, expect, it } from "vitest";
import { csrfToken, csv, display } from "../lib/api";

describe("browser security boundaries", () => {
  it("extracts only the CSRF cookie", () => {
    expect(csrfToken("other=secret; aegis_csrf=abc123; aegis_session=private")).toBe("abc123");
    expect(csrfToken("aegis_session=private")).toBe("");
  });
  it("neutralizes CSV formula injection and escapes quotes", () => {
    const result = csv([{ title: '=HYPERLINK("https://example.org")', value: "a,b" }]);
    expect(result).toContain("'=HYPERLINK");
    expect(result).toContain('""https://example.org""');
    expect(result).toContain('"a,b"');
  });
  it("preserves attacker-controlled text as data", () => {
    expect(display("<script>alert(1)</script>")).toBe("<script>alert(1)</script>");
  });
});
