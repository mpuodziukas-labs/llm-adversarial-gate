import { describe, expect, it } from "vitest";
import { compilePy } from "../src/pyre.js";

const m = (src: string, text: string, flags: { ignoreCase?: boolean; dotAll?: boolean } = {}): string | null =>
  compilePy(src, flags).exec(text)?.[0] ?? null;

describe("compilePy: Python re semantics on a JS engine", () => {
  it("\\b is Unicode-aware like Python (JS native \\b is ASCII only)", () => {
    expect(m(String.raw`\bcafe\b`, "cafe")).toBe("cafe");
    expect(m(String.raw`\bfe\b`, "café")).toBeNull();
    expect(m(String.raw`\bx\b`, "жx")).toBeNull();
    expect(m(String.raw`\bx\b`, "1 x 2")).toBe("x");
  });
  it("\\w and \\d cover Unicode letters and decimal digits", () => {
    expect(m(String.raw`^\w+$`, "naïve_٣")).toBe("naïve_٣");
    expect(m(String.raw`\d+`, "٣٤")).toBe("٣٤");
    expect(m(String.raw`\w`, "-")).toBeNull();
  });
  it("\\s is the Python whitespace set, including U+001C..U+001F and U+0085", () => {
    for (const cp of [0x09, 0x0b, 0x1c, 0x1f, 0x20, 0x85, 0xa0, 0x2028, 0x3000]) {
      expect(m(String.raw`^\s$`, String.fromCodePoint(cp)), cp.toString(16)).not.toBeNull();
    }
    expect(m(String.raw`^\s$`, "​")).toBeNull();
    expect(m(String.raw`^\S$`, "​")).toBe("​");
  });
  it(". excludes only \\n unless dotAll", () => {
    expect(m(String.raw`a.b`, "a\rb")).toBe("a\rb");
    expect(m(String.raw`a.b`, "a b")).toBe("a b");
    expect(m(String.raw`a.b`, "a\nb")).toBeNull();
    expect(m(String.raw`a.b`, "a\nb", { dotAll: true })).toBe("a\nb");
  });
  it("$ matches at the end and before one trailing newline, like Python", () => {
    expect(m(String.raw`end$`, "the end")).toBe("end");
    expect(m(String.raw`end$`, "the end\n")).toBe("end");
    expect(m(String.raw`end$`, "the end\n\n")).toBeNull();
    expect(m(String.raw`end$`, "end here")).toBeNull();
  });
  it("(?-i:...) turns case folding off inside the group", () => {
    expect(m(String.raw`you (?-i:DAN)\b`, "YOU DAN", { ignoreCase: true })).toBe("YOU DAN");
    expect(m(String.raw`you (?-i:DAN)\b`, "you dan", { ignoreCase: true })).toBeNull();
  });
  it("ignoreCase is Unicode simple folding", () => {
    expect(m(String.raw`k`, "K", { ignoreCase: true })).toBe("K");
    expect(m(String.raw`s`, "ſ", { ignoreCase: true })).toBe("ſ");
    expect(m(String.raw`ss`, "ß", { ignoreCase: true })).toBeNull();
    expect(m(String.raw`word`, "WORD", { ignoreCase: true })).toBe("WORD");
    expect(m(String.raw`word`, "WORD")).toBeNull();
  });
  it("Python-only escapes are accepted: \\! \\, \\: \\- and \\\" outside and inside classes", () => {
    expect(m(String.raw`a\!b\,c\:d\-e`, "a!b,c:d-e")).toBe("a!b,c:d-e");
    expect(m(String.raw`[\"\'\-\!]+`, "x\"'-!y")).toBe("\"'-!");
  });
  it("classes accept \\w and \\s members and negation", () => {
    expect(m(String.raw`[\w.+-]+@[\w-]+`, "bob.x+y@mail-1")).toBe("bob.x+y@mail-1");
    expect(m(String.raw`[^\s"'<>]+`, "ab　cd")).toBe("ab");
    expect(m(String.raw`[^\w\s]|_`, "a_b")).toBe("_");
  });
  it("lookbehind and lookahead pass through", () => {
    expect(m(String.raw`(?<!debug\s)context\b`, "debug context")).toBeNull();
    expect(m(String.raw`(?<!debug\s)context\b`, "all context")).toBe("context");
    expect(m(String.raw`rm(?=\s|$|[.,])`, "rm.")).toBe("rm");
  });
  it("rejects constructs it does not translate instead of guessing", () => {
    expect(() => compilePy(String.raw`(a)\1`)).toThrow();
    expect(() => compilePy(String.raw`\B`)).toThrow();
    expect(() => compilePy(String.raw`\Z`)).toThrow();
  });
});
