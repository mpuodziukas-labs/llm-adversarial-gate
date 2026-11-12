import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluate, BLOCK_THRESHOLD, MAX_INPUT_CHARS, HOMOGLYPHS } from "../src/gate.js";
import { PY_WHITESPACE } from "../src/pyre.js";
import { RULE_REGISTRY } from "../src/rules.js";

interface Decision {
  verdict: "BLOCK" | "ALLOW";
  score: number;
  rules: string[];
}
interface Fixture {
  corpus_sha256: string;
  block_threshold: number;
  max_input_chars: number;
  rules: Array<{
    id: string;
    category: string;
    weight: number;
    dotall: boolean;
    ignorecase: boolean;
    source_sha256: string;
  }>;
  homoglyphs: Record<string, string>;
  whitespace: number[];
  records: Record<string, Decision & { label: "adversarial" | "benign" }>;
  edge: Array<Decision & { name: string; prompt: string }>;
}
interface CorpusRow {
  id: string;
  label: "adversarial" | "benign";
  prompt: string;
}

const root = join(import.meta.dirname, "..", "..");
const fixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "fixtures", "parity.json"), "utf8"),
) as Fixture;
const corpusRaw = readFileSync(join(root, "corpus", "adversarial.jsonl"));
const corpus = corpusRaw
  .toString("utf8")
  .split("\n")
  .filter((l) => l.trim() !== "")
  .map((l) => JSON.parse(l) as CorpusRow);

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

describe("parity fixture is current", () => {
  it("was generated from the committed corpus", () => {
    expect(createHash("sha256").update(corpusRaw).digest("hex")).toBe(fixture.corpus_sha256);
  });
  it("has the expected shape (no empty-input pass)", () => {
    expect(corpus.length).toBe(284);
    expect(Object.keys(fixture.records).length).toBe(284);
    expect(fixture.edge.length).toBeGreaterThanOrEqual(60);
    expect(fixture.rules.length).toBe(59);
  });
});

describe("gate constants and tables match Python", () => {
  it("threshold and size cap", () => {
    expect(BLOCK_THRESHOLD).toBe(fixture.block_threshold);
    expect(MAX_INPUT_CHARS).toBe(fixture.max_input_chars);
  });
  it("rule table: ids, order, category, weight, flags, pattern fingerprint (59/59)", () => {
    expect(RULE_REGISTRY.length).toBe(fixture.rules.length);
    let same = 0;
    fixture.rules.forEach((want, i) => {
      const got = RULE_REGISTRY[i];
      expect(got?.ruleId).toBe(want.id);
      expect(got?.category).toBe(want.category);
      expect(got?.weight).toBe(want.weight);
      expect(got?.dotAll).toBe(want.dotall);
      expect(got?.ignoreCase).toBe(want.ignorecase);
      expect(got === undefined ? "" : sha(got.source), want.id).toBe(want.source_sha256);
      same += 1;
    });
    expect(same).toBe(59);
  });
  it("look-alike fold table is identical (138 entries)", () => {
    const got: Record<string, string> = {};
    for (const [cp, ch] of HOMOGLYPHS) got[String(cp)] = ch;
    expect(Object.keys(got).length).toBe(Object.keys(fixture.homoglyphs).length);
    expect(got).toEqual(fixture.homoglyphs);
  });
  it("Python whitespace set is identical (29 code points)", () => {
    expect([...PY_WHITESPACE].sort((a, b) => a - b)).toEqual(fixture.whitespace);
  });
});

describe("decision parity with the Python gate", () => {
  it("every corpus prompt: verdict, score and matched rule ids (284/284)", () => {
    let agree = 0;
    const bad: string[] = [];
    for (const row of corpus) {
      const want = fixture.records[row.id];
      const got = evaluate(row.prompt);
      const ids = got.matches.map((m) => m.ruleId);
      if (want !== undefined && got.verdict === want.verdict && got.score === want.score && ids.join() === want.rules.join()) {
        agree += 1;
      } else {
        bad.push(`${row.id}: got ${got.verdict}/${got.score}/${ids.join("+")} want ${want?.verdict}/${want?.score}/${want?.rules.join("+")}`);
      }
    }
    expect(bad).toEqual([]);
    expect(agree).toBe(284);
    console.log(`PARITY ${agree}/${corpus.length} prompts agree with the Python gate (verdict, score, rule ids)`);
  });

  it("every edge prompt: verdict, score and matched rule ids (N/N)", () => {
    let agree = 0;
    const bad: string[] = [];
    for (const e of fixture.edge) {
      const got = evaluate(e.prompt);
      const ids = got.matches.map((m) => m.ruleId);
      if (got.verdict === e.verdict && got.score === e.score && ids.join() === e.rules.join()) {
        agree += 1;
      } else {
        bad.push(`${e.name}: got ${got.verdict}/${got.score}/${ids.join("+")} want ${e.verdict}/${e.score}/${e.rules.join("+")}`);
      }
    }
    expect(bad).toEqual([]);
    expect(agree).toBe(fixture.edge.length);
  });

  it("reproduces the published headline: 171/177 adversarial caught, 4/107 benign over-blocked", () => {
    let caught = 0;
    let adversarial = 0;
    let overBlocked = 0;
    let benign = 0;
    for (const row of corpus) {
      const blocked = evaluate(row.prompt).verdict === "BLOCK";
      if (row.label === "adversarial") {
        adversarial += 1;
        if (blocked) caught += 1;
      } else {
        benign += 1;
        if (blocked) overBlocked += 1;
      }
    }
    expect([caught, adversarial]).toEqual([171, 177]);
    expect([overBlocked, benign]).toEqual([4, 107]);
    console.log(`PARITY ${caught}/${adversarial} adversarial caught, ${overBlocked}/${benign} benign over-blocked`);
  });
});
