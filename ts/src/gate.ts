// TypeScript port of gate.py: same normalization, same views, same rules, same scoring.
//
// Differences from the Python module are listed in the README ("TypeScript port").
// Rule descriptions and matched snippets are not carried over: the API only needs
// the rule id, category and weight.

import {
  b64Variants,
  bytesFrom0x,
  bytesFromHexRun,
  HEX0X,
  HEX_RUN,
  printableRuns,
  reverse,
  rot13,
  tagText,
  unescapeUnicode,
  urlUnquote,
} from "./decode.js";
import { HOMOGLYPHS } from "./confusables.js";
import { htmlUnescape } from "./htmlUnescape.js";
import { compilePyGlobal, PY_WHITESPACE } from "./pyre.js";
import { RULE_REGISTRY, type Category } from "./rules.js";

export { HOMOGLYPHS };

export type Verdict = "BLOCK" | "ALLOW";

export interface RuleMatch {
  readonly ruleId: string;
  readonly category: Category;
  readonly weight: number;
}

export interface GateResult {
  readonly verdict: Verdict;
  readonly score: number;
  readonly threshold: number;
  readonly matches: readonly RuleMatch[];
  readonly reason: string;
}

export const BLOCK_THRESHOLD = 1.0;
/** Inputs longer than this many code points are BLOCKed unscored (fail closed). */
export const MAX_INPUT_CHARS = 100_000;
/** Decoded candidates scanned per prompt (bounds latency). */
const MAX_DECODED = 24;

const FILLERS: ReadonlySet<number> = new Set([
  0x115f, 0x1160, 0x3164, 0xffa0, 0x2800, 0x180e, 0x17b4, 0x17b5, 0x2061, 0x2062, 0x2063, 0x2064, 0x034f,
]);

const LEET: ReadonlyMap<string, string> = new Map([
  ["0", "o"], ["1", "i"], ["3", "e"], ["4", "a"], ["5", "s"], ["7", "t"], ["@", "a"], ["$", "s"],
]);

const WS = compilePyGlobal(String.raw`\s+`);
const CTRL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/gu;
const JOIN_LETTERS = /(?<![A-Za-z])(?:[A-Za-z][.\-_*]){3,}[A-Za-z](?![A-Za-z])/gu;
const MIXED_TOKEN = compilePyGlobal(String.raw`\S+`);
const PUNCT = compilePyGlobal(String.raw`[^\w\s]|_`);
const SPACE_CATEGORY = /^[\p{Zs}\p{Zl}\p{Zp}]$/u;
const FORMAT = /^\p{Cf}$/u;
const DROPPED = /^[\p{Cc}\p{Mn}\p{Me}]$/u;

const DEFANG: ReadonlyArray<readonly [RegExp, string]> = [
  [compilePyGlobal(String.raw`h(?:xx|tt)p(s?)\s*(?:://|:\\\\)`, { ignoreCase: true }), "http$1://"],
  [compilePyGlobal(String.raw`\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*`, { ignoreCase: true }), "."],
  [compilePyGlobal(String.raw`\s*(?:\[@\]|\(@\)|\[at\]|\(at\))\s*`, { ignoreCase: true }), "@"],
];

const isAscii = (s: string): boolean => {
  for (let i = 0; i < s.length; i += 1) if (s.charCodeAt(i) > 0x7f) return false;
  return true;
};

/**
 * NFKC, fold look-alike letters, collapse whitespace. Format, combining and control
 * characters are dropped (sep "") so a zero-width space inside a word joins it; with
 * sep " " format characters and fillers become a space instead.
 */
export function normalize(text: string, sep = ""): string {
  if (isAscii(text)) {
    return stripPy(text.replace(CTRL, "").replace(WS, " "));
  }
  const t = text.normalize("NFKC").normalize("NFKD");
  let out = "";
  for (const c of t) {
    const cp = c.codePointAt(0) ?? 0;
    if (PY_WHITESPACE.has(cp) || SPACE_CATEGORY.test(c)) out += " ";
    else if (FILLERS.has(cp) || FORMAT.test(c)) out += sep;
    else if (DROPPED.test(c)) continue;
    else out += c;
  }
  let folded = "";
  for (const c of out) folded += HOMOGLYPHS.get(c.codePointAt(0) ?? 0) ?? c;
  return stripPy(folded.replace(WS, " "));
}

/** str.strip() with Python's whitespace set. */
function stripPy(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && PY_WHITESPACE.has(s.charCodeAt(a))) a += 1;
  while (b > a && PY_WHITESPACE.has(s.charCodeAt(b - 1))) b -= 1;
  return s.slice(a, b);
}

/** De-leet only tokens that mix letters with leet characters. */
function leet(text: string): string {
  return text.replace(MIXED_TOKEN, (tok) => {
    if (/[A-Za-z]/u.test(tok) && /[0-9@$]/u.test(tok)) {
      let o = "";
      for (const c of tok) o += LEET.get(c) ?? c;
      return o;
    }
    return tok;
  });
}

/** Punctuation and underscores become spaces. */
function punct(text: string): string {
  return stripPy(text.replace(PUNCT, " ").replace(WS, " "));
}

function refang(text: string): string {
  let t = text;
  for (const [pat, repl] of DEFANG) t = t.replace(pat, repl);
  return t;
}

function decodedCandidates(norm: string, raw: string): string[] {
  const out: string[] = [];
  const tags = tagText(raw);
  if (tags !== "") out.push(tags);
  if (norm.includes("%")) out.push(urlUnquote(norm));
  if (norm.includes("&")) out.push(htmlUnescape(norm));
  if (norm.includes("\\")) out.push(unescapeUnicode(norm));
  for (const m of norm.matchAll(HEX0X)) {
    out.push(...printableRuns(bytesFrom0x(m[0])));
  }
  out.push(...b64Variants(norm));
  const joined = norm.replace(WS, "");
  if (joined !== norm) out.push(...b64Variants(joined));
  for (const m of norm.matchAll(HEX_RUN)) {
    out.push(...printableRuns(bytesFromHexRun(m[0])));
  }
  out.push(rot13(norm));
  out.push(reverse(norm));
  return out;
}

/** Every reading of the input a rule is matched against; a rule fires if any view matches. */
function views(prompt: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (v: string): void => {
    if (v !== "" && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  };

  add(prompt);
  const norm = normalize(prompt);
  const bases: string[] = [norm, norm.replace(JOIN_LETTERS, (m) => m.replace(/[.\-_*]/gu, ""))];
  const spaced = normalize(prompt, " ");
  if (spaced !== norm) bases.push(spaced);
  const refanged = refang(norm);
  if (refanged !== norm) bases.push(refanged);
  const decodedSeen = new Set<string>();
  for (const cand of decodedCandidates(norm, prompt)) {
    if (decodedSeen.size >= MAX_DECODED) break;
    const n = normalize(cand);
    if (n !== "" && !decodedSeen.has(n) && n !== norm) {
      decodedSeen.add(n);
      bases.push(n);
    }
  }
  bases.push(...bases.map(punct));
  for (const b of bases) {
    add(b);
    add(leet(b));
  }
  return out;
}

function codePointLength(s: string): number {
  let n = 0;
  for (const _c of s) n += 1;
  return n;
}

function failClosed(reason: string): GateResult {
  return { verdict: "BLOCK", score: BLOCK_THRESHOLD, threshold: BLOCK_THRESHOLD, matches: [], reason };
}

export function evaluate(prompt: string): GateResult {
  if (typeof prompt !== "string") return failClosed("[TYPE] non-string input is blocked, not coerced");
  if (prompt.length > MAX_INPUT_CHARS && codePointLength(prompt) > MAX_INPUT_CHARS) {
    return failClosed(`[SIZE] oversize input (more than ${MAX_INPUT_CHARS} chars) is blocked unscored`);
  }
  const matches: RuleMatch[] = [];
  let total = 0;
  const all = views(prompt);
  for (const rule of RULE_REGISTRY) {
    for (const view of all) {
      if (rule.pattern.test(view)) {
        matches.push({ ruleId: rule.ruleId, category: rule.category, weight: rule.weight });
        total += rule.weight;
        break;
      }
    }
  }
  const verdict: Verdict = total >= BLOCK_THRESHOLD ? "BLOCK" : "ALLOW";
  let top: RuleMatch | undefined;
  for (const m of matches) if (top === undefined || m.weight > top.weight) top = m;
  return {
    verdict,
    score: Math.round(total * 1e4) / 1e4,
    threshold: BLOCK_THRESHOLD,
    matches,
    reason: top === undefined ? "" : `[${top.ruleId}] ${top.category}`,
  };
}

export interface Decision {
  readonly decision: Verdict;
  readonly category: Category | "input_limit" | null;
}

/** The public shape of a result: the decision and the category of the strongest match. */
export function summarize(r: GateResult): Decision {
  if (r.verdict === "ALLOW") return { decision: "ALLOW", category: null };
  const first = r.matches.reduce<RuleMatch | undefined>(
    (best, m) => (best === undefined || m.weight > best.weight ? m : best),
    undefined,
  );
  return { decision: "BLOCK", category: first === undefined ? "input_limit" : first.category };
}
