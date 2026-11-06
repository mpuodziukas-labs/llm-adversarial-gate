// Port of Python's html.unescape (CPython 3.11): same charref grammar, same tables
// (generated into htmlEntities.ts), same longest-legacy-prefix rule.
//
// One deliberate difference: CPython raises ValueError for a decimal reference of
// more than 4300 digits. Here the value is computed exactly and anything above
// U+10FFFF becomes U+FFFD, as for any other out-of-range reference.

import { HTML5_ENTITIES, INVALID_CHARREFS, INVALID_CODEPOINTS } from "./htmlEntities.js";

const NAMED: ReadonlyMap<string, string> = new Map(HTML5_ENTITIES);
const REMAP: ReadonlyMap<number, string> = new Map(INVALID_CHARREFS);
const DROPPED: ReadonlySet<number> = new Set(INVALID_CODEPOINTS);

const CHARREF = /&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)/gu;
const MAX_CODE_POINT = 0x10ffffn;

function replaceCharref(whole: string, body: string): string {
  if (body.startsWith("#")) {
    const hex = body[1] === "x" || body[1] === "X";
    const digits = body.slice(hex ? 2 : 1).replace(/;$/, "");
    const big = BigInt(hex ? `0x${digits}` : digits);
    if (big > MAX_CODE_POINT) return "�";
    const num = Number(big);
    const mapped = REMAP.get(num);
    if (mapped !== undefined) return mapped;
    if (num >= 0xd800 && num <= 0xdfff) return "�";
    if (DROPPED.has(num)) return "";
    return String.fromCodePoint(num);
  }
  const exact = NAMED.get(body);
  if (exact !== undefined) return exact;
  // Longest matching legacy name (names that are valid without a trailing semicolon).
  const cps = Array.from(body);
  for (let x = cps.length - 1; x > 1; x -= 1) {
    const prefix = cps.slice(0, x).join("");
    const hit = NAMED.get(prefix);
    if (hit !== undefined) return hit + cps.slice(x).join("");
  }
  return whole;
}

export function htmlUnescape(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(CHARREF, replaceCharref);
}
