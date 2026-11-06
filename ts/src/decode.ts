// Text decoders used to build the extra views of a prompt: percent-encoding,
// \u / \U / \x escapes, base64, hex, 0x bytes, rot13 and tag characters.
// Each mirrors the Python helper of the same job in gate.py.

import { compilePyGlobal } from "./pyre.js";

const ASCII_RUN = /([\x00-\x7f]+)/u;
const HEX_PAIR = /^[0-9A-Fa-f]{2}/u;
const UTF8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/**
 * urllib.parse.unquote(s): %XX in each ASCII run becomes a byte, the bytes decode as
 * UTF-8 with replacement (a leading BOM is kept), non-ASCII text is left alone, and a
 * malformed %XX stays as typed.
 */
export function urlUnquote(s: string): string {
  if (!s.includes("%")) return s;
  const bits = s.split(ASCII_RUN);
  let out = bits[0] ?? "";
  for (let i = 1; i < bits.length; i += 2) {
    const run = bits[i] ?? "";
    const bytes: number[] = [];
    const chunks = run.split("%");
    for (const ch of (chunks[0] ?? "")) bytes.push(ch.charCodeAt(0));
    for (const item of chunks.slice(1)) {
      if (HEX_PAIR.test(item)) {
        bytes.push(parseInt(item.slice(0, 2), 16));
        for (const ch of item.slice(2)) bytes.push(ch.charCodeAt(0));
      } else {
        bytes.push(0x25);
        for (const ch of item) bytes.push(ch.charCodeAt(0));
      }
    }
    out += UTF8.decode(Uint8Array.from(bytes)) + (bits[i + 1] ?? "");
  }
  return out;
}

const UNI_ESC = compilePyGlobal(
  String.raw`\\(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2}))`,
);

/** Replace \uXXXX, \UXXXXXXXX and \xXX escapes. Above U+10FFFF becomes U+FFFD (Python raises). */
export function unescapeUnicode(s: string): string {
  return s.replace(UNI_ESC, (_whole: string, u4?: string, u8?: string, x2?: string) => {
    const cp = parseInt(u4 ?? u8 ?? x2 ?? "0", 16);
    return cp > 0x10ffff ? "�" : String.fromCodePoint(cp);
  });
}

const PRINTABLE_RUN = compilePyGlobal(String.raw`[\x20-\x7e\n\t]{12,}`);
const B64_CHARS = compilePyGlobal(String.raw`[A-Za-z0-9+/_-]{16,}={0,2}`);
export const HEX_RUN = compilePyGlobal(String.raw`(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[ :]?){8,}`);
export const HEX0X = compilePyGlobal(String.raw`(?:0x[0-9A-Fa-f]{2}[\s,;]*){4,}`);
const HEX0X_BYTE = compilePyGlobal(String.raw`0x([0-9A-Fa-f]{2})`);

/** Printable-ASCII runs (12+ chars) inside decoded bytes: tolerates junk around a payload. */
export function printableRuns(raw: Uint8Array): string[] {
  if (raw.length === 0) return [];
  const latin1 = Buffer.from(raw).toString("latin1");
  return Array.from(latin1.matchAll(PRINTABLE_RUN), (m) => m[0]);
}

/** Every base64 run in `joined`, at four alignments, decoded and cut to printable runs. */
export function b64Variants(joined: string): string[] {
  const out: string[] = [];
  for (const m of joined.matchAll(B64_CHARS)) {
    const run = m[0].replaceAll("-", "+").replaceAll("_", "/").replace(/=+$/u, "");
    for (let off = 0; off < 4; off += 1) {
      let r = run.slice(off);
      if (r.length % 4 === 1) r = r.slice(0, r.length - 1);
      const padded = r + "=".repeat((4 - (r.length % 4)) % 4);
      out.push(...printableRuns(Buffer.from(padded, "base64")));
    }
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Bytes of a `0x41 0x42 ...` run. */
export function bytesFrom0x(run: string): Uint8Array {
  return hexToBytes(Array.from(run.matchAll(HEX0X_BYTE), (m) => m[1] ?? "").join(""));
}

/** Bytes of a `41 42 43` / `41:42:43` run. */
export function bytesFromHexRun(run: string): Uint8Array {
  return hexToBytes(run.replace(/[ :]/gu, ""));
}

/** Characters hidden as Unicode tag characters (U+E0020..U+E007E), as plain ASCII. */
export function tagText(raw: string): string {
  let out = "";
  for (const c of raw) {
    const cp = c.codePointAt(0) ?? 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCodePoint(cp - 0xe0000);
  }
  return out;
}

export function rot13(s: string): string {
  return s.replace(/[A-Za-z]/gu, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** Reverse by code point (Python's s[::-1]). */
export function reverse(s: string): string {
  return Array.from(s).reverse().join("");
}
