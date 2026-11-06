// Python `re` pattern text -> JavaScript RegExp.
//
// The rules are kept in their Python spelling so one pattern means one thing in both
// ports (and can be fingerprinted). This module translates the Python-only semantics
// that differ from a JS regex with the `u` flag:
//
//   \b \w \d  Unicode-aware in Python, ASCII-only (\b, \w) in JS    -> lookarounds / \p{..}
//   \s        Python str.isspace() set                              -> explicit class
//   .         anything but "\n" (JS also excludes \r, U+2028, U+2029) -> [^\n] or [^]
//   $         end, or before one trailing "\n"                      -> (?=\n?$)
//   \! \, \:  harmless escapes Python allows, a SyntaxError under /u -> the bare character
//
// Anything else that is not understood throws, so a new construct can never be
// silently mistranslated. Supported groups: (?: (?= (?! (?<= (?<! and (?-i:.

/** Code points for which Python's str.isspace() is true (Python 3.11, Unicode 14). */
export const PY_WHITESPACE: ReadonlySet<number> = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** The same set as the body of a character class. */
const WS = "\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
/** Python \w for str patterns: alphanumeric (letters, numbers) or underscore. */
const WORD = "\\p{L}\\p{N}_";
const BOUNDARY = `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;

const SYNTAX = "^$\\.*+?()[]{}|/";

export interface PyFlags {
  readonly ignoreCase?: boolean;
  readonly dotAll?: boolean;
}

function isAlnum(c: string): boolean {
  return /^[A-Za-z0-9]$/.test(c);
}

function fail(src: string, at: number, why: string): never {
  throw new Error(`pyre: ${why} at offset ${at} in pattern ${JSON.stringify(src.slice(0, 60))}`);
}

function classEscape(src: string, c: string, at: number): string {
  switch (c) {
    case "w":
      return WORD;
    case "d":
      return "\\p{Nd}";
    case "s":
      return WS;
    case "n":
    case "t":
    case "r":
    case "f":
    case "v":
      return `\\${c}`;
    default:
      if (isAlnum(c)) return fail(src, at, `unsupported class escape \\${c}`);
      return "^$\\.*+?()[]{}|/-".includes(c) ? `\\${c}` : c;
  }
}

function translateClass(src: string, start: number): { out: string; next: number } {
  // src[start] === "["
  let i = start + 1;
  let out = "[";
  if (src[i] === "^") {
    out += "^";
    i += 1;
  }
  if (src[i] === "]") fail(src, i, "empty or leading ] class");
  while (i < src.length) {
    const c = src[i] as string;
    if (c === "]") return { out: `${out}]`, next: i + 1 };
    if (c === "\\") {
      const e = src[i + 1];
      if (e === undefined) fail(src, i, "dangling backslash");
      if (e === "x") {
        out += src.slice(i, i + 4);
        i += 4;
        continue;
      }
      out += classEscape(src, e, i);
      i += 2;
      continue;
    }
    out += c;
    i += 1;
  }
  return fail(src, start, "unterminated character class");
}

/** Translate Python pattern text to the equivalent JS pattern text (for the `u` flag). */
export function translatePy(src: string, dotAll: boolean): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === "\\") {
      const e = src[i + 1];
      if (e === undefined) fail(src, i, "dangling backslash");
      switch (e) {
        case "b":
          out += BOUNDARY;
          break;
        case "w":
          out += `[${WORD}]`;
          break;
        case "W":
          out += `[^${WORD}]`;
          break;
        case "d":
          out += "\\p{Nd}";
          break;
        case "D":
          out += "\\P{Nd}";
          break;
        case "s":
          out += `[${WS}]`;
          break;
        case "S":
          out += `[^${WS}]`;
          break;
        case "n":
        case "t":
        case "r":
        case "f":
        case "v":
          out += `\\${e}`;
          break;
        default:
          if (isAlnum(e)) fail(src, i, `unsupported escape \\${e}`);
          out += SYNTAX.includes(e) ? `\\${e}` : e;
      }
      i += 2;
    } else if (c === "[") {
      const cls = translateClass(src, i);
      out += cls.out;
      i = cls.next;
    } else if (c === ".") {
      out += dotAll ? "[^]" : "[^\\n]";
      i += 1;
    } else if (c === "$") {
      out += "(?=\\n?$)";
      i += 1;
    } else if (c === "(" && src[i + 1] === "?") {
      const group = /^\(\?(?::|=|!|<=|<!|-i:)/.exec(src.slice(i, i + 6));
      if (group === null) fail(src, i, "unsupported group syntax");
      out += group[0];
      i += group[0].length;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Compile Python pattern text with Python flags (IGNORECASE, DOTALL) to a JS RegExp. */
export function compilePy(src: string, flags: PyFlags = {}): RegExp {
  const js = translatePy(src, flags.dotAll === true);
  return new RegExp(js, flags.ignoreCase === true ? "iu" : "u");
}

/** Global variant for replace-all (re.sub). */
export function compilePyGlobal(src: string, flags: PyFlags = {}): RegExp {
  const js = translatePy(src, flags.dotAll === true);
  return new RegExp(js, flags.ignoreCase === true ? "giu" : "gu");
}

/** Body of a character class holding Python whitespace, for hand-written JS regexes. */
export const PY_WS_CLASS_BODY = WS;
