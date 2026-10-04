"""
Look-alike letter table used by gate.py to fold confusable characters to ASCII.

Source and honesty note: the entries are a hand-transcribed subset of the
"confusables.txt" data file of Unicode Technical Standard #39 (Unicode Security
Mechanisms, https://www.unicode.org/reports/tr39/), restricted to single code
points whose skeleton is one ASCII letter. The file was not available offline
when this table was written, so it is NOT the full UTS #39 set. Two other
sources feed the fold in gate.py: NFKC (fullwidth, math alphanumerics,
circled and roman-numeral forms) and the Unicode character names ("LATIN
LETTER SMALL CAPITAL X" is derived from the name, see small_capitals()).

Format: "<hex code point>:<ASCII letter>" separated by spaces.
tests/test_hostile.py checks the table is well formed (one entry per code
point, every target an ASCII letter).
"""

from __future__ import annotations

import unicodedata

_TABLE = """
0251:a 03b1:a 0430:a 237a:a 1d00:a 0410:A 0391:A 13aa:A
0432:b 13f4:B 0412:B 0392:B 0299:b
03f2:c 0441:c 1d04:c 0421:C 13df:C 03f9:C
0501:d 13a0:D 1d05:d
0435:e 212f:e 04bd:e 1d07:e 0415:E 0395:E 13ac:E
0261:g 0581:g 0262:g 13c0:G
04bb:h 0570:h 13bb:H 041d:H 0397:H 029c:h
0131:i 0456:i 03b9:i 0269:i 0406:I 0399:I 13d6:I 026a:i
0458:j 03f3:j 0408:J 13ab:J 1d0a:j
03ba:k 043a:k 1d0b:k 041a:K 039a:K 13e6:K
04cf:l 01c0:l 029f:l 13de:L
1d0d:m 041c:M 039c:M 13b7:M
0578:n 057c:n 0274:n 039d:N
03bf:o 043e:o 0585:o 1d0f:o 2134:o 041e:O 039f:O 0555:O 0d20:o 101d:o
0440:p 03c1:p 1d18:p 2374:p 0420:P 03a1:P 13e2:P
051b:q 0563:q 0566:q
0433:r 0280:r 13a1:R
0455:s 01bd:s 0405:S 13da:S
03c4:t 0442:t 1d1b:t 0422:T 03a4:T 13a2:T
03c5:u 057d:u 1d1c:u 028b:u 054d:U
03bd:v 0475:v 1d20:v 13d9:V
0461:w 051d:w 1d21:w 13b3:W 051c:W
0445:x 03c7:x 0425:X 03a7:X
0443:y 03b3:y 04af:y 028f:y 04ae:Y 03a5:Y
1d22:z 13c3:Z 0396:Z
""".split()


def small_capitals() -> dict[int, str]:
    """Latin small capitals, derived from the Unicode name (no hand list)."""
    out: dict[int, str] = {}
    for cp in range(0x0250, 0x0300):
        name = unicodedata.name(chr(cp), "")
        if name.startswith("LATIN LETTER SMALL CAPITAL ") and len(name.split()[-1]) == 1:
            out[cp] = name.split()[-1].lower()
    for cp in range(0x1D00, 0x1D80):
        name = unicodedata.name(chr(cp), "")
        if name.startswith("LATIN LETTER SMALL CAPITAL ") and len(name.split()[-1]) == 1:
            out[cp] = name.split()[-1].lower()
    return out


def build() -> dict[int, str]:
    table: dict[int, str] = {}
    for item in _TABLE:
        cp, target = item.split(":")
        table[int(cp, 16)] = target
    for cp, target in small_capitals().items():
        table.setdefault(cp, target)
    return table


def entries() -> list[tuple[int, str]]:
    """Raw hand-written entries (with duplicates visible) for the well-formedness test."""
    return [(int(i.split(":")[0], 16), i.split(":")[1]) for i in _TABLE]
