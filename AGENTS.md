# Verifying this repository

Purpose: demonstrates a prompt-injection gate that blocks known attack patterns, with its misses and over-blocks measured and published for teams subject to model-risk, audit or change-control review.

Verify: `python3 evaluate.py`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `RESULT: PASS - no unexpected false negatives or false positives (10 documented known gaps)`

Scope: synthetic data, fixed seed, offline, under 60 seconds.

Limitations: Synthetic corpus of n=284 prompts, co-developed with the rules, so the figures are not real-world recall. 171/177 attacks are blocked and 6/177 attacks are missed. 4/107 benign prompts are over-blocked. Mention versus use of an attack phrase cannot be told apart. Evasions outside the listed input views, such as split words, other languages and unlisted encodings, still pass.

Anything else = not verified.
