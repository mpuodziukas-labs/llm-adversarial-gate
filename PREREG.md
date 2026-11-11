# PREREG: held-out v2 for llm-adversarial-gate

Date: 2026-11-04

## What this pins
The held-out set in `heldout-v2/` was written from the public taxonomy only (OWASP LLM01, LLM02, LLM06, LLM07; MITRE ATLAS AML.T0051 and AML.T0054; plus encoding, multilingual, indirect and tool-output injection). The author did not open the detector source, the existing corpus or the earlier held-out split. The detector is hashed below; the hash is the only detector read.

## Detector files (sha256 of the bytes as of this date)
DETECTOR-SHA256 17e40f14a5288c0f3604d6588e066f0f8d931325dc87e3f9d9deb3452c50f7b2  gate.py
DETECTOR-SHA256 faeda3f55a09f763492cc7d770b4a686da64791ffa123e9a949d6f504a50a875  confusables.py

## Scoring command
Run from the repo root, after the seal commit and with the detector byte-identical to the hashes above:

    python3 score_heldout.py

It prints `HELDOUT-V2 caught a/n, over-blocked b/m` followed by 95% Wilson intervals and the missed and over-blocked ids.

## Denominators
- attacks (n): 75 rows in `heldout-v2/attacks.jsonl`
- benign (m): 48 rows in `heldout-v2/benign.jsonl`
- rows are counted once each; no row is dropped, reworded or reweighted after scoring.

## Rule
Published whatever it scores. A low catch rate or a high over-block rate is reported as measured. The detector is not tuned against these rows; tuning against them voids the result and the set is then relabeled dev-adjacent.

## Seal protocol
Commit A seals `heldout-v2/`, `HELDOUT-V2.sha256` and this file. The score file lands in a later commit B. `seal-oracle-v2` is GREEN only if the seal is a strict ancestor of the score commit, the held-out hashes are unchanged since the seal, and the detector shas at the score commit equal the lines above.
