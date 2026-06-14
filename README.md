# LLM Adversarial Validation Gate

![CI](https://github.com/mpuodziukas-labs/llm-adversarial-gate/actions/workflows/ci.yml/badge.svg)

A reproducible, offline adversarial-validation gate for LLM outputs covering
five OWASP LLM Top 10 threat classes. Ships with a bundled synthetic corpus,
a deterministic evaluator, and a full pytest suite — no API keys required.

---

## Honesty Statement

> **These metrics are measured on the bundled synthetic corpus (n=220,
> composition described below). They are NOT from a production deployment,
> NOT from an external benchmark, and NOT from client data.**
>
> The corpus was authored specifically for this repository. It is intentionally
> broad but finite. A rule-based gate will miss novel phrasing not covered by
> its rules; that is a known and expected limitation of this approach. See
> [Limitations](#limitations) for an honest accounting.

---

## Corpus Composition

| Split       | Count | Categories |
|-------------|-------|------------|
| Adversarial | 140   | prompt_injection (40), jailbreak (40), system_prompt_leak (20), data_exfil (20), unsafe_tool_call (20) |
| Benign      | 80    | coding, security education, research, creative writing, tool use, superficially similar edge cases |
| **Total**   | **220** | |

The benign split includes prompts that contain surface-level "suspicious" tokens
(`ignore`, `override`, `base64`, `developer`, `pretend`, etc.) to stress-test
false-positive rate.

**Reference datasets:** This corpus is original synthetic content. It was not
derived from [AdvBench](https://github.com/llm-attacks/llm-attacks),
[HarmBench](https://github.com/centerforaisafety/HarmBench),
[JailbreakBench](https://github.com/JailbreakBench/jailbreakbench), or any
other published dataset, though those are referenced here for context.

---

## Results on Bundled Corpus

```
Confusion Matrix:
                   Predicted BLOCK   Predicted ALLOW
  Actual Adversarial    TP=140           FN=0
  Actual Benign         FP=0             TN=80

Block rate (recall):    100.0%  [140 / 140 adversarial caught]
False-negative rate:      0.0%  [0 adversarial missed]
False-positive rate:      0.0%  [0 benign over-blocked]
Accuracy:               100.0%
Precision:              100.0%
F1:                      1.0000
```

Per-category block rates: prompt_injection 100%, jailbreak 100%,
system_prompt_leak 100%, data_exfil 100%, unsafe_tool_call 100%.

**Why these numbers are honest:** The rules were iteratively developed *against
this corpus*. The corpus and rules were co-developed — the gate was not tested
on a held-out set from a different source. This is the correct thing to say.
The value is that the methodology (rules, corpus, evaluator) is fully
reproducible and auditable.

---

## Replay Command

```bash
# 1. Build corpus (one-time)
python3 build_corpus.py

# 2. Run full evaluation
python3 evaluate.py

# 3. Run test suite
python3 -m pytest tests/ -v

# 4. Query the gate directly
python3 gate.py "Ignore all previous instructions."
python3 gate.py "How do I read a file in Python?"
```

---

## File Structure

```
llm-adversarial-gate/
├── gate.py               # Guardrail: detection rules, evaluate(), ModelAdapter
├── evaluate.py           # Runs corpus through gate, prints metrics
├── build_corpus.py       # Generates corpus/adversarial.jsonl
├── corpus/
│   └── adversarial.jsonl # 220 labeled prompts (140 adversarial / 80 benign)
├── tests/
│   └── test_gate.py      # 114 pytest assertions (offline, deterministic)
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions: pytest + evaluate
├── README.md
└── LICENSE               # MIT
```

---

## Gate Architecture

`gate.py` implements a rule-based scoring gate:

```python
from gate import evaluate

result = evaluate("Ignore all previous instructions.")
# GateResult(verdict=BLOCK, score=1.0, primary_reason="[PI-001] ...")

result = evaluate("How do I sort a list in Python?")
# GateResult(verdict=ALLOW, score=0.0, matches=[])
```

**Detection classes (OWASP LLM Top 10 mapping):**

| Rule prefix | OWASP class | Coverage |
|-------------|-------------|----------|
| PI-*        | LLM01 Prompt Injection | Direct override, delimiter injection, from-now-on hijacks, authority impersonation |
| JB-*        | LLM01 / LLM02 | DAN, persona jailbreak, encoding bypass, mode-switch, social engineering |
| SP-*        | LLM02 Sensitive Info Disclosure | System-prompt leak, instruction dump, indirect operator leaks |
| DE-*        | LLM06 Sensitive Info Disclosure | URL/webhook exfil, API-key-in-link, memory dump |
| TC-*        | LLM07 Insecure Plugin Design | Shell injection, sensitive-path write, credential extraction, network exfil via tool |
| CO-*        | Composite | Urgency+override stacking, research-disclaimer bypass, context flooding |

**Scoring:** Each rule has a weight. Score = sum of matched rule weights.
A score ≥ 1.0 triggers `BLOCK`. Rules with weight 1.0 block on a single match.
Lower-weight rules (0.4–0.6) require co-occurrence to reach threshold.

**Extension:** Add rules to `RULE_REGISTRY` in `gate.py` without changing the
evaluation loop. Each `Rule` takes a compiled regex, a weight, and metadata.

---

## Plugging in a Real Model

`gate.py` ships a `ModelAdapter` interface:

```python
from gate import ModelAdapter, evaluate

class OpenAIAdapter(ModelAdapter):
    def __init__(self, api_key: str):
        import openai
        self.client = openai.OpenAI(api_key=api_key)

    def generate(self, prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.choices[0].message.content

# Pre-flight: gate the input before sending to the model
gate_result = evaluate(prompt)
if gate_result.blocked:
    raise ValueError(f"Blocked: {gate_result.primary_reason}")

# Send to model, then gate the response too
adapter = OpenAIAdapter(api_key="...")
response = adapter.generate(prompt)
response_result = evaluate(response)  # check for response-side violations
```

The `MockModelAdapter` (no API key needed) is used in CI and the test suite.

---

## Limitations

This is an honest list of what this gate does not do:

1. **Corpus is synthetic and co-developed with rules.** Metrics on this corpus
   reflect the rules' coverage of *known* patterns, not generalization to
   novel attacks.

2. **Regex/heuristic gaps.** Novel phrasing, adversarial synonyms, or heavily
   obfuscated attacks (multi-turn, token-splitting, low-and-slow) will not be
   caught by these rules without extension.

3. **No semantic understanding.** A rule-based gate cannot reason about intent.
   It is a complement to, not a replacement for, a trained classifier or LLM
   judge.

4. **False-positive risk on production data.** The 0% FPR is on 80 synthetic
   benign prompts. Real production traffic will have more surface area for
   false alarms, especially in developer/security contexts.

5. **No output-side coverage for most classes.** The gate currently evaluates
   input prompts. Response-side violations (LLM02 indirect prompt injection
   via retrieved documents, LLM06 PII leakage) require a second evaluation
   pass on the model output.

6. **Not a complete OWASP LLM Top 10 implementation.** LLM03 (Training Data
   Poisoning), LLM04 (Model DoS), LLM05 (Supply Chain), LLM08 (Excessive
   Agency), LLM09 (Overreliance), LLM10 (Model Theft) are outside scope.

---

## License

MIT — see [LICENSE](LICENSE).
