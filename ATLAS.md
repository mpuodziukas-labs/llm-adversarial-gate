# MITRE ATLAS mapping

Each attack category in `corpus/adversarial.jsonl` is mapped to the closest
technique in MITRE ATLAS (Adversarial Threat Landscape for AI Systems). This is
a mapping, not certification.

Source: ATLAS data release 2026.10 (format 6.1.0, modified 2026-10-28),
https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.10.yaml
(project: https://github.com/mitre-atlas/atlas-data, site: https://atlas.mitre.org/techniques).
Fetched 2026-11-05. Every id and name below was read from that file.

| Corpus category | ATLAS id | ATLAS name | Basis |
|-----------------|----------|------------|-------|
| `prompt_injection` | AML.T0051 | LLM Prompt Injection | Override and delimiter attacks are prompts crafted to make the model act in unintended ways. |
| `jailbreak` | AML.T0054 | LLM Jailbreak | Persona, role-play and mode-switch prompts that try to defeat safety behavior. |
| `system_prompt_leak` | AML.T0069.002 | Discover LLM System Information: System Prompt | Requests that reveal the system instructions. |
| `data_exfil` | AML.T0086, AML.T0136 | Exfiltration via AI Agent Tool Invocation; Exfiltration via AI User Interface | Link, webhook and image based leaks of data through tools or the model output. Closest fit, not exact. |
| `unsafe_tool_call` | AML.T0053 | AI Agent Tool Invocation | Prompts that make an agent invoke shell, file or network tools. |

Not confirmed in this release: `AML.T0056` (earlier name "Extract LLM System
Prompt") and `AML.T0057` ("LLM Data Leakage") appear only in the deprecated 5.6.0
data file. They are absent from release 2026.10, so they are not used above.

`tests/test_atlas.py` fails if a corpus category is missing from this table.
