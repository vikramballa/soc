# AI analyst controls mapped to the OWASP Top 10 for LLM Applications

This maps the local AI analyst's defences to the risks in the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) (2026 edition). Each row names
the code that enforces the control and the test that proves it. Risks are listed by name; check the
OWASP site for the current numbering.

The design premise (ADR-007, ADR-011): the model is **advisory only**. Detection, risk scoring, promotion
and response never depend on it, it runs locally, it has no tools, and its output is validated against the
evidence before anyone sees it.

| OWASP risk | How SentinelX addresses it | Code | Tests |
|---|---|---|---|
| **Prompt injection** (including indirect, via logs) | Telemetry is attacker-controlled, so it is passed as escaped JSON inside an untrusted block. Instruction-like fields are flagged and *withheld* from the model. A `likely_benign` verdict is rejected whenever injection flags exist. A Sigma rule raises an alert for text aimed at AI tooling. | `ai/sanitize.py`, `ai/prompt.py`, `ai/validator.py`, `security/sigma-rules/process/ai_prompt_injection.yml` | `test_prompt_injection_is_flagged_and_kept_as_data`, `test_injected_fields_are_withheld_and_benign_verdict_rejected`, `test_prompt_injection_in_list_fields_is_flagged_too` |
| **Sensitive information disclosure** | Secrets (passwords, tokens, keys) are redacted before any prompt. Context holds only the minimum evidence for one incident in the caller's tenant (RLS applies). Models are local only, so data never leaves the host. | `ai/sanitize.py`, `ai/context.py`, `ai/ollama.py` | `test_secret_redaction`, `test_cloud_models_are_excluded`, `tests/security/test_auth_and_isolation.py` |
| **Excessive agency** | The model has no tools and cannot act. Output claiming an action was taken is rejected, and response actions are human-created tasks, notes and watchlist entries only. | `ai/validator.py`, `api/routes/incidents.py` | `test_action_claims_are_rejected` |
| **Supply chain** | Only local Ollama models; `:cloud` and remote-served models are refused in the client and at the API route. Python and npm dependencies are audited in CI, GitHub Actions are pinned to commit SHAs, and an SBOM is published. | `ai/ollama.py`, `api/routes/ai.py`, `.github/workflows/ci.yml` | `test_cloud_models_are_excluded`, CI `Dependency audit` steps |
| **Data and model poisoning** | No fine-tuning or retrieval store is built from telemetry. Each investigation is stateless, so poisoned events can only affect the one incident they belong to, and are still subject to injection flagging. | `ai/context.py` | `test_ai_investigation_paths` |
| **Unbounded consumption** | Requests are bounded: capped evidence (`AI_MAX_EVIDENCE_EVENTS`), fixed context window (`OLLAMA_NUM_CTX`), request timeout (`OLLAMA_TIMEOUT_SECONDS`), one running investigation per incident, a separate worker lane, plus the API rate limit and the `ai:investigate` permission. | `ai/service.py`, `ai/ollama.py`, `jobs/worker.py`, `api/routes/incidents.py` | `test_ollama_client_structured_request`, `test_ai_investigation_paths` |
| **Misinformation** (hallucination) | Every claim must cite `E01`-style references that map to real events. Unknown references, indicators or ATT&CK ids fail validation, and AI text is labelled as AI-generated, separately from evidence, in the UI and reports. | `ai/validator.py`, `reports/incident_report.py` | `test_invented_event_reference_fails_validation`, `test_unsupported_or_fake_techniques_and_indicators_fail`, `test_incident_lifecycle_timeline_and_report` |
| **Hidden context exposure** (system prompt leakage) | The system prompt holds policy only, with no secrets, credentials or tenant data, so revealing it gives an attacker nothing to use. The prompt version is stored with each result for audit. | `ai/prompt.py` | — |
| **Vector and embedding weaknesses** | Not applicable: SentinelX uses no embeddings or vector store. | — | — |
| **Improper output handling** | Output must match a JSON schema before use. It is rendered as text (React escaping; reports HTML-escape every field) and never executed or used to build queries or commands. | `ai/schema.py`, `reports/incident_report.py`, `apps/web` | `test_incident_lifecycle_timeline_and_report` (XSS payload escaped) |

When you change the AI analyst, keep every row true and add a test for any new control. Run
`make ai-eval` against the Demo Lab to measure grounding and invalid-output rates with a real model.
