# Advisory AI

`AI_PROVIDER=local` works without credentials and produces a deterministic
evidence summary. The UI labels it as such; it is not represented as an LLM.
OpenAI and Azure providers use configured HTTPS chat-completion endpoints,
models and keys. No provider code has access to execute response operations.

Outbound investigation context includes up to AI_EVIDENCE_LIMIT event IDs,
timestamps, categories/actions/outcomes and a small set of alert fields. Raw
messages, command lines, usernames, IPs, notes and original evidence are excluded.
Do not assume this removes every organizational sensitivity: classification and
provider selection remain deployment policy decisions.

Prompts separate trusted security instructions from explicitly untrusted evidence.
Outputs validate against a strict schema. Citation IDs must belong to the supplied
evidence; Observed claims must cite events. Categories are Observed, Inferred,
Possible and Unknown. Citation validation cannot prove a natural-language sentence
is true, so generated assertions remain subject to analyst verification.

External calls have a 20-second timeout, one connection retry, output-token cap,
64 KB response cap and per-user hourly request limit. Invalid/failed external
analysis returns a clearly labeled deterministic fallback. No external success is
fabricated. Query generation validates the structured query and never executes it
automatically. Raw user questions may be sent externally if external query
generation is selected; avoid entering unnecessary personal information.

External integration configuration:

```text
AI_PROVIDER=openai
AI_ENDPOINT=https://api.openai.com/v1/chat/completions
AI_MODEL=<approved-model>
AI_API_KEY=<secret-from-environment>
```

Azure uses `AI_PROVIDER=azure`, a complete approved deployment URL including its
API version, and an `api-key` header. Provider compatibility and credentials must
be verified against the organization's deployment. External live calls are not
part of the credential-free test suite.
