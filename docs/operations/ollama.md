# AI analyst (Ollama)

1. Install Ollama: <https://ollama.com/download>
2. `ollama pull qwen3:4b-instruct` (default; ~2.5 GB) — any local chat model works
3. `OLLAMA_URL` (default `http://127.0.0.1:11434`; in Docker `http://host.docker.internal:11434`)
4. Administration → AI Analyst lets an admin pick another *local* model. Cloud models are refused.

Hardware: a 4B model answers in ~1–2 minutes on an Apple-silicon laptop. GPU acceleration is used
automatically by native Ollama (Docker on macOS has no GPU access — prefer native Ollama there).

Quality check after changing model or prompt: `sentinelx ai-eval` (validated-output rate, verdict accuracy,
injection resistance, latency) on the Demo Lab.
