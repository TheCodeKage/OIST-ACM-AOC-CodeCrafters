# Praesidium

**Praesidium confirms whether a CVE is actually exploitable in *your* codebase — by executing the code path, not guessing from a version number.**

Static scanners (Dependabot, Snyk, OSV-Scanner) answer one question: *"does this project import a library with a known CVE?"* They can't answer the question that actually matters: *"can an attacker's input ever reach the vulnerable line in this specific application?"* That gap is why teams learn to triage every alert the same way, and real, exploitable vulnerabilities get lost in the noise alongside irrelevant ones.

Praesidium closes that gap. Given a target Python app and a CVE, it builds a static call graph, reasons about what input would trigger the vulnerable branch, monkeypatches the flagged function, and actually drives a real entry point to see if it fires. The result is one of three honest labels, with a trace a human can audit in under 10 seconds.

## How it works

```
[CVE + target app]
      │
      ▼
STAGE 1 — Static Candidate
  Build a call graph from known entry points (Flask/FastAPI routes, CLI args,
  or plain callables) to the CVE's flagged function.
    • No path exists  → label = Not-Reachable, stop.
    • Path exists      → continue to Stage 2.
      │
      ▼
STAGE 2 — Dynamic Confirmation
  An LLM reads the CVE advisory + the flagged function's real signature and
  proposes a concrete input that should trigger the vulnerable branch. The
  flagged function is monkeypatched to log invocation, and a real entry
  point is driven with that input.
    • Fires            → label = Confirmed-Reachable, stop.
    • Doesn't fire      → revise hypothesis, retry (max 2 attempts).
    • Still doesn't fire → label = Static-Match-Only, stop.
      │
      ▼
STAGE 3 — Historical Context (stretch, optional)
  Query a commit-history index to explain *when* and *why* the path became
  reachable. Enriches the trace; never changes the label.
```

| Label | Meaning |
|---|---|
| **Confirmed-Reachable** | The vulnerable function was actually invoked at runtime via a real entry point. |
| **Static-Match-Only** | A call path exists on paper, but no reasonable input hypothesis could trigger it at runtime. |
| **Not-Reachable** | No call path exists from any known entry point to the vulnerable function. |

**Entry point**, for the purposes of Stage 1, means any function directly reachable from an HTTP route decorator, a CLI argument parser, or an explicitly declared public function — nothing else counts.

## What this is not

Praesidium confirms that a code path *fires* — it does not craft or execute a working exploit payload. That's a deliberate design boundary, not a limitation: a tool that ships working exploits for real CVEs is a liability sitting in someone's repo. Every serious tool in this space (IAST-style tools included) draws the same line. Proving reachability is the useful signal; a live exploit is not a feature, and never will be one here.

## Install

```bash
uv sync --extra dev
cp .env.example .env   # fill in GROQ_API_KEY (get one at console.groq.com)
```

Requires Python 3.13+.

## Quick start

```bash
# Configure your API key
uv run praesidium config set-key gsk_your_api_key_here
uv run praesidium config show

# Check one CVE
uv run praesidium check /path/to/app --cve-config cve.json

# Check several CVEs at once
uv run praesidium run --cves cves.json --target /path/to/app
uv run praesidium run --cves cves.json --summary
uv run praesidium run --cves cves.json --output json > results.json
```

Generate a starter CVE config with `uv run praesidium init-config cve.json`, or write one directly:

```json
{
  "cve_id": "CVE-2024-XXXXX",
  "flagged_function": "UploadHandler.save_file",
  "flagged_module": "app.services.upload",
  "flagged_file": "app/services/upload.py",
  "entry_points": ["app.routes.upload_endpoint"],
  "advisory_summary": "Path traversal vulnerability in file upload handler",
  "function_signature": "def save_file(self, filename: str, contents: bytes)",
  "driver_kind": "callable"
}
```

`driver_kind` also accepts `flask_route` and `fastapi_route` for HTTP-driven entry points — see `entry_point_routes` in `schemas.py` for the route/method mapping shape.

#### Fetch CVEs for your dependencies

Before hand-writing a `cves.json`, you can generate a draft one from your
project's actual dependency versions:

```bash
# Scans uv.lock (or pyproject.toml + your environment) and queries
# OSV.dev for known CVEs affecting each resolved package version
uv run praesidium fetch . --output cves.json

# Also include advisories that have no assigned CVE number yet
uv run praesidium fetch . --output cves.json --include-no-cve
```

This writes one entry per matched CVE, but it can't know which function in
*your* codebase is vulnerable or which entry point reaches it — those come
back as `REPLACE_ME` placeholders. Fill in `flagged_function`,
`flagged_module`, `flagged_file`, and `entry_points` for each entry before
running `praesidium run --cves cves.json`.

## Python API

```python
from src import CVETarget, run_pipeline

target = CVETarget(
    cve_id="CVE-2024-XXXXX",
    flagged_function="...",
    flagged_module="...",
    flagged_file="...",
    entry_points=["..."],
    advisory_summary="...",
    function_signature="...",
)

result = run_pipeline(target, target_app_root="/path/to/target/app")
# result: EngineOutput(cve_id, label, trace, static_path, hypothesis_attempts)
```

`CVETarget` and `EngineOutput` (`src/schemas.py`) are the interface contract between the engine and anything driving it — the CLI, a CI job, a future dashboard. Keep them in sync deliberately; don't let field meanings drift.

## Tests

```bash
uv run pytest -v
```

`test_graph_builder.py` and `test_dynamic_harness.py` run against a dummy fixture app and need no API key — use these as the fast inner loop while iterating on Stage 1/2 logic.

```bash
uv run python scripts/smoke_test.py
```

Runs a reachable and a not-reachable case end-to-end against the dummy fixture, printing the full trace. Needs `GROQ_API_KEY`. This is the first real integration check before pointing the engine at a real target app.

## LLM provider

Hypothesis generation (`src/hypothesis.py`) calls Groq's OpenAI-compatible chat completions endpoint, using `openai/gpt-oss-120b` by default. Override with `GROQ_MODEL` in `.env` — e.g. `openai/gpt-oss-20b` for lower latency. Speed matters here specifically: Stage 2 can fire up to 3 calls per CVE (1 initial + 2 retries).

## Architecture decisions

| Piece | Choice | Why |
|---|---|---|
| Orchestration | LangGraph | The pipeline is a conditional-edge state graph, not a multi-agent negotiation — the shape matches the tool. |
| Static call graph | Python stdlib `ast` | Narrow scope (known entry points, known targets) doesn't justify an external graph library. |
| Hypothesis generation | LLM call (Groq) | The one genuinely agentic step: reasoning about what input triggers a *specific* vulnerable branch, not brute-force fuzzing. |
| Dynamic confirmation | Custom monkeypatch harness | Lightweight, deterministic, fully controllable for a live demo. |
| Output | CLI | A terminal trace reads as a credible security tool; a web UI doesn't add judged value here. |

## Known scope boundaries (by design, not oversight)

- **Static graph resolution is name-based, not points-to analysis.** Decorators and dynamic dispatch can produce false negatives at Stage 1 — that's precisely why Stage 2 exists. Don't try to "fix" this in `graph_builder.py`; it's a deliberate tradeoff, not a bug to close.
- **Retry cap is hard-set to 3 total attempts** (1 initial + 2 revised, `nodes.py::MAX_ATTEMPTS`) to keep runtime bounded for a live demo. Don't raise it without checking timing impact.
- **`EntryPointDriver` supports `callable`, `flask_route`, and `fastapi_route` shapes.** If a target app needs CLI-arg driving, extend `dynamic_harness.py`.
- **The dynamic harness executes real target-app code.** Only point it at a disposable, controlled target application — this is intentional (that's the whole point of dynamic confirmation), not something to sandbox away today.
- **CVE input is currently hand-curated**, not pulled live from OSV/GHSA. Advisories rarely name a specific vulnerable function in a structured field, so automatic discovery of `flagged_function` is a real (unsolved-here) problem, not a missing CLI flag — see Roadmap.

## Roadmap

- **Dynamic CVE discovery**: query OSV.dev's batch API against the project's actual lockfile to replace hand-picked CVE lists with real, current ones.
- **Advisory → flagged-function extraction**: an LLM stage that reads an advisory plus the installed package source and proposes a candidate function with a confidence score, falling back to an honest "advisory-level only" label rather than guessing.
- **CI integration**: a GitHub Action triggered on dependency-manifest changes, posting labels as PR annotations rather than hard-blocking merges until static-graph precision is validated on real repos.
- **Stage 3 (historical context)**: reuse an existing git-history index to explain when/why a path became reachable.
- **Batch dashboard**: a single ranked table across many CVEs instead of one-at-a-time runs.

## Project structure

```
src/
  schemas.py          # CVETarget / EngineOutput — the interface contract
  graph_builder.py     # Stage 1: static call graph (ast-based)
  hypothesis.py         # Stage 2: LLM input hypothesis generation
  dynamic_harness.py    # Stage 2: monkeypatch + entry-point drivers
  nodes.py               # LangGraph node functions + conditional-edge logic
  pipeline.py             # Wires nodes into the compiled graph
  cli.py                    # `praesidium` command-line interface
tests/
  fixtures/dummy_target_app/   # No-API-key fixture for fast inner-loop tests
scripts/
  smoke_test.py                 # Full pipeline sanity check (needs API key)
```