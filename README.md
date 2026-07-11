# Praesidium

**Praesidium** is a dynamic CVE reachability confirmation engine that combines static analysis with LLM-powered hypothesis generation to determine if vulnerabilities are actually exploitable in your codebase.

## Features

- 🔍 **Static Call Graph Analysis** - Traces code paths from entry points to vulnerable functions
- 🤖 **LLM-Powered Hypothesis Generation** - Uses Groq's GPT models to generate realistic exploit attempts
- 🎯 **Dynamic Confirmation** - Monkeypatches vulnerable functions to confirm actual reachability
- 📊 **Multi-CVE Support** - Analyze multiple CVEs against your codebase in one command
- 🔑 **Easy Configuration** - Simple CLI for API key management
- 📈 **FastAPI/Flask Support** - Works with popular Python web frameworks

## Setup

```bash
uv sync --extra dev
cp .env.example .env   # fill in GROQ_API_KEY (get one at console.groq.com)
```

## Run tests

```bash
uv run pytest -v
```

`test_graph_builder.py` and `test_dynamic_harness.py` run against the dummy
fixture app in `tests/fixtures/dummy_target_app/` and need no API key —
these are your fast inner-loop tests while building Hour 0:30–3:30.

## Run the full pipeline (needs Groq API key)

```bash
uv run python scripts/smoke_test.py
```

Runs both a reachable and a not-reachable case against the dummy fixture,
printing the full trace. This is your first real integration check before
Checkpoint 1 with Engineer B — swap the dummy fixture for the real target
app + real CVE once B has it ready.

## CLI Usage

### Installation

```bash
# Install from this directory
uv pip install -e .

# Or install from PyPI (once published)
pip install praesidium
```

### Quick Start

#### 1. Configure API Key

```bash
# Set your Groq API key (get one at console.groq.com)
uv run praesidium config set-key gsk_your_api_key_here

# Verify configuration
uv run praesidium config show
```

#### 2. Analyze Multiple CVEs

Create a JSON file with your CVE configurations:

```json
[
  {
    "cve_id": "CVE-2023-12345",
    "flagged_function": "save_file",
    "flagged_module": "app.services.upload",
    "flagged_file": "app/services/upload.py",
    "entry_points": ["app.routes.upload_endpoint"],
    "advisory_summary": "Path traversal vulnerability",
    "function_signature": "def save_file(filename, contents)"
  },
  {
    "cve_id": "CVE-2023-67890",
    "flagged_function": "process_data",
    "flagged_module": "app.services.data",
    "flagged_file": "app/services/data.py",
    "entry_points": ["app.routes.data_endpoint"],
    "advisory_summary": "SQL injection vulnerability"
  }
]
```

Run the analysis:

```bash
# Analyze current directory
uv run praesidium run --cves cves.json

# Analyze specific directory
uv run praesidium run --cves cves.json --target /path/to/app

# Get summary only
uv run praesidium run --cves cves.json --summary

# Output as JSON
uv run praesidium run --cves cves.json --output json > results.json
```

#### 3. Check Single CVE

For single CVE analysis:

```bash
# Generate sample config
uv run praesidium init-config cve.json

# Edit the config, then run
uv run praesidium check /path/to/app --cve-config cve.json
```

Or use command-line options:

```bash
uv run praesidium check /path/to/app \
  --cve-id CVE-2023-12345 \
  --flagged-function save_file \
  --flagged-module app.services.upload \
  --flagged-file app/services/upload.py \
  --entry-points app.routes.upload_endpoint \
  --advisory-summary "Path traversal vulnerability"
```

### Available Commands

- `praesidium config set-key <API_KEY>` - Configure Groq API key
- `praesidium config show` - Display current configuration
- `praesidium run --cves <FILE>` - Analyze multiple CVEs from JSON file
- `praesidium check <PATH>` - Check single CVE against target app
- `praesidium init-config <FILE>` - Generate sample CVE config file

## Python API (the interface contract)

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

`CVETarget` and `EngineOutput` in `schemas.py` are the two shapes from
build-plan.md Section 2 — sync any changes to these with Engineer B
immediately, don't let them drift silently.

## LLM provider

Hypothesis generation (`hypothesis.py`) calls Groq's OpenAI-compatible chat
completions endpoint, using `openai/gpt-oss-120b` by default (Groq's
current recommended production model for reasoning workloads — the earlier
`llama-3.3-70b-versatile` was deprecated). Override with `GROQ_MODEL` in
`.env` if you want to try `openai/gpt-oss-20b` for lower latency during
iteration. Groq's speed matters here specifically because Stage 2 can fire
up to 3 calls per CVE (1 initial + 2 retries) inside a live demo.

## Publishing to PyPI

To publish Praesidium to PyPI:

```bash
# 1. Update version in pyproject.toml

# 2. Build the package
uv build

# 3. Test on TestPyPI first (recommended)
uv pip install twine
uv run twine upload --repository testpypi dist/*

# 4. Test install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ praesidium

# 5. If everything works, publish to PyPI
uv run twine upload dist/*
```

**Note:** You'll need PyPI accounts and API tokens. See [PyPI documentation](https://packaging.python.org/tutorials/packaging-projects/) for details.

## Known scope boundaries (by design, not oversight)

- Static graph resolution is name-based, not points-to analysis — decorators
  and dynamic dispatch can produce false negatives at Stage 1. This is why
  Stage 2 exists; don't try to fix it in `graph_builder.py`.
- Retry cap is hard-set to 2 attempts (`nodes.py::MAX_RETRIES`) to keep demo
  runtime bounded. Don't raise it without checking demo timing.
- `EntryPointDriver` supports `callable` and `flask_route` shapes only. If
  B's fixture needs CLI-arg driving, extend `dynamic_harness.py`.
