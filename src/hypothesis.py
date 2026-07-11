"""
Stage 2 hypothesis generation (problem-statement.md Section 3 & 5). Given a
CVE advisory + the flagged function's signature + a real entry point, ask
an LLM (via Groq) to reason about what input triggers the vulnerable
branch, and return it as a structured, drivable input.

This is the actual novel/agentic logic in the whole pipeline — worth
iterating on directly rather than accepting the first draft (build-plan.md
Section 3). Keep the prompt centralized here so it's easy to tune without
touching graph wiring in nodes.py.

Uses Groq's OpenAI-compatible chat completions endpoint for low-latency
inference, which matters here since Stage 2 can call this up to 3 times per
CVE (1 initial + 2 retries) inside a live demo.
"""
from __future__ import annotations

import json
import os

from groq import Groq
from pydantic import BaseModel

# openai/gpt-oss-120b is Groq's current recommended production model for
# general-purpose + reasoning workloads (llama-3.3-70b-versatile was
# deprecated June 2026). Override via GROQ_MODEL if you want to try
# something else -- e.g. openai/gpt-oss-20b for lower latency, or
# qwen/qwen3.6-27b as an alternative to gpt-oss-120b.
DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

_client: Groq | None = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    return _client


class Hypothesis(BaseModel):
    reasoning: str
    hypothesis_input: dict
    # For driver_kind "callable": keys must be EXACTLY the given entry point
    # parameter names, e.g. {"filename": "...", "contents": b"..."}.
    # For driver_kind "flask_route": {"data": {...}|null, "json": {...}|null, "query_string": {...}|null}.


CALLABLE_SYSTEM_PROMPT = """You are the hypothesis-generation step of a CVE \
reachability confirmation agent. You are given a CVE advisory, the \
signature of the flagged vulnerable function, and the REAL parameter names \
of the entry point you must drive. Propose concrete values for those exact \
parameters that, when passed to the entry point, would cause execution to \
reach the flagged function.

Respond with ONLY a JSON object, no prose, no markdown fences:
{
  "reasoning": "<one or two sentences: why these values should reach the vulnerable branch>",
  "hypothesis_input": { "<param_name>": <value>, ... }
}

hypothesis_input MUST have exactly the parameter names given to you as keys
-- no more, no fewer, no renaming, no "args"/"kwargs" wrapper. Do not hedge,
do not explain the CVE back to the user, do not include anything other than
the JSON object."""

FLASK_ROUTE_SYSTEM_PROMPT = """You are the hypothesis-generation step of a \
CVE reachability confirmation agent. You are given a CVE advisory, the \
signature of the flagged vulnerable function, and one real Flask route to \
drive. Propose a concrete HTTP request that, when sent to that route, \
would cause execution to reach the flagged function.

Respond with ONLY a JSON object, no prose, no markdown fences:
{
  "reasoning": "<one or two sentences: why this request should reach the vulnerable branch>",
  "hypothesis_input": {"data": {...} | null, "json": {...} | null, "query_string": {...} | null}
}

Do not hedge, do not explain the CVE back to the user, do not include
anything other than the JSON object."""


def generate_hypothesis(
    cve_id: str,
    advisory_summary: str,
    flagged_function: str,
    function_signature: str | None,
    entry_point: str,
    driver_kind: str,
    prior_attempts: list[str],
    entry_point_params: list[str] | None = None,
) -> Hypothesis:
    prior_block = ""
    if prior_attempts:
        prior_block = (
            "\n\nPrevious hypotheses that did NOT fire the flagged function "
            "(propose something meaningfully different this time):\n"
            + "\n".join(f"- {a}" for a in prior_attempts)
        )

    if driver_kind == "callable":
        system_prompt = CALLABLE_SYSTEM_PROMPT
        params_block = f"\nEntry point parameter names (use exactly these as keys): {entry_point_params}"
    else:
        system_prompt = FLASK_ROUTE_SYSTEM_PROMPT
        params_block = ""

    user_prompt = f"""CVE: {cve_id}
Advisory: {advisory_summary}
Flagged function: {flagged_function}
Function signature: {function_signature or "unknown -- infer a reasonable shape"}
Entry point to drive: {entry_point}{params_block}{prior_block}"""

    response = _get_client().chat.completions.create(
        model=DEFAULT_MODEL,
        max_tokens=1000,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
    )
    raw_text = response.choices[0].message.content
    raw_text = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    hyp = Hypothesis(**json.loads(raw_text))

    if driver_kind == "callable" and entry_point_params is not None:
        got = set(hyp.hypothesis_input.keys())
        expected = set(entry_point_params)
        if got != expected:
            raise ValueError(
                f"Hypothesis param mismatch: model returned keys {got}, "
                f"entry point expects exactly {expected}. Raw response: {raw_text}"
            )

    return hyp
