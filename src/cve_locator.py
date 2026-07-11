"""
Stage 0.5 (agentic pre-processing for `praesidium fetch`): given an OSV
vulnerability record for a specific dependency, try to determine where in
that dependency's OWN source tree the vulnerable code lives -- i.e. fill in
flagged_module / flagged_file / flagged_function so a generated cves.json
entry is actually drivable by dynamic_harness.py, instead of shipping with
REPLACE_ME placeholders.

Approach: OSV advisories almost always link primary references (GHSA page,
a "fixed commit" diff, sometimes the advisory's own text) via
vuln["references"]. We fetch a handful of those pages, hand the raw text
+ diff content to an LLM (Groq, same provider as hypothesis.py), and ask
it to extract module/file/function names -- treating this the same way
hypothesis.py treats reachability: a best-effort inference, not ground
truth, that the person MUST review before running the pipeline.

This is best-effort by nature. Advisory writeups vary wildly in quality
and structure; a fix-commit diff is usually the most reliable signal since
it shows the literal function that changed, but not every advisory has
one. Low-confidence or failed extractions fall back to the REPLACE_ME
placeholders `cli.py` already emits -- we never fabricate a
plausible-sounding function name with no textual support.
"""
from __future__ import annotations

import json
import os
import re

import httpx
from groq import Groq
from pydantic import BaseModel

DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

_client: Groq | None = None


def _get_client() -> Groq:
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    return _client


class LocateResult(BaseModel):
    confident: bool
    flagged_module: str | None = None      # importable dotted path, e.g. "yaml.loader"
    flagged_file: str | None = None        # path within the package, e.g. "yaml/loader.py"
    flagged_function: str | None = None    # e.g. "Loader.construct_python_object" or "load"
    reasoning: str


SYSTEM_PROMPT = """You are the CVE-localization step of a reachability \
confirmation pipeline. You are given a CVE/advisory summary for a Python \
package, and raw text scraped from one or more reference pages (advisory \
page, GitHub fix commit, issue tracker, etc). Your job is to determine \
EXACTLY where in the PACKAGE'S OWN source the vulnerable function lives \
-- not in any downstream application, just the library itself.

Respond with ONLY a JSON object, no prose, no markdown fences:
{
  "confident": true | false,
  "flagged_module": "<importable dotted module path within the package, or null>",
  "flagged_file": "<file path within the package's source tree, or null>",
  "flagged_function": "<function or Class.method name, or null>",
  "reasoning": "<one or two sentences citing what evidence you used>"
}

Set "confident" to false (and the other fields to null) if the scraped \
text does not give you enough evidence to name a specific function --
do NOT guess a plausible-sounding function name with no textual support.
A fix commit's diff, if present, is the strongest evidence: the function(s)
touched by the diff are very likely the flagged function. Advisory prose
naming a specific function/method is also strong evidence. General
descriptions of the vulnerability class (e.g. "path traversal in file
handling") without a named function are NOT enough for confidence."""


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\n{3,}")


def _strip_html(html: str) -> str:
    """Very lightweight HTML->text: good enough for feeding advisory pages
    to the LLM without pulling in a full HTML parser dependency. Not meant
    to produce clean prose, just remove markup noise."""
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub("\n\n", text)
    return text.strip()


def fetch_reference_text(url: str, client: httpx.Client, max_chars: int = 6000) -> str | None:
    """Fetches a single OSV reference URL and returns cleaned, truncated
    text. GitHub commit URLs get `.diff` appended when possible, since the
    raw diff is far more information-dense than the rendered HTML page."""
    fetch_url = url
    if "github.com" in url and "/commit/" in url and not url.endswith((".diff", ".patch")):
        fetch_url = url.rstrip("/") + ".diff"

    try:
        resp = client.get(fetch_url, timeout=10.0, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError:
        return None

    body = resp.text
    if "html" in resp.headers.get("content-type", ""):
        body = _strip_html(body)
    return body[:max_chars]


def locate_vulnerable_function(
    cve_id: str,
    package: str,
    version: str,
    advisory_summary: str,
    references: list[str],
    max_references: int = 3,
) -> LocateResult:
    """Best-effort agentic step: fetches a few OSV reference pages for this
    CVE and asks an LLM to extract flagged_module/flagged_file/
    flagged_function from their content. Never raises on network/parse
    failure -- returns confident=False instead, so callers can fall back
    to placeholders."""
    snippets = []
    with httpx.Client() as client:
        for url in references[:max_references]:
            text = fetch_reference_text(url, client)
            if text:
                snippets.append(f"--- {url} ---\n{text}")

    if not snippets:
        return LocateResult(
            confident=False,
            reasoning="No fetchable reference pages were available for this advisory.",
        )

    user_prompt = f"""CVE: {cve_id}
Package: {package} (PyPI), version {version}
Advisory summary: {advisory_summary}

Reference page content:
{chr(10).join(snippets)}"""

    try:
        response = _get_client().chat.completions.create(
            model=DEFAULT_MODEL,
            max_tokens=500,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        raw_text = response.choices[0].message.content
        raw_text = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return LocateResult(**json.loads(raw_text))
    except Exception as exc:
        return LocateResult(
            confident=False,
            reasoning=f"Locator LLM call failed or returned malformed output: {exc}",
        )