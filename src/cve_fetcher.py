"""
Queries OSV.dev (https://osv.dev) for known vulnerabilities affecting the
project's resolved dependencies. OSV needs no API key and covers PyPI
natively -- that's why it's used here instead of the NVD API, which needs
a key for reasonable rate limits.
"""
from __future__ import annotations

import httpx

from .dependency_scanner import Dependency

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _extract_cve_id(vuln: dict) -> str | None:
    """OSV's own "id" is often a GHSA-/PYSEC- id, not a CVE-. The CVE
    number, if one was assigned, usually shows up in "aliases"."""
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return None


def fetch_cves_for_dependency(dep: Dependency, client: httpx.Client) -> list[dict]:
    """Returns [{"cve_id", "osv_id", "summary", "package", "version"}, ...]
    for known vulnerabilities affecting this exact package+version. Skips
    packages with no resolvable version -- OSV's /query endpoint needs a
    concrete version, not a range."""
    if not dep.version:
        return []

    resp = client.post(
        OSV_QUERY_URL,
        json={"version": dep.version, "package": {"name": dep.name, "ecosystem": "PyPI"}},
        timeout=15.0,
    )
    resp.raise_for_status()
    vulns = resp.json().get("vulns", [])

    results = []
    for vuln in vulns:
        cve_id = _extract_cve_id(vuln)
        summary = (vuln.get("summary") or vuln.get("details") or "").strip()
        results.append({
            "cve_id": cve_id,
            "osv_id": vuln.get("id"),
            "summary": summary  [:500],
            "package": dep.name,
            "version": dep.version,
        })
    return results


def fetch_cves_for_dependencies(deps: list[Dependency], verbose: bool = False) -> list[dict]:
    """Queries OSV once per dependency. (OSV also offers a /querybatch
    endpoint -- worth switching to if this becomes a bottleneck on large
    dependency trees, but /query keeps per-package error handling simple.)
    A failure on one package doesn't abort the whole scan; it's surfaced
    as an entry instead.

    When verbose=True, prints one line per package to stderr showing how
    many advisories OSV returned and how many carried a CVE id -- the only
    way to tell "genuinely clean" apart from a swallowed error or an OSV
    advisory with no CVE assigned."""
    import click

    all_results: list[dict] = []
    with httpx.Client() as client:
        for dep in deps:
            try:
                dep_results = fetch_cves_for_dependency(dep, client)
            except httpx.HTTPError as exc:
                if verbose:
                    click.echo(f"  [ERROR] {dep.name}=={dep.version}: {exc}", err=True)
                all_results.append({
                    "cve_id": None,
                    "osv_id": None,
                    "summary": f"[ERROR fetching CVEs for {dep.name}=={dep.version}: {exc}]",
                    "package": dep.name,
                    "version": dep.version,
                })
                continue

            if verbose:
                n_cve = sum(1 for r in dep_results if r["cve_id"])
                if dep_results:
                    click.echo(
                        f"  {dep.name}=={dep.version}: {len(dep_results)} advisory(ies), "
                        f"{n_cve} with a CVE id",
                        err=True,
                    )
                else:
                    click.echo(f"  {dep.name}=={dep.version}: none", err=True)

                all_results.extend(dep_results)
        return all_results