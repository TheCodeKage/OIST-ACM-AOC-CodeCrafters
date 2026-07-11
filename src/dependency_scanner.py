"""
Enumerates local dependencies (name + installed version) for the target
project, so `praesidium fetch` knows what packages to query for known CVEs.

Resolution order:
  1. uv.lock — exact resolved versions for every package in the dep graph
     (direct + transitive). Most accurate, so preferred whenever present.
  2. pyproject.toml — direct dependency names/constraints only. If a
     constraint isn't an exact pin, we fall back to whatever's actually
     installed in the current Python environment via importlib.metadata.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    name: str
    version: str | None  # None if we couldn't resolve a concrete version


def _project_name(project_root: Path) -> str | None:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return None
    data = tomllib.loads(pyproject.read_text())
    return data.get("project", {}).get("name")


def _from_uv_lock(project_root: Path) -> list[Dependency] | None:
    lock_path = project_root / "uv.lock"
    if not lock_path.exists():
        return None
    data = tomllib.loads(lock_path.read_text())
    self_name = _project_name(project_root)
    deps = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and name != self_name:
            deps.append(Dependency(name=name, version=version))
    return deps


_REQ_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]+\])?\s*(.*)$")


def _parse_requirement(spec: str) -> tuple[str, str | None]:
    """Best-effort PEP 508 parse: 'click>=8.1.0' -> ('click', None) since
    that's a range, not an installed version. Only an exact '==' pin counts
    as a resolved version here; everything else gets filled in later from
    the live environment."""
    match = _REQ_RE.match(spec.strip())
    if not match:
        return spec.strip(), None
    name = match.group(1)
    constraint = match.group(2).strip()
    if constraint.startswith("=="):
        return name, constraint[2:].strip()
    return name, None


def _from_pyproject(project_root: Path) -> list[Dependency] | None:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return None
    data = tomllib.loads(pyproject.read_text())
    project = data.get("project", {})
    raw_deps = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        raw_deps.extend(extra_deps)
    return [Dependency(*_parse_requirement(spec)) for spec in raw_deps]


def _fill_installed_versions(deps: list[Dependency]) -> list[Dependency]:
    """Fills in missing versions from what's actually installed in this
    Python environment via importlib.metadata."""
    import importlib.metadata as im

    resolved = []
    for dep in deps:
        version = dep.version
        if version is None:
            try:
                version = im.version(dep.name)
            except im.PackageNotFoundError:
                version = None
        resolved.append(Dependency(name=dep.name, version=version))
    return resolved


def get_project_dependencies(project_root: str | Path) -> list[Dependency]:
    """Public entry point: name + version for every dependency of the
    project at project_root. Prefers uv.lock; falls back to
    pyproject.toml + live-environment introspection."""
    root = Path(project_root).resolve()

    deps = _from_uv_lock(root)
    if deps is not None:
        return deps

    deps = _from_pyproject(root)
    if deps is None:
        return []
    return _fill_installed_versions(deps)