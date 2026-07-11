"""
CLI interface for the Praesidium engine. Allows running CVE reachability analysis
on any Python project from the command line.

Usage:
    praesidium check /path/to/target_app --cve-config cve_manifest.json
    praesidium run --cves cves.json
    praesidium config set-key YOUR_API_KEY
"""
import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv, set_key, find_dotenv

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box

from .pipeline import run_pipeline
from .schemas import CVETarget, EngineOutput

from .cve_fetcher import fetch_cves_for_dependencies
from .dependency_scanner import get_project_dependencies
from .cve_locator import locate_vulnerable_function

# Load environment variables
load_dotenv()

console = Console()

# ── Theme constants ───────────────────────────────────────────────────────────
COLORS = {
    "Confirmed-Reachable": "bold red",
    "Static-Match-Only":   "bold yellow",
    "Not-Reachable":       "bold green",
}
ICONS = {
    "Confirmed-Reachable": "[red]✘ CRITICAL[/red]",
    "Static-Match-Only":   "[yellow]⚠ WARNING[/yellow]",
    "Not-Reachable":       "[green]✔ SAFE[/green]",
}
BORDER_STYLES = {
    "Confirmed-Reachable": "red",
    "Static-Match-Only":   "yellow",
    "Not-Reachable":       "green",
}

BANNER = r"""[bold cyan]
  ____                        _     _ _
 |  _ \ _ __ __ _  ___  ___(_) __| (_)_   _ _ __ ___
 | |_) | '__/ _` |/ _ \/ __| |/ _` | | | | | '_ ` _ \
 |  __/| | | (_| |  __/\__ \ | (_| | | |_| | | | | | |
 |_|   |_|  \__,_|\___||___/_|\__,_|_|\__,_|_| |_| |_|
[/bold cyan]"""

TAGLINE = "[dim]Dynamic CVE Reachability Confirmation Engine[/dim]"


def _render_banner():
    """Print the ASCII banner."""
    console.print(BANNER, highlight=False)
    console.print(f"  {TAGLINE}    [dim]v0.2.1[/dim]\n", highlight=False)


def _render_result_panel(result: EngineOutput):
    """Render a single CVE result as a rich Panel."""
    label = result.label
    border = BORDER_STYLES.get(label, "white")
    icon = ICONS.get(label, "")

    # ── Build body content ──
    body_parts = []

    # Static path
    if result.static_path:
        path_chain = " [dim]→[/dim] ".join(f"[bold]{s}[/bold]" for s in result.static_path)
        body_parts.append(f"[dim]Static Path:[/dim]  {path_chain}")
    else:
        body_parts.append("[dim]Static Path:[/dim]  [dim italic]No path found[/dim italic]")

    # Hypothesis attempts
    if result.hypothesis_attempts:
        body_parts.append("")
        body_parts.append(f"[dim]Hypothesis Attempts ({len(result.hypothesis_attempts)}):[/dim]")
        for i, attempt in enumerate(result.hypothesis_attempts, 1):
            # Truncate long attempts for display
            short = attempt[:200] + "…" if len(attempt) > 200 else attempt
            body_parts.append(f"  [dim]{i}.[/dim] {short}")

    # Trace
    body_parts.append("")
    body_parts.append("[dim]Trace:[/dim]")
    for step in result.trace:
        stage_color = {
            "static": "cyan",
            "hypothesis": "magenta",
            "dynamic": "blue",
            "decide": "white",
        }.get(step.stage, "white")
        body_parts.append(f"  [{stage_color}][{step.stage}][/{stage_color}] {step.detail}")

    body = "\n".join(body_parts)

    title = f"{result.cve_id}  {icon}"
    subtitle = f"[{COLORS.get(label, 'white')}]{label}[/{COLORS.get(label, 'white')}]"

    console.print(Panel(
        body,
        title=title,
        subtitle=subtitle,
        border_style=border,
        padding=(1, 2),
        expand=True,
    ))


def _render_summary(results: list[Optional[EngineOutput]]):
    """Render a summary table of all results."""
    confirmed = sum(1 for r in results if r and r.label == "Confirmed-Reachable")
    static_only = sum(1 for r in results if r and r.label == "Static-Match-Only")
    not_reachable = sum(1 for r in results if r and r.label == "Not-Reachable")
    errors = sum(1 for r in results if r is None)

    console.print()
    console.print(Rule("[bold]Summary[/bold]", style="cyan"))
    console.print()

    # Stats line
    stats = Text()
    stats.append(f"  Total: {len(results)}   ")
    stats.append(f"Critical: {confirmed}", style="bold red")
    stats.append("   ")
    stats.append(f"Warning: {static_only}", style="bold yellow")
    stats.append("   ")
    stats.append(f"Safe: {not_reachable}", style="bold green")
    if errors:
        stats.append("   ")
        stats.append(f"Errors: {errors}", style="bold red")
    console.print(stats)
    console.print()

    # Results table
    table = Table(
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("CVE ID", style="bold", ratio=2)
    table.add_column("Label", justify="center", ratio=2)
    table.add_column("Static Path", justify="center", ratio=1)
    table.add_column("Status", justify="center", ratio=1)

    for result in results:
        if result is None:
            table.add_row("[dim]—[/dim]", "[dim]Error[/dim]", "—", "[red]✘[/red]")
            continue

        label = result.label
        label_styled = f"[{COLORS.get(label, 'white')}]{label}[/{COLORS.get(label, 'white')}]"
        has_path = "[green]Yes[/green]" if result.static_path else "[dim]No[/dim]"
        icon = ICONS.get(label, "")

        table.add_row(result.cve_id, label_styled, has_path, icon)

    console.print(table)
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Commands
# ═══════════════════════════════════════════════════════════════════════════════

@click.group()
@click.version_option(version="0.2.1", prog_name="praesidium")
def main():
    """Praesidium — Dynamic CVE reachability confirmation engine"""
    pass


@main.command()
@click.argument("target_app_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--cve-config",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to JSON file containing CVE target configuration",
)
@click.option("--cve-id", help="CVE identifier (e.g., CVE-2023-12345)")
@click.option("--flagged-function", help="Function name (e.g., UploadHandler.save_file)")
@click.option("--flagged-module", help="Module path (e.g., app.services.upload)")
@click.option("--flagged-file", help="File path (e.g., app/services/upload.py)")
@click.option(
    "--entry-points",
    multiple=True,
    help="Entry points to check (can be specified multiple times)",
)
@click.option("--advisory-summary", default="", help="CVE advisory summary")
@click.option("--function-signature", help="Function signature for context")
@click.option(
    "--driver-kind",
    type=click.Choice(["callable", "flask_route"]),
    default="callable",
    help="Type of driver to use",
)
@click.option("--flask-app-import", help="Flask app import path (module:variable)")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
def check(
    target_app_root: Path,
    cve_config: Optional[Path],
    cve_id: Optional[str],
    flagged_function: Optional[str],
    flagged_module: Optional[str],
    flagged_file: Optional[str],
    entry_points: tuple[str, ...],
    advisory_summary: str,
    function_signature: Optional[str],
    driver_kind: str,
    flask_app_import: Optional[str],
    output: str,
):
    """
    Check if a CVE is reachable in the target application.

    TARGET_APP_ROOT is the path to the Python application to analyze.

    You can provide CVE details either via --cve-config JSON file or via individual options.

    Example using JSON config:
        reach check /path/to/app --cve-config cve.json

    Example using command-line options:
        reach check /path/to/app --cve-id CVE-2023-12345 \\
            --flagged-function UploadHandler.save_file \\
            --flagged-module app.services.upload \\
            --flagged-file app/services/upload.py \\
            --entry-points app.routes.upload_endpoint \\
            --entry-points app.api.v1.upload
    """
    # Load CVE target from config file or command-line options
    if cve_config:
        target = _load_cve_config(cve_config)
    elif all([cve_id, flagged_function, flagged_module, flagged_file]):
        target = CVETarget(
            cve_id=cve_id,
            flagged_function=flagged_function,
            flagged_module=flagged_module,
            flagged_file=flagged_file,
            entry_points=list(entry_points),
            advisory_summary=advisory_summary,
            function_signature=function_signature,
            driver_kind=driver_kind,  # type: ignore
            flask_app_import=flask_app_import,
        )
    else:
        console.print(
            "[red]Error:[/red] Must provide either --cve-config or all of: "
            "--cve-id, --flagged-function, --flagged-module, --flagged-file",
        )
        sys.exit(1)

    # Run the pipeline
    try:
        result = run_pipeline(target, str(target_app_root))
        if output == "json":
            click.echo(result.model_dump_json(indent=2))
        else:
            _render_result_panel(result)
    except Exception as e:
        console.print(f"[red]Error running pipeline:[/red] {e}")
        sys.exit(1)


def _load_cve_config(config_path: Path) -> CVETarget:
    """Load CVE target configuration from JSON file."""
    try:
        with open(config_path) as f:
            data = json.load(f)
        return CVETarget.model_validate(data)
    except Exception as e:
        console.print(f"[red]Error loading config file:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("output_file", type=click.Path(path_type=Path))
def init_config(output_file: Path):
    """
    Generate a sample CVE configuration file.

    Example:
        praesidium init-config cve.json
    """
    sample_config = {
        "cve_id": "CVE-YYYY-XXXXX",
        "flagged_function": "ClassName.method_name",
        "flagged_module": "app.services.module_name",
        "flagged_file": "app/services/module_name.py",
        "entry_points": [
            "app.routes.endpoint_name",
            "app.api.v1.another_endpoint"
        ],
        "advisory_summary": "Brief description of the vulnerability",
        "function_signature": "def method_name(self, param1, param2)",
        "driver_kind": "callable",
        "flask_app_import": None,
        "entry_point_routes": {}
    }

    with open(output_file, "w") as f:
        json.dump(sample_config, f, indent=2)

    console.print(f"[green]✔[/green] Sample configuration written to [bold]{output_file}[/bold]")
    console.print("Edit this file with your CVE details and run:")
    console.print(f"  [cyan]praesidium check /path/to/app --cve-config {output_file}[/cyan]")


@main.command()
@click.argument(
    "target_app_root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    default=Path("cves.json"),
    help="Where to write the fetched CVE manifest (default: cves.json)",
)
@click.option(
    "--include-no-cve",
    is_flag=True,
    help="Also include OSV advisories with no assigned CVE ID (uses the OSV id instead)",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Print per-package OSV query results, to distinguish 'genuinely clean' from errors",
)
@click.option(
    "--locate/--no-locate",
    default=False,
    help="Agentically try to fill in flagged_function/module/file by fetching each "
         "CVE's reference pages (fix commits, advisories) and asking an LLM to "
         "extract them. Requires GROQ_API_KEY. Adds network + LLM calls per CVE.",
)
def fetch(target_app_root: Path, output: Path, include_no_cve: bool, verbose: bool, locate: bool):
    """
    Scan the target project's dependencies and fetch known CVEs for them
    from OSV.dev, writing a draft CVE manifest.
    ...
    """
    console.print(f"[cyan]Scanning dependencies in[/cyan] {target_app_root}...")
    deps = get_project_dependencies(target_app_root)
    if not deps:
        console.print(
            "[red]No dependencies found[/red] (no uv.lock, and no pyproject.toml with dependencies).",
        )
        sys.exit(1)

    resolved = [d for d in deps if d.version]
    unresolved = len(deps) - len(resolved)
    console.print(
        f"Found [bold]{len(deps)}[/bold] dependencies ([bold]{len(resolved)}[/bold] with a resolvable version"
        + (f", {unresolved} skipped — no version found)" if unresolved else ")")
    )
    console.print("[cyan]Querying OSV.dev for known vulnerabilities...[/cyan]")

    raw_results = fetch_cves_for_dependencies(resolved, verbose=verbose)

    n_no_cve = sum(1 for r in raw_results if r["cve_id"] is None and r["osv_id"])
    if n_no_cve and not include_no_cve:
        console.print(
            f"[dim]Note: OSV returned {n_no_cve} advisory(ies) with no CVE id assigned "
            "(re-run with --include-no-cve to keep them).[/dim]"
        )

    manifest = []
    seen_ids = set()
    for r in raw_results:
        cve_id = r["cve_id"]
        if cve_id is None and not include_no_cve:
            continue
        display_id = cve_id or r["osv_id"] or "UNKNOWN"
        if display_id in seen_ids:
            continue
        seen_ids.add(display_id)

        flagged_function = "REPLACE_ME  # e.g. ClassName.method_name"
        flagged_module = "REPLACE_ME  # e.g. app.services.module_name"
        flagged_file = "REPLACE_ME  # e.g. app/services/module_name.py"
        locate_note = ""

        if locate and r.get("references"):
            if verbose:
                console.print(f"  [dim]Locating {display_id} ({r['package']})...[/dim]", highlight=False)
            loc = locate_vulnerable_function(
                cve_id=display_id,
                package=r["package"],
                version=r["version"],
                advisory_summary=r["summary"],
                references=r["references"],
            )
            if loc.confident and loc.flagged_module and loc.flagged_function:
                flagged_module = loc.flagged_module
                flagged_file = loc.flagged_file or flagged_file
                flagged_function = loc.flagged_function
                locate_note = f" [auto-located: {loc.reasoning}]"
            elif verbose:
                console.print(f"    [dim]not confident: {loc.reasoning}[/dim]", highlight=False)

        manifest.append({
            "cve_id": display_id,
            "flagged_function": flagged_function,
            "flagged_module": flagged_module,
            "flagged_file": flagged_file,
            "entry_points": [],
            "advisory_summary": f"[{r['package']}=={r['version']}] {r['summary']}{locate_note}",
            "function_signature": None,
            "driver_kind": "callable",
            "flask_app_import": None,
            "entry_point_routes": {},
        })

    with open(output, "w") as f:
        json.dump(manifest, f, indent=2)

    auto_located = sum(1 for m in manifest if "REPLACE_ME" not in m["flagged_function"])
    if locate:
        console.print(f"  [green]{auto_located}/{len(manifest)}[/green] auto-located with high confidence")

    console.print(f"\n[green]✔[/green] Wrote [bold]{len(manifest)}[/bold] CVE entries to [bold]{output}[/bold]")
    if manifest:
        console.print(
            "[dim]Review flagged_function / flagged_module / flagged_file (especially any "
            "still marked REPLACE_ME) and fill in entry_points, then run:[/dim]"
        )
        console.print(f"  [cyan]praesidium run --cves {output}[/cyan]")


@main.group()
def config():
    """Manage Praesidium configuration (API keys, settings)."""
    pass


@config.command(name="set-key")
@click.argument("api_key")
@click.option(
    "--env-file",
    type=click.Path(path_type=Path),
    default=".env",
    help="Path to .env file (default: .env in current directory)",
)
def set_api_key(api_key: str, env_file: Path):
    """
    Set the Groq API key for hypothesis generation.

    Example:
        praesidium config set-key gsk_your_api_key_here
    """
    # Create .env file if it doesn't exist
    if not env_file.exists():
        env_file.touch()
        console.print(f"[dim]Created {env_file}[/dim]")

    # Set the key
    set_key(str(env_file), "GROQ_API_KEY", api_key)
    console.print(f"[green]✔[/green] API key saved to [bold]{env_file}[/bold]")
    console.print("[dim]You can now run CVE checks without setting the environment variable manually.[/dim]")


@config.command(name="show")
@click.option(
    "--env-file",
    type=click.Path(exists=True, path_type=Path),
    default=".env",
    help="Path to .env file",
)
def show_config(env_file: Path):
    """
    Show current configuration.

    Example:
        praesidium config show
    """
    if not env_file.exists():
        console.print(f"[yellow]No configuration file found at {env_file}[/yellow]")
        return

    load_dotenv(str(env_file))
    api_key = os.getenv("GROQ_API_KEY")

    console.print(f"\n[bold]Configuration[/bold] [dim]from {env_file}[/dim]")
    console.print(Rule(style="dim"))
    if api_key:
        # Mask the API key for security
        masked_key = api_key[:8] + "*" * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else "***"
        console.print(f"  GROQ_API_KEY: [green]{masked_key}[/green]")
    else:
        console.print("  GROQ_API_KEY: [red]Not set[/red]")
    console.print(Rule(style="dim"))


@main.command()
@click.option(
    "--cves",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to JSON file containing array of CVE configurations",
)
@click.option(
    "--target",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Target application root directory (default: current directory)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option(
    "--summary",
    is_flag=True,
    help="Show only summary of results",
)
def run(cves: Path, target: Path, output: str, summary: bool):
    """
    Run CVE reachability checks against the current project.

    This command reads multiple CVE configurations from a JSON file and
    checks them all against the target application.

    Example:
        praesidium run --cves cves.json
        praesidium run --cves cves.json --target /path/to/app
        praesidium run --cves cves.json --output json > results.json

    CVEs JSON format:
        [
          {
            "cve_id": "CVE-2023-12345",
            "flagged_function": "save_file",
            ...
          },
          {
            "cve_id": "CVE-2023-67890",
            ...
          }
        ]
    """
    # Load CVEs from JSON
    try:
        with open(cves) as f:
            cves_data = json.load(f)

        if not isinstance(cves_data, list):
            console.print("[red]Error:[/red] CVEs file must contain a JSON array of CVE configurations")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading CVEs file:[/red] {e}")
        sys.exit(1)

    # Validate and parse CVE targets
    targets = []
    for i, cve_data in enumerate(cves_data):
        try:
            target_obj = CVETarget.model_validate(cve_data)
            targets.append(target_obj)
        except Exception as e:
            console.print(f"[red]Error parsing CVE at index {i}:[/red] {e}")
            sys.exit(1)

    # Run analysis on all CVEs
    results = []
    target_path = str(target.resolve())

    if output == "text" and not summary:
        _render_banner()
        console.print(f"  [dim]Target:[/dim]  [bold]{target_path}[/bold]")
        console.print(f"  [dim]CVEs:[/dim]    [bold]{len(targets)}[/bold] loaded from [bold]{cves}[/bold]")
        console.print()
        console.print(Rule(style="dim"))
        console.print()

    for i, target_obj in enumerate(targets, 1):
        try:
            if output == "text" and not summary:
                console.print(f"  [cyan]▸[/cyan] [{i}/{len(targets)}] Analyzing [bold]{target_obj.cve_id}[/bold]...")

            result = run_pipeline(target_obj, target_path)
            results.append(result)

            if output == "text" and not summary:
                console.print()
                _render_result_panel(result)
        except Exception as e:
            console.print(f"[red]Error analyzing {target_obj.cve_id}:[/red] {e}")
            results.append(None)

    # Output results
    if output == "json":
        json_results = [r.model_dump() if r else None for r in results]
        click.echo(json.dumps(json_results, indent=2))
    elif summary or len(targets) > 1:
        _render_summary(results)


if __name__ == "__main__":
    main()