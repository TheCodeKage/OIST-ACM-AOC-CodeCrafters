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

from .pipeline import run_pipeline
from .schemas import CVETarget, EngineOutput

# Load environment variables
load_dotenv()


@click.group()
@click.version_option(version="0.1.0", prog_name="praesidium")
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
        click.echo(
            "Error: Must provide either --cve-config or all of: "
            "--cve-id, --flagged-function, --flagged-module, --flagged-file",
            err=True,
        )
        sys.exit(1)

    # Run the pipeline
    try:
        result = run_pipeline(target, str(target_app_root))
        _output_result(result, output)
    except Exception as e:
        click.echo(f"Error running pipeline: {e}", err=True)
        sys.exit(1)


def _load_cve_config(config_path: Path) -> CVETarget:
    """Load CVE target configuration from JSON file."""
    try:
        with open(config_path) as f:
            data = json.load(f)
        return CVETarget.model_validate(data)
    except Exception as e:
        click.echo(f"Error loading config file: {e}", err=True)
        sys.exit(1)


def _output_result(result: EngineOutput, format: str):
    """Output the result in the specified format."""
    if format == "json":
        click.echo(result.model_dump_json(indent=2))
    else:
        # Text format
        click.echo(f"\n{'='*60}")
        click.echo(f"CVE ID: {result.cve_id}")
        click.echo(f"Label: {click.style(result.label, fg=_get_label_color(result.label), bold=True)}")
        click.echo(f"{'='*60}\n")

        if result.static_path:
            click.echo("Static Analysis Path:")
            for step in result.static_path:
                click.echo(f"  → {step}")
            click.echo()

        if result.hypothesis_attempts:
            click.echo(f"Hypothesis Attempts ({len(result.hypothesis_attempts)}):")
            for i, attempt in enumerate(result.hypothesis_attempts, 1):
                click.echo(f"  {i}. {attempt}")
            click.echo()

        click.echo("Trace:")
        for step in result.trace:
            click.echo(f"  [{step.stage}] {step.detail}")
        click.echo()


def _get_label_color(label: str) -> str:
    """Get color for label output."""
    if label == "Confirmed-Reachable":
        return "red"
    elif label == "Static-Match-Only":
        return "yellow"
    else:
        return "green"


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

    click.echo(f"Sample configuration written to {output_file}")
    click.echo("Edit this file with your CVE details and run:")
    click.echo(f"  praesidium check /path/to/app --cve-config {output_file}")


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
        click.echo(f"Created {env_file}")

    # Set the key
    set_key(str(env_file), "GROQ_API_KEY", api_key)
    click.echo(f"[OK] API key saved to {env_file}")
    click.echo("You can now run CVE checks without setting the environment variable manually.")


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
        click.echo(f"No configuration file found at {env_file}")
        return

    load_dotenv(str(env_file))
    api_key = os.getenv("GROQ_API_KEY")

    click.echo(f"\nConfiguration from {env_file}:")
    click.echo("=" * 50)
    if api_key:
        # Mask the API key for security
        masked_key = api_key[:8] + "*" * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else "***"
        click.echo(f"GROQ_API_KEY: {masked_key}")
    else:
        click.echo("GROQ_API_KEY: Not set")
    click.echo("=" * 50)


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
            click.echo("Error: CVEs file must contain a JSON array of CVE configurations", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error loading CVEs file: {e}", err=True)
        sys.exit(1)

    # Validate and parse CVE targets
    targets = []
    for i, cve_data in enumerate(cves_data):
        try:
            target_obj = CVETarget.model_validate(cve_data)
            targets.append(target_obj)
        except Exception as e:
            click.echo(f"Error parsing CVE at index {i}: {e}", err=True)
            sys.exit(1)

    # Run analysis on all CVEs
    results = []
    target_path = str(target.resolve())

    if output == "text" and not summary:
        click.echo(f"\n{'='*60}")
        click.echo(f"Running Praesidium analysis on {len(targets)} CVE(s)")
        click.echo(f"Target: {target_path}")
        click.echo(f"{'='*60}\n")

    for i, target_obj in enumerate(targets, 1):
        try:
            if output == "text" and not summary:
                click.echo(f"[{i}/{len(targets)}] Analyzing {target_obj.cve_id}...")

            result = run_pipeline(target_obj, target_path)
            results.append(result)

            if output == "text" and not summary:
                _output_result(result, "text")
        except Exception as e:
            click.echo(f"Error analyzing {target_obj.cve_id}: {e}", err=True)
            results.append(None)

    # Output results
    if output == "json":
        json_results = [r.model_dump() if r else None for r in results]
        click.echo(json.dumps(json_results, indent=2))
    elif summary or len(targets) > 1:
        _output_summary(results)


def _output_summary(results: list[Optional[EngineOutput]]):
    """Output a summary table of results."""
    click.echo(f"\n{'='*80}")
    click.echo("SUMMARY")
    click.echo(f"{'='*80}")

    confirmed = sum(1 for r in results if r and r.label == "Confirmed-Reachable")
    static_only = sum(1 for r in results if r and r.label == "Static-Match-Only")
    not_reachable = sum(1 for r in results if r and r.label == "Not-Reachable")
    errors = sum(1 for r in results if r is None)

    click.echo(f"\nTotal CVEs analyzed: {len(results)}")
    click.echo(f"  {click.style('Confirmed-Reachable:', fg='red')} {confirmed}")
    click.echo(f"  {click.style('Static-Match-Only:', fg='yellow')} {static_only}")
    click.echo(f"  {click.style('Not-Reachable:', fg='green')} {not_reachable}")
    if errors > 0:
        click.echo(f"  {click.style('Errors:', fg='red')} {errors}")

    click.echo(f"\n{'CVE ID':<20} {'Label':<25} {'Static Path'}")
    click.echo("-" * 80)

    for result in results:
        if result is None:
            continue

        label_colored = click.style(result.label, fg=_get_label_color(result.label))
        has_path = "Yes" if result.static_path else "No"
        click.echo(f"{result.cve_id:<20} {label_colored:<33} {has_path}")

    click.echo(f"{'='*80}\n")


if __name__ == "__main__":
    main()
