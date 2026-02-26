"""Command-line interface for KubeShield."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from kubeshield import __version__
from kubeshield.ai import AIAdvisor
from kubeshield.report import ConsoleReporter, JSONReporter
from kubeshield.scanner import Scanner

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="kubeshield")
def main() -> None:
    """KubeShield — AI-powered Kubernetes manifest security scanner."""


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--severity",
    "-s",
    multiple=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Filter by severity (can be specified multiple times).",
)
@click.option(
    "--rule",
    "-r",
    "rule_ids",
    multiple=True,
    help="Filter by rule ID (can be specified multiple times).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Write JSON report to file.",
)
@click.option(
    "--json",
    "json_stdout",
    is_flag=True,
    help="Output JSON report to stdout.",
)
@click.option(
    "--ai",
    "use_ai",
    is_flag=True,
    help="Get AI-powered remediation suggestions (requires OPENAI_API_KEY).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "any"], case_sensitive=False),
    default="high",
    show_default=True,
    help="Minimum severity to trigger a non-zero exit code.",
)
def scan(
    paths: tuple[str, ...],
    severity: tuple[str, ...],
    rule_ids: tuple[str, ...],
    output: str | None,
    json_stdout: bool,
    use_ai: bool,
    fail_on: str,
) -> None:
    """Scan Kubernetes manifests for security issues."""
    scanner = Scanner(
        rule_ids=list(rule_ids) if rule_ids else None,
        severities=list(severity) if severity else None,
    )

    scan_paths = [Path(p) for p in paths]
    result = scanner.scan(scan_paths)

    if json_stdout:
        reporter = JSONReporter()
        click.echo(reporter.generate(result))
    else:
        reporter = ConsoleReporter(console)
        reporter.print_report(result)

    if output:
        json_reporter = JSONReporter()
        json_reporter.write(result, Path(output))
        console.print(f"\n[dim]JSON report written to {output}[/dim]")

    if use_ai:
        advisor = AIAdvisor()
        console.print()
        with console.status("[bold blue]Asking AI advisor for remediation plan..."):
            advice = advisor.advise(result)
        console.print(
            Panel(
                Markdown(advice) if advisor.available else advice,
                title="[bold blue]AI Remediation Advisor[/bold blue]",
                border_style="blue",
            )
        )

    exit_code = _compute_exit_code(result, fail_on)
    raise SystemExit(exit_code)


@main.command(name="rules")
def list_rules() -> None:
    """List all available security rules."""
    from rich.table import Table

    from kubeshield.rules import registry

    table = Table(title="KubeShield Rules", show_lines=True, border_style="dim")
    table.add_column("ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=15)
    table.add_column("Name", width=30)
    table.add_column("Description", ratio=1)

    for rule_cls in sorted(registry, key=lambda r: r.meta.rule_id):
        sev = rule_cls.meta.severity
        table.add_row(
            rule_cls.meta.rule_id,
            f"{sev.icon} {sev.value}",
            rule_cls.meta.category.value,
            rule_cls.meta.name,
            rule_cls.meta.description[:80] + "..." if len(rule_cls.meta.description) > 80 else rule_cls.meta.description,
        )

    console.print(table)


def _compute_exit_code(result, fail_on: str) -> int:
    severity_thresholds = {
        "critical": result.critical_count > 0,
        "high": result.critical_count > 0 or result.high_count > 0,
        "medium": result.critical_count > 0 or result.high_count > 0 or result.medium_count > 0,
        "low": result.total_findings > 0,
        "any": result.total_findings > 0,
    }
    return 1 if severity_thresholds.get(fail_on, False) else 0
