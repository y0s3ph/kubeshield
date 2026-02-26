"""Rich console report output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from kubeshield.models import ScanResult, Severity


class ConsoleReporter:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_report(self, result: ScanResult) -> None:
        self.console.print()
        self._print_header()
        self._print_summary(result)

        if result.findings:
            self._print_findings_table(result)

        if result.errors:
            self._print_errors(result)

        self._print_score(result)
        self.console.print()

    def _print_header(self) -> None:
        header = Text()
        header.append("  KUBESHIELD  ", style="bold white on blue")
        header.append("  Kubernetes Security Scanner", style="bold blue")
        self.console.print(Panel(header, border_style="blue", expand=False))

    def _print_summary(self, result: ScanResult) -> None:
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="bold")
        summary.add_column()
        summary.add_row("Files scanned:", str(result.files_scanned))
        summary.add_row("Resources scanned:", str(result.resources_scanned))
        summary.add_row("Total findings:", str(result.total_findings))
        summary.add_row(
            "Breakdown:",
            Text.assemble(
                (f"{result.critical_count} critical", Severity.CRITICAL.color),
                " | ",
                (f"{result.high_count} high", Severity.HIGH.color),
                " | ",
                (f"{result.medium_count} medium", Severity.MEDIUM.color),
                " | ",
                (f"{result.low_count} low", Severity.LOW.color),
            ),
        )

        self.console.print(
            Panel(summary, title="[bold]Scan Summary[/bold]", border_style="dim", expand=False)
        )

    def _print_findings_table(self, result: ScanResult) -> None:
        table = Table(
            title="Findings",
            show_lines=True,
            title_style="bold",
            border_style="dim",
            expand=True,
        )
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Rule", width=14)
        table.add_column("Name", width=28)
        table.add_column("Resource", width=30)
        table.add_column("Details", ratio=1)

        for finding in sorted(result.findings, key=lambda f: -f.rule.severity.weight):
            sev = finding.rule.severity
            severity_text = Text(f"{sev.icon} {sev.value}", style=sev.color)
            resource_loc = finding.location
            table.add_row(
                severity_text,
                finding.rule.rule_id,
                finding.rule.name,
                resource_loc,
                finding.details,
            )

        self.console.print(table)

    def _print_errors(self, result: ScanResult) -> None:
        self.console.print()
        self.console.print("[bold yellow]Errors:[/bold yellow]")
        for error in result.errors:
            self.console.print(f"  [yellow]! {error}[/yellow]")

    def _print_score(self, result: ScanResult) -> None:
        score = result.score
        if score >= 80:
            color = "green"
        elif score >= 50:
            color = "yellow"
        else:
            color = "red"

        status = "[bold green]PASSED[/bold green]" if result.passed else "[bold red]FAILED[/bold red]"

        score_display = Text()
        score_display.append(f"  Security Score: ", style="bold")
        score_display.append(f"{score}/100", style=f"bold {color}")
        score_display.append("  |  Status: ")

        panel = Panel(
            Text.assemble(
                ("Security Score: ", "bold"),
                (f"{score}/100", f"bold {color}"),
                ("  |  Status: ", ""),
                (
                    "PASSED" if result.passed else "FAILED",
                    "bold green" if result.passed else "bold red",
                ),
            ),
            border_style=color,
            expand=False,
        )
        self.console.print(panel)
