"""Report generators for KubeShield."""

from kubeshield.report.console import ConsoleReporter
from kubeshield.report.json_report import JSONReporter

__all__ = ["ConsoleReporter", "JSONReporter"]
