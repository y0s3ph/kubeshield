"""Data models for KubeShield scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]


class Category(str, Enum):
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    NETWORKING = "Networking"
    RESOURCES = "Resources"
    BEST_PRACTICE = "Best Practice"


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    cis_benchmark: str | None = None
    remediation: str | None = None


@dataclass
class Finding:
    rule: RuleMetadata
    resource_name: str
    resource_kind: str
    namespace: str
    file_path: str
    container_name: str | None = None
    details: str = ""

    @property
    def location(self) -> str:
        parts = [f"{self.resource_kind}/{self.resource_name}"]
        if self.namespace:
            parts.insert(0, self.namespace)
        if self.container_name:
            parts.append(f"container:{self.container_name}")
        return "/".join(parts)


@dataclass
class Resource:
    api_version: str
    kind: str
    name: str
    namespace: str
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    spec: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    file_path: str = ""


@dataclass
class ScanResult:
    files_scanned: int = 0
    resources_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_paths: list[Path] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.LOW)

    @property
    def score(self) -> int:
        """Security score from 0-100. Higher is better."""
        if self.resources_scanned == 0:
            return 100
        max_penalty = self.resources_scanned * Severity.CRITICAL.weight * 3
        penalty = sum(f.rule.severity.weight for f in self.findings)
        return max(0, int(100 * (1 - penalty / max_penalty)))

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for finding in sorted(self.findings, key=lambda f: -f.rule.severity.weight):
            result.setdefault(finding.rule.severity, []).append(finding)
        return result

    def by_resource(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.location, []).append(finding)
        return result
