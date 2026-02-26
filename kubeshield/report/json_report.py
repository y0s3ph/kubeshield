"""JSON report output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from kubeshield import __version__
from kubeshield.models import ScanResult


class JSONReporter:
    def generate(self, result: ScanResult) -> str:
        report = {
            "kubeshield_version": __version__,
            "scan_timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "summary": {
                "files_scanned": result.files_scanned,
                "resources_scanned": result.resources_scanned,
                "total_findings": result.total_findings,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "security_score": result.score,
                "passed": result.passed,
            },
            "findings": [
                {
                    "rule_id": f.rule.rule_id,
                    "rule_name": f.rule.name,
                    "severity": f.rule.severity.value,
                    "category": f.rule.category.value,
                    "description": f.rule.description,
                    "resource_kind": f.resource_kind,
                    "resource_name": f.resource_name,
                    "namespace": f.namespace,
                    "container_name": f.container_name,
                    "file_path": f.file_path,
                    "details": f.details,
                    "remediation": f.rule.remediation,
                    "cis_benchmark": f.rule.cis_benchmark,
                }
                for f in sorted(result.findings, key=lambda f: -f.rule.severity.weight)
            ],
            "errors": result.errors,
        }
        return json.dumps(report, indent=2)

    def write(self, result: ScanResult, output_path: Path) -> None:
        content = self.generate(result)
        output_path.write_text(content, encoding="utf-8")
