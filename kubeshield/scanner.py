"""Core scanner that loads manifests and applies rules."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from kubeshield.models import Resource, ScanResult
from kubeshield.rules import Rule, registry

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json"}

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}


class Scanner:
    def __init__(
        self,
        rule_ids: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> None:
        self._rules = self._build_rules(rule_ids, severities)

    def _build_rules(
        self,
        rule_ids: list[str] | None,
        severities: list[str] | None,
    ) -> list[Rule]:
        rules = []
        for rule_cls in registry:
            if rule_ids and rule_cls.meta.rule_id not in rule_ids:
                continue
            if severities:
                severity_upper = [s.upper() for s in severities]
                if rule_cls.meta.severity.value not in severity_upper:
                    continue
            rules.append(rule_cls())
        return rules

    def scan(self, paths: list[Path]) -> ScanResult:
        result = ScanResult()

        for path in paths:
            if path.is_file():
                self._scan_file(path, result)
            elif path.is_dir():
                for file_path in sorted(path.rglob("*")):
                    if file_path.suffix in SUPPORTED_EXTENSIONS:
                        self._scan_file(file_path, result)
            else:
                result.errors.append(f"Path not found: {path}")

        result.scanned_paths = paths
        return result

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        result.files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8")
            documents = list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            result.errors.append(f"YAML parse error in {file_path}: {e}")
            return
        except OSError as e:
            result.errors.append(f"Cannot read {file_path}: {e}")
            return

        for doc in documents:
            if not isinstance(doc, dict):
                continue

            if "kind" in doc and "apiVersion" in doc:
                resources = [doc]
            elif doc.get("kind") == "List":
                resources = doc.get("items", [])
            else:
                continue

            for raw_resource in resources:
                if not isinstance(raw_resource, dict):
                    continue
                resource = self._parse_resource(raw_resource, str(file_path))
                if resource:
                    result.resources_scanned += 1
                    self._apply_rules(resource, result)

    def _parse_resource(self, raw: dict, file_path: str) -> Resource | None:
        kind = raw.get("kind", "")
        if kind not in WORKLOAD_KINDS:
            return None

        metadata = raw.get("metadata", {})
        return Resource(
            api_version=raw.get("apiVersion", ""),
            kind=kind,
            name=metadata.get("name", "unnamed"),
            namespace=metadata.get("namespace", ""),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=raw.get("spec", {}),
            raw=raw,
            file_path=file_path,
        )

    def _apply_rules(self, resource: Resource, result: ScanResult) -> None:
        for rule in self._rules:
            if not rule.applies_to(resource):
                continue
            try:
                findings = rule.check(resource)
                result.findings.extend(findings)
            except Exception as e:
                logger.warning(
                    "Rule %s failed on %s/%s: %s",
                    rule.meta.rule_id,
                    resource.kind,
                    resource.name,
                    e,
                )
                result.errors.append(
                    f"Rule {rule.meta.rule_id} error on {resource.kind}/{resource.name}: {e}"
                )
