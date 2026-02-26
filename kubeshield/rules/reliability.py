"""Reliability-focused rules."""

from __future__ import annotations

from kubeshield.models import Category, Finding, Resource, RuleMetadata, Severity
from kubeshield.rules.base import Rule


class MissingLivenessProbe(Rule):
    meta = RuleMetadata(
        rule_id="KS-REL-001",
        name="Missing liveness probe",
        description="Without a liveness probe, Kubernetes cannot detect if a container "
        "is stuck in a broken state and needs to be restarted.",
        severity=Severity.MEDIUM,
        category=Category.RELIABILITY,
        remediation="Add a `livenessProbe` with an appropriate HTTP, TCP, or exec check.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for ctype, container in self._get_containers(resource):
            if ctype == "initContainer":
                continue
            if "livenessProbe" not in container:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="No liveness probe configured",
                    )
                )
        return findings


class MissingReadinessProbe(Rule):
    meta = RuleMetadata(
        rule_id="KS-REL-002",
        name="Missing readiness probe",
        description="Without a readiness probe, traffic may be routed to a container "
        "before it's ready to serve, causing errors for users.",
        severity=Severity.MEDIUM,
        category=Category.RELIABILITY,
        remediation="Add a `readinessProbe` with an appropriate HTTP, TCP, or exec check.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for ctype, container in self._get_containers(resource):
            if ctype == "initContainer":
                continue
            if "readinessProbe" not in container:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="No readiness probe configured",
                    )
                )
        return findings


class SingleReplica(Rule):
    meta = RuleMetadata(
        rule_id="KS-REL-003",
        name="Single replica deployment",
        description="Running a single replica creates a single point of failure. "
        "If the pod crashes, there's downtime until it restarts.",
        severity=Severity.LOW,
        category=Category.RELIABILITY,
        remediation="Set `spec.replicas` to at least 2 for production workloads.",
    )
    workload_kinds = {"Deployment", "StatefulSet"}  # type: ignore[assignment]

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        replicas = resource.raw.get("spec", {}).get("replicas", 1)
        if replicas <= 1:
            findings.append(
                Finding(
                    rule=self.meta,
                    resource_name=resource.name,
                    resource_kind=resource.kind,
                    namespace=resource.namespace,
                    file_path=resource.file_path,
                    details=f"Only {replicas} replica(s) configured",
                )
            )
        return findings
