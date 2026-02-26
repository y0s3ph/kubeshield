"""Networking-focused rules."""

from __future__ import annotations

from kubeshield.models import Category, Finding, Resource, RuleMetadata, Severity
from kubeshield.rules.base import Rule


class HostPort(Rule):
    meta = RuleMetadata(
        rule_id="KS-NET-001",
        name="Container uses hostPort",
        description="Using hostPort ties the pod to a specific node and limits "
        "scheduling flexibility. It also exposes the port directly on the node.",
        severity=Severity.MEDIUM,
        category=Category.NETWORKING,
        cis_benchmark="5.2.13",
        remediation="Use a Service with type NodePort or LoadBalancer instead of hostPort.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            for port in container.get("ports", []):
                if port.get("hostPort"):
                    findings.append(
                        Finding(
                            rule=self.meta,
                            resource_name=resource.name,
                            resource_kind=resource.kind,
                            namespace=resource.namespace,
                            file_path=resource.file_path,
                            container_name=container.get("name"),
                            details=f"hostPort {port['hostPort']} is bound",
                        )
                    )
        return findings


class DefaultNamespace(Rule):
    meta = RuleMetadata(
        rule_id="KS-NET-002",
        name="Resource in default namespace",
        description="Using the default namespace makes it harder to apply RBAC policies "
        "and network policies, and mixes unrelated workloads together.",
        severity=Severity.LOW,
        category=Category.BEST_PRACTICE,
        remediation="Deploy workloads in a dedicated namespace with appropriate RBAC "
        "and network policies.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        if resource.namespace in ("default", ""):
            findings.append(
                Finding(
                    rule=self.meta,
                    resource_name=resource.name,
                    resource_kind=resource.kind,
                    namespace=resource.namespace or "default",
                    file_path=resource.file_path,
                    details="Resource is deployed in the default namespace",
                )
            )
        return findings
